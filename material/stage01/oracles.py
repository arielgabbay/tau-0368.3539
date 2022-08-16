"""
Oracles for chosen-ciphertext attacks on PKCS #1

This script manages interaction with the server.
No need to modify anything here unless you want to!
"""
import socket
import struct
import select

# TLS "client hello" message to be sent at the beginning of the session.
CLIENT_HELLO = bytes.fromhex("16030300610100005d030362ac2c12d90b74d84a688188a36a11df1455920891da9ab4cfc2cfb8f0ba0a7d00000400b600ff010000300000000e000c0000096c6f63616c686f7374000d000e000c060306010503050104030401001600000017000000230000")


def _build_keyexch(pms, identity=b"Client_identity"):
    """
    Builds a TLS client key exchange message with the encrypted PMS given.
    :param pms: the encrypted PMS to send.
    :param identity: the "client identity" field to send; no need to change this.
    :return: a bytes object with the key exchange message.
    """
    paramslen = 4 + len(pms) + len(identity)
    fmt = ">BHHBBHH%usH%us" % (len(identity), len(pms))
    return struct.pack(fmt, 22, 0x303, paramslen + 4, 16, 0, paramslen, len(identity), identity, len(pms), pms)

def _sock_init(addr, port):
    """
    Open a TCP socket to the server and exchange TLS "hello" messages.
    :param addr: the server's address.
    :param port: the server's port.
    :return: the connection socket.
    """
    sock = socket.socket()
    sock.connect((addr, port))
    sock.send(CLIENT_HELLO)
    sock.setblocking(0)
    _read_server_hello(sock)
    return sock

def _read_bytes(sock, count, timeout=1):
    """
    Reads (at most) `count' bytes from the given socket with a given timeout.
    :param sock: the socket to read from.
    :param count: the (maximal) number of bytes to read.
    :param timeout: the timeout of the read operation in seconds.
    :return: a bytes object with the read data (empty if timeout has elapsed with no data received).
    """
    res = select.select([sock], [], [], timeout)
    if not res[0]:
        return b""
    return sock.recv(count)

def _read_server_hello(sock):
    """
    Reads the server's "hello" response sent at the beginning of a session from the socket given.
    """
    while True:
        hdr = _read_bytes(sock, 6)
        typ, ver, length, msgtype = struct.unpack(">BHHB", hdr)
        _read_bytes(sock, length - 1)  # read rest of frame
        if msgtype == 0xE:  # server hello done
            break

def _read_resp(sock):
    """
    Reads the server's response to a key exchange request.
    :param sock: the socket of the connection.
    :return: the error value returned by the server.
    """
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
    """
    Decorator for class methods that ensures the connection on the socket is active and initialized.
    """
    def new_method(self, *args, **kwargs):
        if self.sock is None:
            self.sock = _sock_init(self.addr, self.port)
        return method(self, *args, **kwargs)
    return new_method


class MbedTLS_Oracle:
    ERROR_INVALID_PADDING=91  # Error value that the server sends in case of invalid padding.

    def __init__(self, addr, port, stage):
        self.sock = None
        self.addr = addr
        self.port = port

    @_init_sock
    def query(self, content):
        """
        Open a connection with the server if it isn't already open and query the server with the
        encrypted PMS given.
        :param content: the encrypted PMS to send.
        :return: the server's response (padding valid/invalid - boolean).
        """
        self.sock.send(_build_keyexch(content))
        resp = _read_resp(self.sock)
        return resp != self.ERROR_INVALID_PADDING
