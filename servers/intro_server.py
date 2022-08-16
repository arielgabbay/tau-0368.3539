#!/usr/bin/python3.8
import argparse
import socket
import multiprocessing
import select
from Crypto.PublicKey import RSA

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--num-servers", "-n", type=int, default=1, help="Number of server threads")
    parser.add_argument("--key-file", "-k", required=True, help="Private RSA key file")
    parser.add_argument("--server-port", "-p", default=4433, type=int, help="Port to listen on")
    return parser.parse_args()

def print_w_info(info, *args):
    return
    print("[{0}:{1}]".format(*info), *args)

def recv(conn, length, timeout=5):
    resp = b""
    while len(resp) < length:
        rlist, _, _ = select.select([conn], [], [], timeout)
        if len(rlist) == 0:
            break
        resp += conn.recv(length)
    return resp

def handle_client(args):
    conn, info, d, n, size_in_bytes = args
    conn.setblocking(0)
    r = recv(conn, 2)
    if len(r) < 2:
        print_w_info(info, "timed out.")
        conn.close()
        return False
    cipherlen = int.from_bytes(r, byteorder="big")
    print_w_info(info, "length:", cipherlen)
    if not 0 < cipherlen <= size_in_bytes:
        conn.close()
        print_w_info(info, "invalid length (%d)." % cipherlen)
        return False
    r = recv(conn, cipherlen)
    if len(r) < cipherlen:
        conn.close()
        print_w_info(info, "timed out.")
        return False
    cipher = int.from_bytes(r, byteorder="big")
    plain = pow(cipher, d, n)
    result = int(plain > (n >> 1))
    print_w_info(info, "result:", result)
    conn.send(result.to_bytes(1, byteorder="big"))
    conn.close()
    return True

def main():
    args = parse_args()
    with open(args.key_file, "rb") as f:
        key = RSA.import_key(f.read())
    pool = multiprocessing.Pool(processes=args.num_servers)
    serv = socket.socket()
    serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serv.bind(("0.0.0.0", args.server_port))
    serv.listen(args.num_servers)
    while True:
        conn, info = serv.accept()
        print_w_info(info, "connected")
        res = pool.map_async(handle_client, ((conn, info, key.d, key.n, key.size_in_bytes()),))

if __name__ == "__main__":
    main()

