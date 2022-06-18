#!/usr/bin/python3.8

import Crypto.Cipher.PKCS1_v1_5 as PKCS
from Crypto.PublicKey import RSA

import argparse
import socket
import sys
import struct

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--key_file", "-k")
    parser.add_argument("--port", "-p", type=int, default=4433)
    return parser.parse_args()

def print_client_msg(info, msg, msgtype="-"):
    print(("[%s] %s:%u: " % ((msgtype,) + info)) + msg)

def read_client_keyexch(sock, info):
    typ = sock.recv(1)
    assert typ == b"\x16", "Invalid message type"
    ver = sock.recv(2)
    assert ver == b"\x03\x03", "Invalid TLS version"
    remaining_len = int.from_bytes(sock.recv(2), byteorder="big")
    assert remaining_len >= 8, "Invalid message length %d" % remaining_len
    assert sock.recv(1) == b"\x10", "Invalid message"
    paramslen = int.from_bytes(sock.recv(3), byteorder="big")
    assert paramslen == remaining_len - 4, "Invalid param length %d" % paramslen
    identlen = int.from_bytes(sock.recv(2), byteorder="big")
    assert identlen <= paramslen + 4, "Invalid identity length %d" % identlen
    ident = sock.recv(identlen)
    pmslen = int.from_bytes(sock.recv(2), byteorder="big")
    assert pmslen == paramslen - 4 - identlen, "Invalid PMS length %d" % pmslen
    pms = sock.recv(pmslen)
    assert len(pms) == pmslen, "Partial pms received"
    return pms

def handle_client(pkcs, sock, info):
    print_client_msg(info, "client connected")
    client_hello = sock.recv(102)
    print_client_msg(info, "client hello received")
    while True:
        try:
            pms = read_client_keyexch(sock, info)
        except AssertionError as ex:
            print_client_msg(info, "error on received message: " + str(ex), "!")
            continue
        err = False
        try:
            dec_pms = pkcs.decrypt(pms, None)
            err = not dec_pms
        except ValueError:
            err = True
        if err:
            # print_client_msg(info, "invalid pkcs message")
            sock.send(b"\x15\x03\x03\x00\x02\x02\x5b")
        else:
            print_client_msg(info, "valid pkcs message")
            sock.send(b"\x15\x03\x03\x00\x02\x02\x5c")

def main():
    args = parse_args()
    with open(args.key_file, "rb") as keyfile:
        key = RSA.import_key(keyfile.read())
    pkcs = PKCS.new(key)
    serv_sock = socket.socket()
    serv_sock.bind(("0.0.0.0", args.port))
    serv_sock.listen(1)
    while True:
        handle_client(pkcs, *serv_sock.accept())

if __name__ == "__main__":
    sys.exit(main())
