#!/usr/bin/python3.8
from Crypto.PublicKey import RSA
import Crypto.Cipher.PKCS1_v1_5 as PKCS_1_5
import Crypto.Cipher.PKCS1_OAEP as PKCS_OAEP
import random
import os
import subprocess
import argparse
import multiprocessing
import json

import bleichenbacher
import manger

FLAGSIZE = 16

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--num-flags", "-n", required=True, type=int)
    parser.add_argument("--flagpool-directory", "-d", required=True)
    return parser.parse_args()

def call(cmd):
    sp = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    res = sp.wait()
    assert res == 0

SUBJ = "/C=GB/ST=London/L=London/O=Global Security/OU=IT Department/CN=example.com"

def gen_single_flag(flag_dir):
    os.mkdir(flag_dir)
    flag = os.urandom(FLAGSIZE)
    with open(os.path.join(flag_dir, "flag"), "w") as f:
        f.write(flag.hex())
    priv = os.path.join(flag_dir, "priv.key.pem")
    req = os.path.join(flag_dir, "request.csr")
    cert = os.path.join(flag_dir, "cert.crt")
    call(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:1024",
          "-out", priv])
    call(["openssl", "req", "-new", "-key", priv, "-out", req, "-subj", SUBJ])
    call(["openssl", "x509", "-req", "-days", "365", "-in", req, "-signkey", priv, "-out",
          cert])
    with open(priv, "rb") as f:
        key = RSA.import_key(f.read())
    with open(os.path.join(flag_dir, "pubkey.bin"), "wb") as f:
        f.write(key.n.to_bytes(key.size_in_bytes(), byteorder="big"))
        f.write(key.e.to_bytes(key.size_in_bytes(), byteorder="big"))
    result = []
    for idx, pkcs_class, count_func in ((0, PKCS_1_5, bleichenbacher.count_rounds),
                                        (1, PKCS_OAEP, manger.count_rounds)):
        pkcs = pkcs_class.new(key)
        enc = pkcs.encrypt(flag)
        with open(os.path.join(flag_dir, "enc%02d.bin" % idx), "wb") as f:
            f.write(enc)
        result.append(count_func(key, enc, key.size_in_bytes()))
    return result

NUM_PROCESSES = 10

def main(args):
    pool = multiprocessing.Pool(processes=NUM_PROCESSES)
    results = pool.imap(gen_single_flag, (os.path.join(args.flagpool_directory, "%02d" % i) for i in range(args.num_flags)))
    rounds = list(results)
    with open(os.path.join(args.flagpool_directory, "queries.json"), "w") as f:
        json.dump(rounds, f)

if __name__ == "__main__":
    args = parse_args()
    main(args)
