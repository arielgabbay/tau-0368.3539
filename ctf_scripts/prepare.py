from Crypto.PublicKey import RSA
import Crypto.Cipher.PKCS1_v1_5 as PKCS
import os
import sys
import argparse
import subprocess

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--num-groups", "-n", required=True, type=int)
    parser.add_argument("ctf_dir")
    return parser.parse_args()

FLAGSIZE = 16

def generate_group(priv, pub, enc, flagfile, flag=None):
    key = RSA.import_key(open(priv, "rb").read())
    pkcs = PKCS.new(key)

    with open(pub, "wb") as f:
        f.write(key.n.to_bytes(key.size_in_bytes(), byteorder="big"))
        f.write(key.e.to_bytes(key.size_in_bytes(), byteorder="big"))

    if flag is None:
        flag = os.urandom(FLAGSIZE)
    with open(enc, "wb") as f:
        f.write(pkcs.encrypt(flag))
    with open(flagfile, "wb") as f:
        f.write(flag)

NUM_STAGES = 3
SUBJ = "/C=GB/ST=London/L=London/O=Global Security/OU=IT Department/CN=example.com"

def call(cmd):
    sp = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    res = sp.wait()
    assert res == 0, "Command\n%s\nreturned %d; stderr is:\n%s" % (" ".join(cmd), res, sp.stderr.read())

def main():
    args = parse_args()
    os.mkdir(args.ctf_dir)
    for group_num in range(1, args.num_groups + 1):
        groupdir = os.path.join(args.ctf_dir, "group_%02d" % group_num)
        os.mkdir(groupdir)
        for stage_num in range(1, NUM_STAGES + 1):
            stagedir = os.path.join(groupdir, "stage_%02d" % stage_num)
            os.mkdir(stagedir)
            servdir = os.path.join(stagedir, "server")
            os.mkdir(servdir)
            priv = os.path.join(servdir, "priv.key.pem")
            req = os.path.join(servdir, "request.csr")
            cert = os.path.join(servdir, "cert.crt")
            call(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:1024",
                  "-out", priv])
            call(["openssl", "req", "-new", "-key", priv, "-out", req, "-subj", SUBJ])
            call(["openssl", "x509", "-req", "-days", "365", "-in", req, "-signkey", priv, "-out",
                  cert])
            grpdir = os.path.join(stagedir, "group")
            os.mkdir(grpdir)
            generate_group(priv, os.path.join(grpdir, "pubkey.bin"), os.path.join(grpdir, "enc.bin"),
                           os.path.join(stagedir, "flag.bin"))


if __name__ == "__main__":
    sys.exit(main())