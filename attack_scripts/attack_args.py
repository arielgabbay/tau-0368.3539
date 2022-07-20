import argparse
from Crypto.PublicKey import RSA

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--num-servers", "-n", type=int, default=1)
    parser.add_argument("--server-port", "-p", type=int, default=4433)
    parser.add_argument("--server-addr", "-s", default="127.0.0.1")
    parser.add_argument("--given-enc", "-c")
    parser.add_argument("--public-key", "-k", required=True)
    parser.add_argument("--n-length", "-l", type=int, default=1024)
    parser.add_argument("--verbose", "-v", action="count", default=0)
    return parser.parse_args()

def read_pubkey(f, n_bytes):
    return RSA.RsaKey(n=int.from_bytes(f.read(n_bytes), byteorder="big"),
            e=int.from_bytes(f.read(n_bytes), byteorder="big"))

