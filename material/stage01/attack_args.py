import argparse
from Crypto.PublicKey import RSA

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server-port", "-p", type=int, required=True)
    parser.add_argument("--server-addr", "-s", required=True)
    parser.add_argument("--given-enc", "-c", required=True)
    parser.add_argument("--public-key", "-k", required=True)
    parser.add_argument("--n-length", "-l", type=int, default=1024)
    return parser.parse_args()

def read_pubkey(f, n_bytes):
    return RSA.RsaKey(n=int.from_bytes(f.read(n_bytes), byteorder="big"),
            e=int.from_bytes(f.read(n_bytes), byteorder="big"))

