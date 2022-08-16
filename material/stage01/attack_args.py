"""
This script parses command-line arguments for the attack script.
Run bleichenbacher.py --help to view the arguments.
No need to change anything here unless you want to!
"""
import argparse
from Crypto.PublicKey import RSA

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server-port", "-p", type=int, required=True, help="The server's port")
    parser.add_argument("--server-addr", "-s", required=True, help="The server's address")
    parser.add_argument("--given-enc", "-c", required=True, help="The encrypted file to decrypt")
    parser.add_argument("--public-key", "-k", required=True, help="The server's public key file")
    parser.add_argument("--n-length", "-l", type=int, default=1024, help="The server's key size in bits")
    return parser.parse_args()

def read_pubkey(f, n_bytes):
    return RSA.RsaKey(n=int.from_bytes(f.read(n_bytes), byteorder="big"),
            e=int.from_bytes(f.read(n_bytes), byteorder="big"))

