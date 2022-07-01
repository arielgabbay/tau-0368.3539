from Crypto.PublicKey import RSA
import Crypto.Cipher.PKCS1_v1_5 as PKCS
import os
import sys
import argparse

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--priv", "-p", help="Input private key file (.pem)", required=True)
    parser.add_argument("--pub", "-o", help="Output public key file", required=True)
    parser.add_argument("--enc", "-e", help="Output encryption file", required=True)
    parser.add_argument("plaintext", help="Plaintext to encrypt into encryption file", nargs="?")
    return parser.parse_args()

def main():
    args = parse_args()
    key = RSA.import_key(open(args.priv, "rb").read())
    pkcs = PKCS.new(key)

    with open(args.pub, "wb") as f:
        f.write(key.n.to_bytes(key.size_in_bytes(), byteorder="big"))
        f.write(key.e.to_bytes(key.size_in_bytes(), byteorder="big"))

    with open(args.enc, "wb") as f:
        if args.plaintext is None:
            plain = os.urandom(10)
        else:
            plain = args.plaintext.encode()
        f.write(pkcs.encrypt(plain))
        print(plain)

if __name__ == "__main__":
    sys.exit(main())