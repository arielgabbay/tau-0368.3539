import argparse
import socket
from Crypto.PublicKey import RSA

def parse_args():
    """
    Parses command-line arguments.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("--server-port", "-p", type=int, help="The port on which the server is listening.", required=True)
    parser.add_argument("--server-addr", "-s", help="The server's IP address.", required=True)
    parser.add_argument("--given-enc", "-e", help="Encrypted file to decrypt.", required=True)
    parser.add_argument("--public-key", "-k", help="Server's public RSA key file.", required=True)
    parser.add_argument("--n-length", "-l", type=int, help="RSA key length.", default=1024)
    return parser.parse_args()

def query(addr, port, ciphertext, n_bytes):
    sock = socket.socket()
    sock.connect((addr, port))
    sock.send(n_bytes.to_bytes(2, byteorder="big"))
    sock.send(ciphertext.to_bytes(n_bytes, byteorder="big"))
    return bool(int.from_bytes(sock.recv(1), byteorder="big"))

def double(c, key):
    """
    Receives a ciphertext c and doubles its plaintext.
    """
    new_ciphertext = 
    return new_ciphertext

def main():
    args = parse_args()  # parse command-line arguments
    n_bytes = args.n_length >> 3  # key length in bytes
    # Read the server's public key to an RsaKey object
    with open(args.public_key, "rb") as f:
        key = RSA.RsaKey(n=int.from_bytes(f.read(n_bytes), byteorder="big"),
                         e=int.from_bytes(f.read(n_bytes), byteorder="big"))
    # Read the encrypted file given
    with open(args.given_enc, "rb") as f:
        orig_ciphertext = int.from_bytes(f.read(), byteorder="big")
    # Query the server until interval is sufficiently small
    ciphertext = orig_ciphertext
    interval_min, interval_max = 
    while interval_min < interval_max - 1:
        mid = ((interval_max + interval_min) >> 1) + ((interval_max & 1) ^ (interval_min & 1))
        if query(args.server_addr, args.server_port, ciphertext, n_bytes):
            interval_min = 
        else:
            interval_max = 
        ciphertext = 
    # Check if the ciphertext found is correct
    if pow(interval_min, key.e, key.n) == orig_ciphertext:
        print(interval_min)
        return interval_min
    # If the ciphertext found is not correct, check close values
    for offset in range(1, 500):
        for candidate in (interval_min + offset, interval_min - offset):
            if pow(candidate, key.e, key.n) == orig_ciphertext:
                print(candidate)
                return candidate
    print("Not found!")
    return None

if __name__ == "__main__":
    main()
