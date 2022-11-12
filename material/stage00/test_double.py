import os
from Crypto.PublicKey import RSA

from attack import double

def main():
    key = RSA.generate(1024)
    pubkey = key.public_key()
    plain = int.from_bytes(os.urandom(1024 // 8), byteorder="big")
    ciphertext = pow(plain, key.e, key.n)
    doubled_ciphertext = double(ciphertext, pubkey)
    doubled_plain = pow(doubled_ciphertext, key.d, key.n)
    assert doubled_plain == (plain * 2) % key.n, "double() isn't working!"
    print("double() is working!")

if __name__ == "__main__":
    main()
