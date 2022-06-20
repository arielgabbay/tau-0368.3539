from Crypto.PublicKey import RSA
import Crypto.Cipher.PKCS1_v1_5 as PKCS
import os

key = RSA.import_key(open("priv.key.pem", "rb").read())
pkcs = PKCS.new(key)

with open("pubkey.bin", "wb") as f:
    f.write(key.n.to_bytes(key.size_in_bytes(), byteorder="big"))
    f.write(key.e.to_bytes(key.size_in_bytes(), byteorder="big"))

with open("enc.bin", "wb") as f:
    f.write(pkcs.encrypt(os.urandom(10)))