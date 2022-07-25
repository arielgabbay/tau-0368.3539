"""
Python implementation of PKCS-1.5 RSA encryption
https://tools.ietf.org/html/rfc2313
"""

from os import urandom

def parse(eb):
    """
    Parse encryption block
    :param eb: encryption block
    :return: parsed data
    """
