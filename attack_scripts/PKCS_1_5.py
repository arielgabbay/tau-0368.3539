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
    # Make sure that EB starts with 0 and a valid BT
    if eb[0] != 0 or eb[1] not in (0, 1, 2):
        return None
    firstzero = eb.find(0, 2)  # first zero byte after BT
    if firstzero == -1:  # gotta have a zero byte
        return None
    if eb[1] == 0:
        if firstzero != 2:  # first byte after BT has to be zero; data starts after zeros
            return None
        return eb[3:].lstrip(b"\x00")
    elif eb[1] == 1:
        if not all(c == 0xFF for c in eb[:firstzero]):  # FFs until first zero, then data
            return None
        return eb[firstzero + 1:]
    elif eb[1] == 2:
        return eb[firstzero + 1:]  # data starts after first zero
    return None

