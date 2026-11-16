"""Manual RSA (PKCS#1 v1.5 padding)."""
import os, random

def is_prime(n, k=8):
    if n < 2: return False
    for p in (2,3,5,7,11,13,17,19,23,29,31,37):
        if n % p == 0: return n == p
    d = n - 1; r = 0
    while d % 2 == 0:
        d //= 2; r += 1
    for _ in range(k):
        a = random.randrange(2, n-1)
        x = pow(a, d, n)
        if x == 1 or x == n-1: continue
        for _ in range(r-1):
            x = x*x % n
            if x == n-1: break
        else: return False
    return True

def gen_prime(bits):
    while True:
        p = random.getrandbits(bits) | (1 << (bits-1)) | 1
        if is_prime(p): return p

def generate_keypair(bits=512):
    p = gen_prime(bits//2)
    q = gen_prime(bits//2)
    while q == p:
        q = gen_prime(bits//2)
    n = p*q
    phi = (p-1)*(q-1)
    e = 65537
    d = pow(e, -1, phi)
    return (n, e, d), (n, e)

def _i2osp(x, length): return x.to_bytes(length, "big")
def _os2ip(b): return int.from_bytes(b, "big")

def encrypt(plaintext, public_key):
    n, e = public_key
    k = (n.bit_length()+7)//8
    if len(plaintext) > k - 11:
        raise ValueError("message too long")
    ps = bytearray()
    while len(ps) < k - len(plaintext) - 3:
        b = os.urandom(1)
        if b != b"\x00":
            ps += b
    em = b"\x00\x02" + bytes(ps) + b"\x00" + plaintext
    m = _os2ip(em)
    c = pow(m, e, n)
    return _i2osp(c, k)

def decrypt(ciphertext, private_key):
    n, e, d = private_key
    k = (n.bit_length()+7)//8
    c = _os2ip(ciphertext)
    m = pow(c, d, n)
    em = _i2osp(m, k)
    if em[0] != 0 or em[1] != 2:
        raise ValueError("decryption error")
    idx = em.find(b"\x00", 2)
    if idx < 0:
        raise ValueError("decryption error")
    return em[idx+1:]

def serialize_public(pub):
    return pub  # (n, e) tuple

def load_public(data):
    return data