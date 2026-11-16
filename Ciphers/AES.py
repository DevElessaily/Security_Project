"""Manual AES (128/192/256), CBC mode, column-major state."""
SBOX = [0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16]

INV_SBOX = [0]*256
for i, v in enumerate(SBOX):
    INV_SBOX[v] = i

RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]

def gf_mul(a, b):
    r = 0
    for _ in range(8):
        if b & 1: r ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi: a ^= 0x1b
        b >>= 1
    return r

def sub_bytes(s): return [SBOX[b] for b in s]
def inv_sub_bytes(s): return [INV_SBOX[b] for b in s]

def shift_rows(s):
    out = [0]*16
    for r in range(4):
        for c in range(4):
            out[r+4*c] = s[r + 4*((c+r)%4)]
    return out

def inv_shift_rows(s):
    out = [0]*16
    for r in range(4):
        for c in range(4):
            out[r+4*c] = s[r + 4*((c-r)%4)]
    return out

def mix_columns(s):
    out = [0]*16
    for c in range(4):
        a0,a1,a2,a3 = s[0+4*c],s[1+4*c],s[2+4*c],s[3+4*c]
        out[0+4*c] = gf_mul(a0,2)^gf_mul(a1,3)^a2^a3
        out[1+4*c] = a0^gf_mul(a1,2)^gf_mul(a2,3)^a3
        out[2+4*c] = a0^a1^gf_mul(a2,2)^gf_mul(a3,3)
        out[3+4*c] = gf_mul(a0,3)^a1^a2^gf_mul(a3,2)
    return out

def inv_mix_columns(s):
    out = [0]*16
    for c in range(4):
        a0,a1,a2,a3 = s[0+4*c],s[1+4*c],s[2+4*c],s[3+4*c]
        out[0+4*c] = gf_mul(a0,14)^gf_mul(a1,11)^gf_mul(a2,13)^gf_mul(a3,9)
        out[1+4*c] = gf_mul(a0,9)^gf_mul(a1,14)^gf_mul(a2,11)^gf_mul(a3,13)
        out[2+4*c] = gf_mul(a0,13)^gf_mul(a1,9)^gf_mul(a2,14)^gf_mul(a3,11)
        out[3+4*c] = gf_mul(a0,11)^gf_mul(a1,13)^gf_mul(a2,9)^gf_mul(a3,14)
    return out

def add_round_key(s, rk):
    return [s[i]^rk[i] for i in range(16)]

def key_expansion(key):
    nk = len(key)//4
    nr = {16:10,24:12,32:14}[len(key)]
    w = [list(key[4*i:4*i+4]) for i in range(nk)]
    for i in range(nk, 4*(nr+1)):
        temp = w[i-1][:]
        if i % nk == 0:
            temp = temp[1:]+temp[:1]
            temp = [SBOX[b] for b in temp]
            temp[0] ^= RCON[i//nk - 1]
        elif nk > 6 and i % nk == 4:
            temp = [SBOX[b] for b in temp]
        w.append([w[i-nk][j]^temp[j] for j in range(4)])
    round_keys = []
    for r in range(nr+1):
        rk = []
        for i in range(4):
            rk += w[r*4+i]
        round_keys.append(rk)
    return round_keys, nr

def encrypt_block(block, key):
    rks, nr = key_expansion(key)
    s = add_round_key(list(block), rks[0])
    for r in range(1, nr):
        s = sub_bytes(s)
        s = shift_rows(s)
        s = mix_columns(s)
        s = add_round_key(s, rks[r])
    s = sub_bytes(s)
    s = shift_rows(s)
    s = add_round_key(s, rks[nr])
    return bytes(s)

def decrypt_block(block, key):
    rks, nr = key_expansion(key)
    s = add_round_key(list(block), rks[nr])
    s = inv_shift_rows(s)
    s = inv_sub_bytes(s)
    for r in range(nr-1, 0, -1):
        s = add_round_key(s, rks[r])
        s = inv_mix_columns(s)
        s = inv_shift_rows(s)
        s = inv_sub_bytes(s)
    s = add_round_key(s, rks[0])
    return bytes(s)

def _fix_key(key, size):
    if len(key) < size:
        key = key + b"\0"*(size-len(key))
    return key[:size]

def encrypt(plaintext, key, iv=None):
    import os
    size = len(key) if len(key) in (16,24,32) else 16
    key = _fix_key(key, size)
    if iv is None:
        iv = os.urandom(16)
    iv = _fix_key(iv, 16)
    pad_len = 16 - (len(plaintext) % 16)
    if pad_len == 0: pad_len = 16
    data = plaintext + bytes([pad_len])*pad_len
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        block = bytes(a^b for a,b in zip(data[i:i+16], prev))
        ct = encrypt_block(block, key)
        out += ct
        prev = ct
    return bytes(out), iv

def decrypt(ciphertext, key, iv):
    size = len(key) if len(key) in (16,24,32) else 16
    key = _fix_key(key, size)
    iv = _fix_key(iv, 16)
    out = bytearray()
    prev = iv
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        pt = decrypt_block(block, key)
        xored = bytes(a^b for a,b in zip(pt, prev))
        out += xored
        prev = block
    pad_len = out[-1]
    if 1 <= pad_len <= 16:
        out = out[:-pad_len]
    return bytes(out)