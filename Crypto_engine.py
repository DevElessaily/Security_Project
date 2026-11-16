import os, struct, hashlib
import sys
sys.path.insert(0, ".")
from Ciphers import DES, AES, RSA, hmac as hmac_layer


class CryptoEngine:
    def __init__(self):
        self.des_key = self.aes_key = self.hmac_key = None
        self.private_key = self.public_key = self.peer_public_key = None

    @classmethod
    def new_receiver(cls):
        e = cls()
        e.private_key, e.public_key = RSA.generate_keypair()
        return e

    @classmethod
    def new_sender(cls, peer_public_key):
        e = cls()
        e.peer_public_key = peer_public_key
        e.des_key = os.urandom(8)
        e.aes_key = os.urandom(32)
        e.hmac_key = hashlib.sha256(e.des_key + e.aes_key).digest()
        return e

    @classmethod
    def from_psk(cls, passphrase):
        e = cls()
        seed = hashlib.sha256(passphrase.encode()).digest()
        e.des_key = seed[:8]
        e.aes_key = hashlib.sha256(seed + b"aes").digest()
        e.hmac_key = hashlib.sha256(seed + b"hmac").digest()
        return e

    def public_key_pem(self):
        return self.public_key  # (n, e) tuple

    def setup_payload(self):
        return RSA.encrypt(self.des_key + self.aes_key, self.peer_public_key)

    def load_setup(self, wrapped):
        b = RSA.decrypt(wrapped, self.private_key)
        self.des_key, self.aes_key = b[0:8], b[8:40]
        self.hmac_key = hashlib.sha256(self.des_key + self.aes_key).digest()

    def encrypt_chunk(self, plaintext):
        l1, iv1 = DES.encrypt(plaintext, self.des_key)
        l2, iv2 = AES.encrypt(l1, self.aes_key)
        tag = hmac_layer.mac(self.hmac_key, iv1 + iv2 + l2)
        return iv1 + iv2 + struct.pack(">I", len(l2)) + l2 + tag

    def decrypt_chunk(self, payload):
        iv1, iv2 = payload[0:8], payload[8:24]
        ct_len = struct.unpack(">I", payload[24:28])[0]
        ct = payload[28:28+ct_len]
        tag = payload[28+ct_len:28+ct_len+32]
        if not hmac_layer.verify(self.hmac_key, iv1 + iv2 + ct, tag):
            raise ValueError("HMAC verification failed")
        l1 = AES.decrypt(ct, self.aes_key, iv2)
        return DES.decrypt(l1, self.des_key, iv1)
