import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# DES
from Ciphers.DES import encrypt as des_enc, decrypt as des_dec
from Crypto.Cipher import DES
key, iv = os.urandom(8), os.urandom(8)
msg = os.urandom(64)
ct1, _ = des_enc(msg, key, iv)
ct2 = DES.new(key, DES.MODE_CBC, iv).encrypt(__import__("Crypto.Util.Padding", fromlist=["pad"]).pad(msg, 8))
print("DES manual == lib:", ct1 == ct2)

# AES (manual only)
from Ciphers.AES import encrypt as aes_enc, decrypt as aes_dec
key, iv = os.urandom(16), os.urandom(16)
msg = os.urandom(64)
ct, _ = aes_enc(msg, key, iv)
print("AES roundtrip:", aes_dec(ct, key, iv) == msg)

# RSA (manual only)
from Ciphers.RSA import generate_keypair, encrypt as rsa_enc, decrypt as rsa_dec
priv, pub = generate_keypair(512)
msg = os.urandom(32)
ct = rsa_enc(msg, pub)
print("RSA roundtrip:", rsa_dec(ct, priv) == msg)

# Engine
from Crypto_engine import CryptoEngine
rx = CryptoEngine.new_receiver()
tx = CryptoEngine.new_sender(rx.public_key)
data = os.urandom(256)
rx.load_setup(tx.setup_payload())
pkt = tx.encrypt_chunk(data)
print("Engine roundtrippppp:", rx.decrypt_chunk(pkt) == data)
