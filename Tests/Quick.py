import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from Crypto_engine import CryptoEngine

rx = CryptoEngine.new_receiver()
tx = CryptoEngine.new_sender(rx.public_key)
data = os.urandom(1024)
rx.load_setup(tx.setup_payload())
pkt = tx.encrypt_chunk(data)
assert rx.decrypt_chunk(pkt) == data
print("Quick smoke test: PASS")
