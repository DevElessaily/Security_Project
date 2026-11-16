import hmac, hashlib
def mac(key, data):
    return hmac.new(key, data, hashlib.sha256).digest()
def verify(key, data, tag):
    return hmac.compare_digest(mac(key, data), tag)