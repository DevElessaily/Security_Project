import struct, socket

def send_frame(sock, data):
    sock.sendall(struct.pack(">I", len(data)) + data)

def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("socket closed")
        buf += chunk
    return buf

def recv_frame(sock):
    header = recv_exact(sock, 4)
    (n,) = struct.unpack(">I", header)
    if n == 0:
        return b""
    return recv_exact(sock, n)
