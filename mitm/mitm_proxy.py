import socket, threading, random, struct, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from network.framing import recv_exact

class MITMProxy:
    def __init__(self, listen_port=12348, target_host="127.0.0.1", target_port=12347,
                 mode="passive", tamper_rate=0.3, on_log=None):
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port
        self.mode = mode
        self.tamper_rate = tamper_rate
        self.on_log = on_log or (lambda s: None)
        self._sock = None; self._running = False

    def start(self):
        self._running = True
        threading.Thread(target=self._run, daemon=True).start()

    def stop(self):
        self._running = False
        try:
            if self._sock: self._sock.close()
        except Exception:
            pass

    def _run(self):
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind(("0.0.0.0", self.listen_port))
            self._sock.listen(5)
            self.on_log(f"MITM listening on 0.0.0.0:{self.listen_port} -> {self.target_host}:{self.target_port} mode={self.mode}")
            while self._running:
                client, addr = self._sock.accept()
                self.on_log(f"MITM connection from {addr}")
                threading.Thread(target=self._relay, args=(client,), daemon=True).start()
        except Exception as ex:
            self.on_log(f"MITM error: {ex}")
        finally:
            self._running = False

    def _relay(self, client):
        try:
            upstream = socket.create_connection((self.target_host, self.target_port), timeout=10)
        except Exception as ex:
            self.on_log(f"MITM upstream failed: {ex}")
            client.close()
            return
        t1 = threading.Thread(target=self._forward, args=(client, upstream, "C->S"), daemon=True)
        t2 = threading.Thread(target=self._forward, args=(upstream, client, "S->C"), daemon=True)
        t1.start(); t2.start()
        t1.join(); t2.join()
        for s in (client, upstream):
            try: s.close()
            except Exception: pass

    def _forward(self, src, dst, label):
        first = True
        while self._running:
            try:
                header = recv_exact(src, 4)
            except Exception:
                break
            (n,) = struct.unpack(">I", header)
            if n == 0:
                dst.sendall(header); continue
            payload = recv_exact(src, n)
            self.on_log(f"{label} frame {n} bytes")
            out = payload
            tamper = (not first) and self.mode == "active" and random.random() < self.tamper_rate
            first = False
            if tamper and len(payload) > 0:
                idx = random.randrange(len(payload))
                out = payload[:idx] + bytes([payload[idx] ^ 0xFF]) + payload[idx+1:]
                self.on_log(f"{label} TAMPERED byte {idx}")
            elif self.mode == "drop" and (not first) and random.random() < self.tamper_rate:
                self.on_log(f"{label} DROPPED")
                continue
            dst.sendall(struct.pack(">I", len(out)) + out)
