import socket, threading, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from Crypto_engine import CryptoEngine

class UDPSender:
    def __init__(self, broadcast_addr="<broadcast>", port=12347, passphrase="secret", on_status=None):
        if "," in broadcast_addr:
            self.targets = [x.strip() for x in broadcast_addr.split(",") if x.strip()]
            self.broadcast = False
        elif broadcast_addr == "<broadcast>":
            self.targets = ["<broadcast>"]
            self.broadcast = True
        else:
            self.targets = [broadcast_addr]
            self.broadcast = False
        self.port = port
        self.engine = CryptoEngine.from_psk(passphrase)
        self.on_status = on_status or (lambda s: None)
        self._queue = __import__("queue").Queue()
        self._running = False; self._sock = None; self._thread = None

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def enqueue(self, chunk):
        if self._running:
            self._queue.put(chunk)

    def stop(self):
        self._running = False
        self._queue.put(None)
        try:
            if self._sock: self._sock.close()
        except Exception:
            pass

    def _run(self):
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            if self.broadcast:
                self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.on_status(f"sending to {self.targets}:{self.port}")
            while self._running:
                chunk = self._queue.get()
                if chunk is None:
                    break
                pkt = self.engine.encrypt_chunk(chunk)
                for t in self.targets:
                    try:
                        self._sock.sendto(pkt, (t, self.port))
                    except Exception as ex:
                        self.on_status(f"send error to {t}: {ex}")
            self.on_status("udp sender stopped")
        except Exception as ex:
            self.on_status(f"udp sender error: {ex}")
        finally:
            self._running = False
