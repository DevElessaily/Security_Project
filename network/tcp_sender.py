import socket, threading, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from Crypto_engine import CryptoEngine
from network.framing import send_frame, recv_frame

class TCPSender:
    def __init__(self, host, port=12347, on_status=None):
        self.host = host; self.port = port
        self.on_status = on_status or (lambda s: None)
        self.engine = None
        self._sock = None; self._queue = __import__("queue").Queue()
        self._running = False; self._thread = None

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
            self._sock = socket.create_connection((self.host, self.port), timeout=10)
            data = recv_frame(self._sock)
            n_str, e_str = data.decode().split("|")
            pub = (int(n_str), int(e_str))
            self.engine = CryptoEngine.new_sender(pub)
            send_frame(self._sock, self.engine.setup_payload())
            self.on_status(f"connected to {self.host}:{self.port}; keys exchanged")
            while self._running:
                chunk = self._queue.get()
                if chunk is None:
                    break
                pkt = self.engine.encrypt_chunk(chunk)
                send_frame(self._sock, pkt)
            self.on_status("sender stopped")
        except Exception as ex:
            self.on_status(f"sender error: {ex}")
        finally:
            self._running = False
            try:
                if self._sock: self._sock.close()
            except Exception:
                pass
