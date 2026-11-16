import socket, threading, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from Crypto_engine import CryptoEngine
from network.framing import send_frame, recv_frame

class TCPReceiver:
    def __init__(self, host="0.0.0.0", port=12347, on_audio=None, on_status=None):
        self.host = host; self.port = port
        self.engine = CryptoEngine.new_receiver()
        self.on_audio = on_audio or (lambda b: None)
        self.on_status = on_status or (lambda s: None)
        self._sock = None; self._running = False; self.conn = None

    def start(self):
        self._running = True
        threading.Thread(target=self._run, daemon=True).start()

    def stop(self):
        self._running = False
        for s in (self.conn, self._sock):
            try:
                if s: s.close()
            except Exception:
                pass

    def _run(self):
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind((self.host, self.port))
            self._sock.listen(1)
            self.on_status(f"listening on {self.host}:{self.port}")
            self.conn, addr = self._sock.accept()
            self.on_status(f"connected from {addr}")
            # send public key as "n|e"
            n, e = self.engine.public_key
            send_frame(self.conn, f"{n}|{e}".encode())
            wrapped = recv_frame(self.conn)
            self.engine.load_setup(wrapped)
            self.on_status("key exchange complete; receiving audio")
            while self._running:
                pkt = recv_frame(self.conn)
                if not pkt:
                    break
                try:
                    audio = self.engine.decrypt_chunk(pkt)
                    self.on_audio(audio)
                except Exception as ex:
                    self.on_status(f"decrypt error: {ex}")
        except Exception as ex:
            self.on_status(f"receiver error: {ex}")
        finally:
            self.on_status("receiver stopped")
            self._running = False
