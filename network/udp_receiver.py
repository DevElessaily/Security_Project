import socket, threading, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from Crypto_engine import CryptoEngine

class UDPReceiver:
    def __init__(self, port=12347, passphrase="secret", on_audio=None, on_status=None):
        self.port = port
        self.engine = CryptoEngine.from_psk(passphrase)
        self.on_audio = on_audio or (lambda b: None)
        self.on_status = on_status or (lambda s: None)
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
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind(("0.0.0.0", self.port))
            self.on_status(f"listening (udp) on 0.0.0.0:{self.port}")
            while self._running:
                try:
                    pkt, addr = self._sock.recvfrom(65535)
                except Exception:
                    break
                try:
                    audio = self.engine.decrypt_chunk(pkt)
                    self.on_audio(audio)
                except Exception as ex:
                    self.on_status(f"decrypt error: {ex}")
            self.on_status("udp receiver stopped")
        except Exception as ex:
            self.on_status(f"udp receiver error: {ex}")
        finally:
            self._running = False
