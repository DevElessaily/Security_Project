import os, sys, queue, threading, tkinter as tk
from tkinter import ttk, scrolledtext
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from network.tcp_sender import TCPSender
from network.tcp_receiver import TCPReceiver
from network.udp_broadcast import UDPSender
from network.udp_receiver import UDPReceiver
from audio import AudioCapture, AudioPlayer
from mitm.mitm_proxy import MITMProxy

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Audio Crypto - CS401 (DES/AES/RSA)")
        self.logq = queue.Queue()
        self.sender = None; self.receiver = None; self.mitm = None
        self.capture = None; self.player = None
        self._build()
        self._poll()

    def _build(self):
        nb = ttk.Notebook(self.root); nb.pack(fill="both", expand=True)
        self.ts = ttk.Frame(nb); self.tr = ttk.Frame(nb); self.tm = ttk.Frame(nb)
        nb.add(self.ts, text="Sender"); nb.add(self.tr, text="Receiver"); nb.add(self.tm, text="MITM")
        self._sender_tab(); self._receiver_tab(); self._mitm_tab()
        self.log = scrolledtext.ScrolledText(self.root, height=12, state="disabled")
        self.log.pack(fill="both", expand=False, padx=5, pady=5)

    def logmsg(self, m):
        self.logq.put(str(m))

    def _poll(self):
        try:
            while True:
                m = self.logq.get_nowait()
                self.log.config(state="normal"); self.log.insert("end", m+"\n"); self.log.see("end")
                self.log.config(state="disabled")
        except queue.Empty:
            pass
        self.root.after(200, self._poll)

    # Sender
    def _sender_tab(self):
        f = self.ts
        ttk.Label(f, text="Mode").grid(row=0, column=0, sticky="w")
        self.s_mode = ttk.Combobox(f, values=["TCP (1:1)", "UDP (broadcast)"], width=20)
        self.s_mode.current(0); self.s_mode.grid(row=0, column=1)
        ttk.Label(f, text="Receiver IP/hosts").grid(row=1, column=0, sticky="w")
        self.s_host = ttk.Entry(f, width=22); self.s_host.insert(0, "127.0.0.1"); self.s_host.grid(row=1, column=1)
        ttk.Label(f, text="Port").grid(row=2, column=0, sticky="w")
        self.s_port = ttk.Entry(f, width=22); self.s_port.insert(0, "12347"); self.s_port.grid(row=2, column=1)
        ttk.Label(f, text="PSK (UDP)").grid(row=3, column=0, sticky="w")
        self.s_psk = ttk.Entry(f, width=22); self.s_psk.insert(0, "secret"); self.s_psk.grid(row=3, column=1)
        ttk.Button(f, text="Start Sender", command=self.start_sender).grid(row=4, column=0, pady=4)
        ttk.Button(f, text="Stop Sender", command=self.stop_sender).grid(row=4, column=1, pady=4)
        ttk.Button(f, text="Start Mic", command=self.start_mic).grid(row=5, column=0, pady=4)
        ttk.Button(f, text="Stop Mic", command=self.stop_mic).grid(row=5, column=1, pady=4)
        self.s_status = ttk.Label(f, text="idle"); self.s_status.grid(row=6, column=0, columnspan=2, sticky="w")

    def start_sender(self):
        host = self.s_host.get().strip()
        port = int(self.s_port.get().strip())
        mode = self.s_mode.get()
        if "UDP" in mode:
            self.sender = UDPSender(broadcast_addr=host, port=port, passphrase=self.s_psk.get().strip(),
                                    on_status=lambda m: (self.root.after(0, lambda: self.s_status.config(text=m)), self.logmsg("[sender] "+m)))
        else:
            self.sender = TCPSender(host=host, port=port,
                                    on_status=lambda m: (self.root.after(0, lambda: self.s_status.config(text=m)), self.logmsg("[sender] "+m)))
        self.sender.start(); self.logmsg("sender started")

    def stop_sender(self):
        if self.sender:
            self.sender.stop(); self.sender = None; self.logmsg("sender stopped")
        self.stop_mic()

    def start_mic(self):
        if not self.sender:
            self.logmsg("start sender first"); return
        if self.capture: return
        self.capture = AudioCapture(on_chunk=lambda c: self.sender.enqueue(c))
        self.capture.start(); self.logmsg("mic started")

    def stop_mic(self):
        if self.capture:
            self.capture.stop(); self.capture = None; self.logmsg("mic stopped")

    # Receiver
    def _receiver_tab(self):
        f = self.tr
        ttk.Label(f, text="Mode").grid(row=0, column=0, sticky="w")
        self.r_mode = ttk.Combobox(f, values=["TCP (1:1)", "UDP (broadcast)"], width=20)
        self.r_mode.current(0); self.r_mode.grid(row=0, column=1)
        ttk.Label(f, text="Port").grid(row=1, column=0, sticky="w")
        self.r_port = ttk.Entry(f, width=22); self.r_port.insert(0, "12347"); self.r_port.grid(row=1, column=1)
        ttk.Label(f, text="PSK (UDP)").grid(row=2, column=0, sticky="w")
        self.r_psk = ttk.Entry(f, width=22); self.r_psk.insert(0, "secret"); self.r_psk.grid(row=2, column=1)
        ttk.Button(f, text="Start Receiver", command=self.start_receiver).grid(row=3, column=0, pady=4)
        ttk.Button(f, text="Stop Receiver", command=self.stop_receiver).grid(row=3, column=1, pady=4)
        self.r_status = ttk.Label(f, text="idle"); self.r_status.grid(row=4, column=0, columnspan=2, sticky="w")

    def start_receiver(self):
        port = int(self.r_port.get().strip())
        mode = self.r_mode.get()
        if not self.player:
            self.player = AudioPlayer(); self.player.start()
        if "UDP" in mode:
            self.receiver = UDPReceiver(port=port, passphrase=self.r_psk.get().strip(),
                                       on_audio=lambda b: self.player.play(b),
                                       on_status=lambda m: (self.root.after(0, lambda: self.r_status.config(text=m)), self.logmsg("[receiver] "+m)))
        else:
            self.receiver = TCPReceiver(port=port,
                                       on_audio=lambda b: self.player.play(b),
                                       on_status=lambda m: (self.root.after(0, lambda: self.r_status.config(text=m)), self.logmsg("[receiver] "+m)))
        self.receiver.start(); self.logmsg("receiver started")

    def stop_receiver(self):
        if self.receiver:
            self.receiver.stop(); self.receiver = None; self.logmsg("receiver stopped")
        if self.player:
            self.player.stop(); self.player = None

    # MITM
    def _mitm_tab(self):
        f = self.tm
        ttk.Label(f, text="Listen port").grid(row=0, column=0, sticky="w")
        self.m_listen = ttk.Entry(f, width=22); self.m_listen.insert(0, "12348"); self.m_listen.grid(row=0, column=1)
        ttk.Label(f, text="Target host").grid(row=1, column=0, sticky="w")
        self.m_thost = ttk.Entry(f, width=22); self.m_thost.insert(0, "127.0.0.1"); self.m_thost.grid(row=1, column=1)
        ttk.Label(f, text="Target port").grid(row=2, column=0, sticky="w")
        self.m_tport = ttk.Entry(f, width=22); self.m_tport.insert(0, "12347"); self.m_tport.grid(row=2, column=1)
        ttk.Label(f, text="Mode").grid(row=3, column=0, sticky="w")
        self.m_mode = ttk.Combobox(f, values=["passive", "active", "drop"], width=20)
        self.m_mode.current(0); self.m_mode.grid(row=3, column=1)
        ttk.Label(f, text="Tamper rate").grid(row=4, column=0, sticky="w")
        self.m_rate = ttk.Entry(f, width=22); self.m_rate.insert(0, "0.3"); self.m_rate.grid(row=4, column=1)
        ttk.Button(f, text="Start MITM", command=self.start_mitm).grid(row=5, column=0, pady=4)
        ttk.Button(f, text="Stop MITM", command=self.stop_mitm).grid(row=5, column=1, pady=4)
        self.m_status = ttk.Label(f, text="idle"); self.m_status.grid(row=6, column=0, columnspan=2, sticky="w")

    def start_mitm(self):
        lp = int(self.m_listen.get().strip())
        th = self.m_thost.get().strip()
        tp = int(self.m_tport.get().strip())
        mode = self.m_mode.get().strip()
        rate = float(self.m_rate.get().strip())
        self.mitm = MITMProxy(listen_port=lp, target_host=th, target_port=tp,
                              mode=mode, tamper_rate=rate, on_log=self.logmsg)
        self.mitm.start(); self.logmsg("mitm started")

    def stop_mitm(self):
        if self.mitm:
            self.mitm.stop(); self.mitm = None; self.logmsg("mitm stopped")

def main():
    root = tk.Tk()
    App(root)
    root.mainloop()

if __name__ == "__main__":
    main()
