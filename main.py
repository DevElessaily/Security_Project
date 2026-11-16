import argparse, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def main():
    parser = argparse.ArgumentParser(description="Secure Audio Crypto")
    parser.add_argument("--mode", choices=["gui", "selftest"], default="gui")
    args = parser.parse_args()
    if args.mode == "selftest":
        import time
        from network.tcp_receiver import TCPReceiver
        from network.tcp_sender import TCPSender
        from network.udp_receiver import UDPReceiver
        from network.udp_broadcast import UDPSender
        # TCP
        received = []
        rx = TCPReceiver(host="127.0.0.1", port=12490, on_audio=lambda b: received.append(b))
        rx.start(); time.sleep(0.5)
        tx = TCPSender(host="127.0.0.1", port=12490); tx.start(); time.sleep(0.8)
        import os as _os
        payload = _os.urandom(256)
        tx.enqueue(payload); time.sleep(1.0)
        tx.stop(); rx.stop(); time.sleep(0.5)
        print("TCP selftest:", "PASS" if payload in received else "FAIL")
        # UDP
        received2 = []
        rx2 = UDPReceiver(port=12491, passphrase="p", on_audio=lambda b: received2.append(b))
        rx2.start(); time.sleep(0.3)
        tx2 = UDPSender(broadcast_addr="127.0.0.1", port=12491, passphrase="p")
        tx2.start(); time.sleep(0.3)
        payload2 = _os.urandom(128)
        tx2.enqueue(payload2); time.sleep(1.0)
        tx2.stop(); rx2.stop(); time.sleep(0.3)
        print("UDP selftest:", "PASS" if payload2 in received2 else "FAIL")
        return
    from gui import main as gui_main
    gui_main()

if __name__ == "__main__":
    main()
