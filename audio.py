import queue, threading
import numpy as np
import sounddevice as sd
SAMPLE_RATE = 16000
CHANNELS = 1
CHUNK = 1024

class AudioCapture:
    def __init__(self, on_chunk, sample_rate=SAMPLE_RATE, chunk_frames=CHUNK):
        self.on_chunk = on_chunk
        self.sample_rate = sample_rate
        self.chunk_frames = chunk_frames
        self._stream = None; self._running = False

    def start(self):
        self._running = True
        self._stream = sd.InputStream(samplerate=self.sample_rate, channels=CHANNELS,
                                      dtype="int16", blocksize=self.chunk_frames,
                                      callback=self._cb)
        self._stream.start()

    def stop(self):
        self._running = False
        if self._stream:
            try:
                self._stream.stop(); self._stream.close()
            except Exception:
                pass
            self._stream = None

    def _cb(self, indata, frames, time_info, status):
        if self._running:
            self.on_chunk(np.copy(indata).astype("int16").tobytes())

class AudioPlayer:
    def __init__(self, sample_rate=SAMPLE_RATE):
        self.sample_rate = sample_rate
        self._stream = None; self._q = queue.Queue(maxsize=64)
        self._running = False; self._thread = None

    def start(self):
        self._running = True
        self._stream = sd.OutputStream(samplerate=self.sample_rate, channels=CHANNELS, dtype="int16")
        self._stream.start()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        try:
            self._q.put_nowait(None)
        except queue.Full:
            pass
        if self._thread:
            self._thread.join(timeout=2)
        if self._stream:
            try:
                self._stream.stop(); self._stream.close()
            except Exception:
                pass
            self._stream = None

    def play(self, chunk):
        if self._running:
            try:
                self._q.put_nowait(chunk)
            except queue.Full:
                pass

    def _loop(self):
        while self._running:
            chunk = self._q.get()
            if chunk is None:
                break
            try:
                arr = np.frombuffer(chunk, dtype="int16").reshape(-1, CHANNELS)
                self._stream.write(arr)
            except Exception:
                pass

def list_devices():
    return sd.query_devices()
