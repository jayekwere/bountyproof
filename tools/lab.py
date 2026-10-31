"""Start the three owned loopback fixture services. Ctrl-C stops all."""
import signal
import threading
from tools.verify import servers

if __name__ == '__main__':
    stopped = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopped.set())
    signal.signal(signal.SIGINT, lambda *_: stopped.set())
    with servers():
        print('Owned labs: vulnerable 127.0.0.1:8091, fixed 127.0.0.1:8092; internal upstream 8093', flush=True)
        stopped.wait()
