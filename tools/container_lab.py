"""Container entrypoint: one mode plus private upstream within its namespace."""
import os
import threading
from lab.internal import make_server as internal_server
from lab.server import make_server

if __name__ == '__main__':
    internal = internal_server()
    threading.Thread(target=internal.serve_forever,daemon=True).start()
    make_server(os.environ.get('LAB_MODE','fixed'),'0.0.0.0').serve_forever()
