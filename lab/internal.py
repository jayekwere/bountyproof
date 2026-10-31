"""Fictional SSRF upstream, loopback only, never configurable."""
from http.server import BaseHTTPRequestHandler, HTTPServer


def make_server():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def do_GET(self):
            data = b'FICTIONAL_INTERNAL_MARKER' if self.path == '/private' else b'Public stock: 7'
            self.send_response(200)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
    return HTTPServer(('127.0.0.1', 8093), Handler)


if __name__ == '__main__':
    make_server().serve_forever()
