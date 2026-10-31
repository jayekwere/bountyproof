"""Lab listeners only. Management UI is a separate read-only server."""
import argparse
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit
from lab.scenarios import Lab, invoice


def make_server(mode, host='127.0.0.1', port=None):
    port = port or (8091 if mode == 'vulnerable' else 8092)
    lab = Lab(mode)

    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(3)

        def log_message(self, *args):
            pass

        def do_GET(self):
            if self.headers.get('Host') not in (f'127.0.0.1:{port}', f'localhost:{port}'):
                self.send_error(403)
                return
            if self.headers.get('Origin') or self.headers.get('Sec-Fetch-Site') == 'cross-site':
                self.send_error(403)
                return
            if len(self.path) > 4096 or self.headers.get('Transfer-Encoding') or int(self.headers.get('Content-Length', '0')):
                self.send_error(413)
                return
            url = urlsplit(self.path)
            try:
                code, body, extra = lab.call(url.path, parse_qs(url.query), self.headers)
            except Exception:
                code, body, extra = 400, {'error': 'Invalid fixture input'}, {}
            data = body.encode() if isinstance(body, str) else json.dumps(body).encode()
            self.send_response(code)
            self.send_header('Content-Type', 'text/html; charset=utf-8' if isinstance(body, str) else 'application/json')
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            # XSS endpoint deliberately permits inline script in vulnerable fixture.
            self.send_header('Content-Security-Policy', "default-src 'none'; script-src 'unsafe-inline'; frame-ancestors 'none'")
            for key, value in extra.items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(data)
    return HTTPServer((host, port), Handler)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', choices=['vulnerable', 'fixed'], default='fixed')
    args = parser.parse_args()
    make_server(args.mode, '0.0.0.0' if os.environ.get('BOUNTYPROOF_CONTAINER') == '1' else '127.0.0.1').serve_forever()
