"""Fixed local targets only. No redirects, proxies, target arguments or scanning."""
import json
import urllib.error
import urllib.parse
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def replay(mode, path, params=None, headers=None):
    if mode not in ('vulnerable', 'fixed') or path not in ('/health', '/api/invoices', '/sql', '/xss', '/ssrf', '/jwt', '/oauth/start', '/oauth/callback', '/auth/login', '/auth/me', '/path', '/command', '/business', '/business/admin'):
        raise ValueError('Outside local fixture scope')
    port = 8091 if mode == 'vulnerable' else 8092
    query = urllib.parse.urlencode(params or {})
    url = f'http://127.0.0.1:{port}{path}' + ('?' + query if query else '')
    request_headers = {'Authorization':'Bearer fixture-alice', **(headers or {})}
    request = urllib.request.Request(url, headers=request_headers)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        response = opener.open(request, timeout=3)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        body = response.read(16385)
        if len(body) > 16384:
            raise ValueError('Response exceeds evidence limit')
        return {'request': f'GET {path}' + ('?' + query if query else '') + ' HTTP/1.1\r\nHost: 127.0.0.1:' + str(port) + '\r\n' + '\r\n'.join(k+': '+v for k,v in request_headers.items()),
                'status':response.code, 'headers':dict(response.headers), 'body':body.decode()}


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=['vulnerable','fixed'], default='fixed')
    args = parser.parse_args()
    print(json.dumps(replay(args.mode, '/api/invoices', {'id':'2'}), indent=2))
