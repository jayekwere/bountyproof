"""Original, bounded vulnerable and corrected implementations. Never expose publicly."""
from contextlib import closing
import base64
import hashlib
import hmac
import html
import json
import re
import secrets
import sqlite3
import subprocess
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).parent / 'fixtures'
JWT_KEY = b'fictional-lab-key-not-production'
PASSWORD = 'fictional-alice-password'
SESSIONS = {'fixture-alice': 'alice', 'fixture-bob': 'bob'}
INVOICES = {'1': {'owner': 'alice', 'total': 120}, '2': {'owner': 'bob', 'total': 450}}


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def jwt_token(subject='alice', signed=True, **claims):
    head = b64(json.dumps({'alg': 'HS256' if signed else 'none', 'typ': 'JWT'}).encode())
    body = b64(json.dumps({'sub': subject, 'iss': 'bountyproof', 'aud': 'local-lab',
                           'exp': int(time.time()) + 600, **claims}).encode())
    message = head + '.' + body
    return message + '.' + (b64(hmac.digest(JWT_KEY, message.encode(), 'sha256')) if signed else '')


def decode_part(value):
    return json.loads(base64.urlsafe_b64decode(value + '=' * (-len(value) % 4)))


def invoice(identifier, session, mode):
    actor = SESSIONS.get(session)
    if not actor:
        return 401, {'error': 'Authentication required'}
    record = INVOICES.get(identifier)
    if not record:
        return 404, {'error': 'Not found'}
    if mode == 'fixed' and record['owner'] != actor:
        return 403, {'error': 'Forbidden'}
    return 200, record


def sql_vulnerable(q):
    with closing(sqlite3.connect(':memory:')) as db:
        db.executescript("CREATE TABLE notes(owner TEXT, body TEXT); INSERT INTO notes VALUES ('alice','Alice note'),('bob','Bob private note');")
        return db.execute("SELECT body FROM notes WHERE owner='alice' AND body LIKE '%" + q + "%'").fetchall()


def sql_fixed(q):
    with closing(sqlite3.connect(':memory:')) as db:
        db.executescript("CREATE TABLE notes(owner TEXT, body TEXT); INSERT INTO notes VALUES ('alice','Alice note'),('bob','Bob private note');")
        return db.execute("SELECT body FROM notes WHERE owner=? AND body LIKE ?", ('alice', '%' + q + '%')).fetchall()


def xss_vulnerable(q):
    return '<!doctype html><title>Search result</title><p>' + q + '</p>'


def xss_fixed(q):
    return '<!doctype html><title>Search result</title><p>' + html.escape(q, quote=True) + '</p>'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def fixture_fetch(url):
    # Immutable transport cage applies even to vulnerable mode: no public targets or redirects.
    if url not in ('http://127.0.0.1:8093/public', 'http://127.0.0.1:8093/private'):
        return 400, {'error': 'Outside immutable fixture transport cage'}
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(url, timeout=2) as response:
        return 200, {'content': response.read(1024).decode()}


def ssrf_vulnerable(url):
    return fixture_fetch(url)


def ssrf_fixed(url):
    if url != 'http://127.0.0.1:8093/public':
        return 403, {'error': 'Destination is not approved'}
    return fixture_fetch(url)


def jwt_vulnerable(token):
    # Decode-only verification mistake.
    return decode_part(token.split('.')[1])['sub']


def jwt_fixed(token):
    head, body, signature = token.split('.')
    header, claims = decode_part(head), decode_part(body)
    expected = b64(hmac.digest(JWT_KEY, (head + '.' + body).encode(), 'sha256'))
    if (header.get('alg') != 'HS256' or not hmac.compare_digest(signature, expected)
            or claims.get('iss') != 'bountyproof' or claims.get('aud') != 'local-lab'
            or type(claims.get('exp')) is not int or claims['exp'] <= time.time()
            or claims.get('sub') not in ('alice', 'bob')):
        raise ValueError('Invalid token')
    return claims['sub']


def oauth_vulnerable(state, cookie, states):
    return 200, {'linked_account': 'fictional-provider-bob'}


def oauth_fixed(state, cookie, states):
    entry = states.get(state)
    if not entry or entry[0] != cookie or entry[1] < time.monotonic():
        return 403, {'error': 'State missing, expired, reused or not bound to session'}
    del states[state]
    return 200, {'linked_account': 'fictional-provider-bob'}


def auth_vulnerable(password, sid, sessions):
    if not hmac.compare_digest(password, PASSWORD):
        return 401, {'error': 'Bad credentials'}, None
    sessions[sid] = 'alice'
    return 200, {'user': 'alice'}, sid


def auth_fixed(password, sid, sessions):
    if not hmac.compare_digest(password, PASSWORD):
        return 401, {'error': 'Bad credentials'}, None
    sessions.pop(sid, None)
    fresh = secrets.token_urlsafe(32)
    sessions[fresh] = 'alice'
    return 200, {'user': 'alice'}, fresh


def path_vulnerable(name):
    return (ROOT / 'public' / name).read_text()


def path_fixed(name):
    target = (ROOT / 'public' / name).resolve()
    if not target.is_relative_to((ROOT / 'public').resolve()):
        raise PermissionError('Path escapes public root')
    return target.read_text()


def command_vulnerable(value):
    return subprocess.run('printf %s ' + value, shell=True, capture_output=True,
                          text=True, timeout=1, check=True).stdout


def command_fixed(value):
    return subprocess.run(['printf', '%s', value], shell=False, capture_output=True,
                          text=True, timeout=1, check=True).stdout


def business_vulnerable(role):
    return 200, {'user': 'alice', 'role': role}


def business_fixed(role):
    if role != 'reader':
        return 403, {'error': 'Role changes require administrator authorization'}
    return 200, {'user': 'alice', 'role': 'reader'}


class Lab:
    def __init__(self, mode):
        if mode not in ('vulnerable', 'fixed'):
            raise ValueError('Invalid mode')
        self.mode = mode
        self.sessions = dict(SESSIONS)
        self.states = {}
        self.roles = {'alice':'reader','bob':'reader'}

    def call(self, path, params, headers):
        get = lambda key, default='': params.get(key, [default])[0]
        cookie = headers.get('Cookie', '').removeprefix('sid=')
        auth = headers.get('Authorization', '').removeprefix('Bearer ')
        fn = lambda name: globals()[name + '_' + self.mode]
        extra = {}
        if path == '/health':
            return 200, {'service': 'bountyproof-lab', 'mode': self.mode}, extra
        if path == '/api/invoices':
            code, body = invoice(get('id'), auth, self.mode)
            return code, body, extra
        if path == '/oauth/start':
            if cookie not in SESSIONS:
                return 401, {'error': 'Fixture session required'}, extra
            state = secrets.token_urlsafe(24)
            self.states = {k: v for k, v in self.states.items() if v[1] > time.monotonic()}
            if len(self.states) >= 100:
                return 429, {'error': 'State capacity reached'}, extra
            self.states[state] = (cookie, time.monotonic() + 60)
            return 200, {'state': state}, extra
        if path == '/oauth/callback':
            code, body = fn('oauth')(get('state'), cookie, self.states)
        elif path == '/auth/login':
            if len(self.sessions) >= 100:
                return 429, {'error': 'Session capacity reached; restart fixture'}, extra
            sid = cookie if re.fullmatch(r'[A-Za-z0-9_-]{1,80}', cookie) else 'anonymous'
            code, body, new = fn('auth')(get('password'), sid, self.sessions)
            if new:
                extra['Set-Cookie'] = f'sid={new}; HttpOnly; SameSite=Strict; Path=/'
        elif path == '/auth/me':
            user = self.sessions.get(cookie)
            code, body = (200, {'user': user}) if user else (401, {'error': 'No session'})
        elif path not in ('/sql', '/xss', '/ssrf', '/jwt', '/path', '/command', '/business', '/business/admin'):
            return 404, {'error': 'Not found'}, extra
        elif auth not in SESSIONS:
            return 401, {'error': 'Fixture bearer required'}, extra
        elif path == '/business/admin':
            if self.roles[SESSIONS[auth]] != 'admin':
                return 403, {'error': 'Administrator role required'}, extra
            return 200, {'audit': 'FICTIONAL_ADMIN_AUDIT_MARKER'}, extra
        elif path == '/sql':
            code, body = 200, {'rows': fn('sql')(get('q'))}
        elif path == '/xss':
            code, body = 200, fn('xss')(get('q'))
        elif path == '/ssrf':
            code, body = fn('ssrf')(get('url'))
        elif path == '/jwt':
            try:
                code, body = 200, {'subject': fn('jwt')(get('token'))}
            except (ValueError, KeyError, IndexError, TypeError):
                code, body = 401, {'error': 'Invalid token'}
        elif path == '/path':
            # Cage limits even vulnerable traversal to two fictional files.
            if get('name') not in ('hello.txt', '../private/marker.txt'):
                return 400, {'error': 'Outside fixture file cage'}, extra
            try:
                code, body = 200, {'content': fn('path')(get('name'))}
            except PermissionError:
                code, body = 403, {'error': 'Path escapes public root'}
        elif path == '/command':
            # Exact immutable payload allowlist prevents arbitrary shell execution.
            if get('value') not in ('hello', 'hello; printf INJECTED'):
                return 400, {'error': 'Outside fixture command cage'}, extra
            code, body = 200, {'output': fn('command')(get('value'))}
        else:
            code, body = fn('business')(get('role', 'reader'))
            if code == 200:
                self.roles[SESSIONS[auth]] = body['role']
        return code, body, extra
