"""Start owned fixtures, verify HTTP behavior and publish measured evidence."""
import hashlib
import inspect
import json
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from lab import scenarios
from lab.catalog import catalog
from lab.internal import make_server as internal_server
from lab.server import make_server
from tools.replay import replay

ROOT = Path(__file__).resolve().parent.parent


@contextmanager
def servers():
    listeners = []
    try:
        for factory in (lambda: make_server('vulnerable'), lambda: make_server('fixed'), internal_server):
            listener = factory()
            listeners.append(listener)
            threading.Thread(target=listener.serve_forever, daemon=True).start()
        yield
    finally:
        for listener in listeners:
            listener.shutdown()
            listener.server_close()


def body(response):
    return json.loads(response['body'])


def verify():
    findings = []
    for item in catalog():
        slug = item['slug']
        attack, legit = dict(item['attack']), dict(item['legitimate'])
        if slug == 'jwt':
            attack = {'token':scenarios.jwt_token('bob', signed=False)}
            legit = {'token':scenarios.jwt_token()}
        before = replay('vulnerable', item['path'], attack, {'Cookie':'sid=known-session'} if slug == 'auth' else None)
        after = replay('fixed', item['path'], attack, {'Cookie':'sid=known-session'} if slug == 'auth' else None)
        assert before['status'] == 200, (slug, before)
        exploit_values = {
            'idor': {'owner':'bob','total':450},
            'ssrf': {'content':'FICTIONAL_INTERNAL_MARKER'},
            'jwt': {'subject':'bob'},
            'oauth': {'linked_account':'fictional-provider-bob'},
            'auth': {'user':'alice'},
            'business': {'user':'alice','role':'admin'},
            'path': {'content':'FICTIONAL_PRIVATE_MARKER\n'},
        }
        if slug in exploit_values:
            assert body(before) == exploit_values[slug], (slug,before)
        if slug in ('idor','ssrf','oauth','path','business'):
            assert after['status'] == 403, (slug, after)
        elif slug == 'jwt':
            assert after['status'] == 401
        elif slug == 'sql':
            assert ['Bob private note'] in body(before)['rows'] and body(after)['rows'] == []
        elif slug == 'xss':
            assert '<script>' in before['body'] and '&lt;script&gt;' in after['body']
        elif slug == 'command':
            assert body(before)['output'] == 'helloINJECTED'
            assert body(after)['output'] == 'hello; printf INJECTED'
        extras = []
        if slug == 'oauth':
            start = replay('fixed','/oauth/start',headers={'Cookie':'sid=fixture-alice'})
            legit = {'state':body(start)['state']}
            valid = replay('fixed', item['path'], legit, {'Cookie':'sid=fixture-alice'})
            reused = replay('fixed', item['path'], legit, {'Cookie':'sid=fixture-alice'})
            assert reused['status'] == 403
            extras.append(reused)
        elif slug == 'auth':
            old_before = replay('vulnerable','/auth/me',headers={'Cookie':'sid=known-session'})
            old_after = replay('fixed','/auth/me',headers={'Cookie':'sid=known-session'})
            assert old_before['status'] == 200 and old_after['status'] == 401
            cookie = next(value for key,value in after['headers'].items() if key.lower() == 'set-cookie').split(';')[0]
            valid = replay('fixed','/auth/me',headers={'Cookie':cookie})
            extras += [old_before,old_after]
        else:
            valid = replay('fixed', item['path'], legit)
        assert valid['status'] == 200, (slug, valid)
        positive_values = {
            'idor': {'owner':'alice','total':120},
            'sql': {'rows':[['Alice note']]},
            'ssrf': {'content':'Public stock: 7'},
            'jwt': {'subject':'alice'},
            'oauth': {'linked_account':'fictional-provider-bob'},
            'auth': {'user':'alice'},
            'path': {'content':'Public fixture document\n'},
            'command': {'output':'hello'},
            'business': {'user':'alice','role':'reader'},
        }
        if slug == 'xss':
            assert valid['body'] == '<!doctype html><title>Search result</title><p>hello</p>'
        else:
            assert body(valid) == positive_values[slug], (slug,valid)
        if slug == 'idor':
            bob = replay('fixed',item['path'],attack,{'Authorization':'Bearer fixture-bob'})
            assert bob['status'] == 200 and body(bob) == {'owner':'bob','total':450}
            extras.append(bob)
        source = item['source']
        if source == 'invoice':
            vulnerable_code = fixed_code = inspect.getsource(scenarios.invoice)
        else:
            vulnerable_code = inspect.getsource(getattr(scenarios, source+'_vulnerable'))
            fixed_code = inspect.getsource(getattr(scenarios, source+'_fixed'))
        findings.append({**item, 'attack':attack,'legitimate':legit, 'before':before, 'after':after,
                         'positive':valid, 'additional':extras,'vulnerableCode':vulnerable_code,
                         'fixedCode':fixed_code,'status':'Verified over HTTP',
                         'checks':{'reproduced':True,'remediated':True,'legitimateAccess':True}})
    return {'schemaVersion':1,'generatedAt':datetime.now(timezone.utc).isoformat(),
            'sourceSha256':hashlib.sha256((ROOT/'lab/scenarios.py').read_bytes()).hexdigest(),
            'scope':'Owned local fictional fixtures only','findings':findings}


if __name__ == '__main__':
    with servers():
        evidence = verify()
    (ROOT/'evidence/results.json').write_text(json.dumps(evidence,indent=2)+'\n')
    print('Verified 10 exploit reproductions, 10 remediations and 10 legitimate operations over HTTP.')
