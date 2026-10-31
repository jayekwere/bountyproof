import time
import unittest
from lab.scenarios import Lab, jwt_token, jwt_fixed, path_fixed
from tools.replay import replay
from tools.verify import servers, verify


class HttpLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.context = servers()
        cls.context.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.context.__exit__(None, None, None)

    def test_ten_full_lifecycles(self):
        data = verify()
        self.assertEqual(len(data['findings']), 10)
        for item in data['findings']:
            self.assertTrue(all(item['checks'].values()))

    def test_cages_deny_nonfixture_inputs(self):
        for mode in ('vulnerable','fixed'):
            for path,params in [('/command',{'value':'id'}),('/path',{'name':'/etc/passwd'}),('/ssrf',{'url':'http://example.com'}),('/ssrf',{'url':'http://127.0.0.1:8093/public@evil.com'})]:
                self.assertIn(replay(mode,path,params)['status'], (400,403))

    def test_unauthenticated_scenario_access(self):
        for mode in ('vulnerable','fixed'):
            for path in ('/sql','/ssrf','/path','/command','/business'):
                self.assertEqual(replay(mode,path,headers={'Authorization':''})['status'],401)

    def test_dns_rebinding_and_cross_origin_denied(self):
        for mode in ('vulnerable','fixed'):
            self.assertEqual(replay(mode,'/health',headers={'Host':'evil.example'})['status'],403)
            self.assertEqual(replay(mode,'/health',headers={'Origin':'http://evil.example'})['status'],403)

    def test_bad_login_and_jwt_inputs(self):
        self.assertEqual(replay('fixed','/auth/login',{'password':'wrong'})['status'],401)
        for token in ('bad','e30.e30.','a.b.c','..'):
            self.assertEqual(replay('fixed','/jwt',{'token':token})['status'],401)


class FixedBoundaryTests(unittest.TestCase):
    def test_jwt_signature_expiry_audience_issuer(self):
        for token in (jwt_token(signed=False),jwt_token(exp=0),jwt_token(aud='other'),jwt_token(iss='other'),jwt_token('admin'),jwt_token()+'x'):
            with self.assertRaises(ValueError):
                jwt_fixed(token)
        self.assertEqual(jwt_fixed(jwt_token()),'alice')

    def test_oauth_binding_expiration_and_reuse(self):
        lab = Lab('fixed')
        lab.states['valid'] = ('fixture-alice',time.monotonic()+10)
        lab.states['expired'] = ('fixture-alice',0)
        def call(state,cookie):
            return lab.call('/oauth/callback',{'state':[state]},{'Cookie':'sid='+cookie})[0]
        self.assertEqual(call('valid','fixture-bob'),403)
        self.assertEqual(call('expired','fixture-alice'),403)
        self.assertEqual(call('valid','fixture-alice'),200)
        self.assertEqual(call('valid','fixture-alice'),403)

    def test_path_canonicalization(self):
        for path in ('../private/marker.txt','../../../../etc/passwd','/etc/passwd'):
            with self.assertRaises(PermissionError):
                path_fixed(path)
        self.assertIn('Public',path_fixed('hello.txt'))

    def test_state_and_session_capacity(self):
        lab = Lab('fixed')
        lab.sessions = {str(i): 'alice' for i in range(100)}
        self.assertEqual(lab.call('/auth/login', {'password':['fictional-alice-password']}, {})[0],429)
        lab.states = {str(i): ('fixture-alice',time.monotonic()+60) for i in range(100)}
        self.assertEqual(lab.call('/oauth/start', {}, {'Cookie':'sid=fixture-alice'})[0],429)
