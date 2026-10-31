import unittest
from lab.server import invoice


class AuthorizationTests(unittest.TestCase):
    def test_exploit_and_remediation(self):
        self.assertEqual(invoice('2', 'fixture-alice', 'vulnerable')[0], 200)
        self.assertEqual(invoice('2', 'fixture-alice', 'fixed')[0], 403)

    def test_legitimate_access(self):
        for mode in ('vulnerable', 'fixed'):
            self.assertEqual(invoice('1', 'fixture-alice', mode)[0], 200)
            self.assertEqual(invoice('2', 'fixture-bob', mode)[0], 200)

    def test_unauthenticated_and_missing(self):
        for mode in ('vulnerable', 'fixed'):
            self.assertEqual(invoice('2', '', mode)[0], 401)
            self.assertEqual(invoice('3', 'fixture-alice', mode)[0], 404)
