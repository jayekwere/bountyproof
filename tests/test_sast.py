import unittest
from tools.sast import validate


class SastGateTests(unittest.TestCase):
    def test_missing_control_or_scanner_error_fails(self):
        for data in ({'results':[]},{'errors':[{'message':'failed'}],'results':[]}):
            with self.assertRaises(ValueError):
                validate(data)

    def test_unreviewed_finding_fails(self):
        with self.assertRaises(ValueError):
            validate({'results':[{'check_id':'python-shell-execution','path':'src/server.ts','start':{'line':1}}]})
