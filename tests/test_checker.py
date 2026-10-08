import unittest
from checker import build_check, evaluate
class CheckerTests(unittest.TestCase):
    def test_build_boundaries(self):
        self.assertEqual(build_check('14.1-73.36','standard')[0],'affected_build')
        self.assertEqual(build_check('14.1-73.37','standard')[0],'fixed_build')
        self.assertEqual(build_check('13.1-64.23','standard')[0],'fixed_build')
        self.assertEqual(build_check('13.1-37.278','fips')[0],'affected_build')
        self.assertEqual(build_check('13.1-37.279','ndcpp')[0],'fixed_build')
        self.assertEqual(build_check('13.0-99.99','standard')[0],'unknown')
    def test_vpn_dtls_default(self):
        r=evaluate('add vpn vserver vpn1 SSL 192.0.2.1 443','14.1-73.10')
        self.assertEqual(r['results'][1]['status'],'potentially_exposed')
    def test_vpn_dtls_off(self):
        r=evaluate('add vpn vserver vpn1 SSL 192.0.2.1 443 -dtls OFF','14.1-73.10')
        self.assertEqual(r['results'][1]['status'],'precondition_not_observed')
    def test_oracle(self):
        r=evaluate('add lb vserver prod ORACLE 192.0.2.2 1521','13.1-64.01')
        self.assertEqual(r['results'][5]['status'],'potentially_exposed')
    def test_isn(self):
        r=evaluate('add lb vserver prod TCP 192.0.2.2 443','14.1-73.10',tcpparam='Enhanced ISN Generation: DISABLED')
        self.assertEqual(r['results'][7]['status'],'potentially_exposed')
    def test_fixed(self):
        r=evaluate('add vpn vserver vpn1 SSL 192.0.2.1 443','14.1-73.37')
        self.assertTrue(all(x['status']=='fixed_build' for x in r['results']))
    def test_missing_build(self):
        r=evaluate('add vpn vserver vpn1 SSL 192.0.2.1 443')
        self.assertTrue(all(x['status']=='unknown_build' for x in r['results']))
if __name__=='__main__':unittest.main()
