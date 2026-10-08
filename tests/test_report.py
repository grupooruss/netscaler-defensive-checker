import tempfile
import unittest
from pathlib import Path
from checker import evaluate
from report import render_html

class ReportTests(unittest.TestCase):
    def test_html_has_eight_cves_and_no_config_lines(self):
        config = 'add vpn vserver confidential-vpn SSL 192.0.2.9 443'
        report = evaluate(config, '14.1-73.20')
        html = render_html(report)
        self.assertEqual(html.count('<tr><td><strong>CVE-2026-'), 8)
        self.assertNotIn('confidential-vpn', html)
        self.assertNotIn('192.0.2.9', html)
        self.assertIn('Potential exposure', html)
    def test_untrusted_build_escaped(self):
        report = evaluate('add vpn vserver a SSL 192.0.2.1 443', '<script>alert(1)</script>')
        html = render_html(report)
        self.assertNotIn('<script>alert(1)</script>', html)
        self.assertIn('&lt;script&gt;', html)
    def test_html_standalone(self):
        html = render_html(evaluate('add lb vserver prod TCP 192.0.2.1 443', '14.1-73.37'))
        self.assertIn('<!doctype html>', html)
        self.assertIn('<style>', html)
        self.assertNotIn('https://cdn.', html)
if __name__ == '__main__': unittest.main()
