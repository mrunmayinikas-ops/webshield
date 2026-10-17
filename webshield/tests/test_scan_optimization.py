import unittest
from unittest.mock import Mock, patch

from scanner.sqli_scanner import scan_sql_injection
from scanner.xss_scanner import scan_xss


class ScanOptimizationTests(unittest.TestCase):
    def _mock_response(self, *, text='', status_code=200):
        response = Mock()
        response.text = text
        response.status_code = status_code
        response.headers = {}
        return response

    @patch('scanner.xss_scanner.safe_request')
    def test_xss_scan_checks_all_supplied_urls(self, mock_request):
        base_url = 'https://example.com/page?foo=1&bar=2&baz=3&qux=4'
        urls = [base_url, base_url + '?foo=2', base_url + '?bar=3', base_url + '?baz=4']
        mock_request.return_value = self._mock_response(text='static page')

        findings = scan_xss(base_url, urls)

        self.assertIsInstance(findings, list)
        self.assertGreater(mock_request.call_count, 24)

    @patch('scanner.sqli_scanner.safe_request')
    def test_sqli_scan_keeps_request_budget_under_control(self, mock_request):
        base_url = 'https://example.com/page?user=alice&role=admin&search=hello'
        urls = [base_url, base_url + '?search=world', base_url + '?role=user']
        mock_request.return_value = self._mock_response(text='static page', status_code=200)

        findings = scan_sql_injection(base_url, urls)

        self.assertIsInstance(findings, list)
        self.assertLessEqual(mock_request.call_count, 20)


if __name__ == '__main__':
    unittest.main()
