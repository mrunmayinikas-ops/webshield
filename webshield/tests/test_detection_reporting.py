import unittest
from unittest.mock import Mock, patch

from app import compile_scan_result, deduplicate_findings, normalize_scan_summary, scan_page_headers
from scanner.headers import analyze_headers, passed_security_headers
from scanner.path_scanner import scan_sensitive_paths
from scanner.sqli_scanner import scan_sql_injection
from scanner.xss_scanner import scan_xss


class DetectionReportingTests(unittest.TestCase):
    def response(self, headers=None, text='normal page', status_code=200):
        response = Mock()
        response.headers = headers or {}
        response.text = text
        response.status_code = status_code
        return response

    @patch('scanner.headers.safe_request')
    def test_frame_header_missing(self, request):
        request.return_value = self.response()
        findings = analyze_headers('https://example.com/')
        frame = [item for item in findings if item['parameter'] == 'X-Frame-Options' and 'missing' in item['title'].lower()]
        self.assertEqual(len(frame), 1)

    @patch('scanner.headers.safe_request')
    def test_frame_header_present_case_insensitively(self, request):
        request.return_value = self.response({'x-frame-options': 'SAMEORIGIN'})
        findings = analyze_headers('https://example.com/')
        missing = [item for item in findings if item['parameter'] == 'X-Frame-Options' and 'missing' in item['title'].lower()]
        self.assertEqual(missing, [])

    @patch('scanner.headers.safe_request')
    def test_nosniff_is_present_case_insensitively(self, request):
        request.return_value = self.response({'X-CONTENT-TYPE-OPTIONS': 'nosniff'})
        findings = analyze_headers('https://example.com/')
        missing = [item for item in findings if item['parameter'] == 'X-Content-Type-Options' and 'missing' in item['title'].lower()]
        self.assertEqual(missing, [])

    def test_present_security_headers_count_as_passes(self):
        response = self.response({
            'Content-Security-Policy': "default-src 'self'",
            'Strict-Transport-Security': 'max-age=31536000',
            'X-Frame-Options': 'DENY',
            'X-Content-Type-Options': 'nosniff',
            'Referrer-Policy': 'no-referrer',
            'Permissions-Policy': 'geolocation=()',
        })
        self.assertEqual(len(passed_security_headers('https://example.com/', response)), 6)

    def test_compiled_scan_counts_passed_security_headers(self):
        summary = compile_scan_result(
            'https://example.com/',
            ['https://example.com/'],
            [],
            {'passed_header_rules': [
                'Content-Security-Policy', 'Strict-Transport-Security',
                'X-Frame-Options', 'X-Content-Type-Options',
                'Referrer-Policy', 'Permissions-Policy',
            ]},
        )
        self.assertEqual(summary['secure_checks'], 6)

    @patch('scanner.xss_scanner.safe_request')
    @patch('scanner.sqli_scanner.safe_request')
    def test_successful_xss_and_sqli_checks_count_as_secure_checks(self, sqli_request, xss_request):
        xss_request.side_effect = [
            Mock(text='<html><body><h1>hello</h1></body></html>', status_code=200, headers={'Content-Type': 'text/html'}),
            Mock(text='<html><body><h1>hello</h1></body></html>', status_code=200, headers={'Content-Type': 'text/html'}),
            Mock(text='<html><body><h1>hello</h1></body></html>', status_code=200, headers={'Content-Type': 'text/html'}),
            Mock(text='<html><body><h1>hello</h1></body></html>', status_code=200, headers={'Content-Type': 'text/html'}),
        ]
        sqli_request.side_effect = [
            Mock(text='<html><body><h1>hello</h1></body></html>', status_code=200, headers={'Content-Type': 'text/html'}),
            Mock(text='<html><body><h1>hello</h1></body></html>', status_code=200, headers={'Content-Type': 'text/html'}),
        ]
        findings, xss_passes = scan_xss('https://example.com/?id=1', ['https://example.com/?id=1'], include_passes=True)
        self.assertEqual(findings, [])
        self.assertGreater(len(xss_passes), 0)

        sqli_findings, sqli_passes = scan_sql_injection('https://example.com/?id=1', ['https://example.com/?id=1'], include_passes=True)
        self.assertEqual(sqli_findings, [])
        self.assertGreater(len(sqli_passes), 0)

    def test_normalized_scan_preserves_passed_security_headers(self):
        summary = normalize_scan_summary({
            'target_url': 'https://example.com/',
            'passed_header_rules': ['X-Frame-Options', 'Referrer-Policy'],
            'findings': [{
                'title': 'Frame protection policy may be weaker than recommended',
                'severity': 'informational',
                'parameter': 'X-Frame-Options',
                'url': 'https://example.com/',
            }],
        })
        self.assertEqual(summary['secure_checks'], 2)

    def test_explicit_passes_are_not_erased_by_other_page_failures(self):
        summary = normalize_scan_summary({
            'target_url': 'https://example.com/',
            'passed_header_rules': ['X-Frame-Options'],
            'findings': [{
                'title': 'Frame protection is missing',
                'severity': 'low',
                'parameter': 'X-Frame-Options',
                'url': 'https://example.com/missing',
            }],
        })
        self.assertEqual(summary['secure_checks'], 1)

    def test_legacy_sameorigin_finding_still_counts_as_secure_check(self):
        summary = normalize_scan_summary({
            'target_url': 'https://example.com/',
            'findings': [{
                'title': 'HTTP Strict Transport Security is missing',
                'severity': 'low',
                'parameter': 'Strict-Transport-Security',
                'url': 'https://example.com/',
            }, {
                'title': 'Frame protection policy may be weaker than recommended',
                'severity': 'informational',
                'parameter': 'X-Frame-Options',
                'url': 'https://example.com/',
            }],
        })
        self.assertEqual(summary['secure_checks'], 5)
    @patch('scanner.headers.safe_request')
    def test_hsts_is_skipped_for_http(self, request):
        request.return_value = self.response()
        findings = analyze_headers('http://example.com/')
        self.assertFalse(any(item['parameter'] == 'Strict-Transport-Security' for item in findings))

    @patch('scanner.headers.safe_request')
    def test_hsts_missing_for_https(self, request):
        request.return_value = self.response()
        findings = analyze_headers('https://example.com/')
        self.assertTrue(any(item['parameter'] == 'Strict-Transport-Security' and 'missing' in item['title'].lower() for item in findings))

    def test_duplicate_findings_keep_affected_urls(self):
        findings = [
            {'title': 'Content Security Policy is missing', 'severity': 'low', 'parameter': 'Content-Security-Policy', 'url': 'https://example.com/page/1', 'evidence': 'Header missing'},
            {'title': 'Content Security Policy is missing', 'severity': 'low', 'parameter': 'Content-Security-Policy', 'url': 'https://example.com/page/2', 'evidence': 'Header missing'},
        ]
        summary = compile_scan_result('https://example.com/', [item['url'] for item in findings], findings)
        self.assertEqual(summary['vulnerability_count'], 1)
        self.assertEqual(summary['findings'][0]['affected_url_count'], 2)

    def test_44_duplicate_csp_instances_become_one_group(self):
        urls = [f'https://example.com/page/{index}' for index in range(44)]
        findings = [
            {
                'rule_id': 'header:missing:content-security-policy',
                'title': 'Content Security Policy is missing',
                'severity': 'low',
                'parameter': 'Content-Security-Policy',
                'url': url,
                'evidence': 'Header: Content-Security-Policy Observed: Missing Expected: header present.',
            }
            for url in urls
        ]
        summary = compile_scan_result('https://example.com/', urls, findings)
        self.assertEqual(summary['finding_instances'], 44)
        self.assertEqual(summary['unique_findings'], 1)
        self.assertEqual(summary['findings'][0]['affected_url_count'], 44)
        self.assertEqual(summary['affected_url_count'], 44)

    def test_legacy_header_titles_still_group_by_rule(self):
        urls = [f'https://example.com/page/{index}' for index in range(44)]
        findings = [
            {
                'title': 'Content Security Policy is missing',
                'severity': 'high',
                'parameter': 'Content-Security-Policy',
                'url': url,
                'evidence': f'Content-Security-Policy was not found at {url}.',
            }
            for url in urls
        ]
        grouped = deduplicate_findings(findings)
        self.assertEqual(len(grouped), 1)
        self.assertEqual(grouped[0]['affected_url_count'], 44)

    def test_legacy_missing_headers_are_not_high(self):
        summary = normalize_scan_summary({
            'target_url': 'https://example.com/',
            'findings': [{
                'title': 'Content Security Policy is missing',
                'severity': 'high',
                'parameter': 'Content-Security-Policy',
                'url': 'https://example.com/',
                'evidence': 'Header missing',
            }],
        })
        self.assertEqual(summary['high'], 0)
        self.assertEqual(summary['low'], 1)

    def test_legacy_undefined_referrer_policy_is_not_high(self):
        summary = normalize_scan_summary({
            'target_url': 'https://example.com/',
            'findings': [{
                'title': 'Referrer policy is not defined',
                'severity': 'high',
                'parameter': 'Referrer-Policy',
                'url': 'https://example.com/',
                'evidence': 'Referrer policy was not defined.',
            }],
        })
        self.assertEqual(summary['high'], 0)
        self.assertEqual(summary['low'], 1)

    @patch('scanner.sqli_scanner.safe_request')
    def test_single_500_is_not_sql_injection(self, request):
        request.side_effect = [
            self.response(text='normal page', status_code=200),
            self.response(text='server error', status_code=500),
            self.response(text='normal page', status_code=200),
        ]
        findings = scan_sql_injection('https://example.com/', ['https://example.com/?id=1'])
        self.assertFalse(any(item['title'] == 'Potential SQL Injection' for item in findings))

    @patch('app.safe_request')
    def test_page_header_checks_reuse_one_response(self, request):
        request.return_value = self.response({'Server': 'test'})
        findings = scan_page_headers('https://example.com/')
        self.assertTrue(findings)
        self.assertEqual(request.call_count, 1)

    @patch('scanner.path_scanner.safe_request')
    def test_reachable_dashboard_without_sensitive_content_is_low(self, request):
        request.return_value = self.response(text='not found', status_code=200)
        findings = scan_sensitive_paths('https://example.com/')
        dashboard = next(item for item in findings if item['url'].endswith('/dashboard'))
        self.assertEqual(dashboard['title'], 'Potentially sensitive endpoint discovered')
        self.assertEqual(dashboard['severity'], 'low')

    @patch('scanner.path_scanner.safe_request')
    def test_dashboard_with_sensitive_content_remains_high(self, request):
        request.return_value = self.response(text='<h1>Dashboard</h1><a>Logout</a>', status_code=200)
        findings = scan_sensitive_paths('https://example.com/')
        dashboard = next(item for item in findings if item['url'].endswith('/dashboard'))
        self.assertEqual(dashboard['severity'], 'high')

    @patch('scanner.path_scanner.safe_request')
    def test_other_sensitive_paths_keep_existing_200_findings(self, request):
        request.return_value = self.response(text='normal page', status_code=200)
        findings = scan_sensitive_paths('https://example.com/')
        admin = next(item for item in findings if item['url'].endswith('/admin'))
        self.assertEqual(admin['title'], 'Sensitive path accessible: /admin')
        self.assertEqual(admin['severity'], 'high')


if __name__ == '__main__':
    unittest.main()
