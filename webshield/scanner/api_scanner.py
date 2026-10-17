from __future__ import annotations

from typing import Any, Dict, List

from scanner.sqli_scanner import scan_sql_injection
from scanner.utils import ensure_finding, safe_request
from scanner.xss_scanner import scan_xss


SENSITIVE_KEYS = {'password', 'passwd', 'secret', 'token', 'api_key', 'apikey', 'private_key'}


def _api_finding(endpoint: Dict[str, Any], title: str, severity: str, description: str, evidence: str, remediation: str) -> Dict[str, Any]:
    return ensure_finding({
        'title': f'API: {title}',
        'severity': severity,
        'url': endpoint.get('url', 'N/A'),
        'parameter': endpoint.get('method', 'GET'),
        'description': description,
        'evidence': evidence,
        'impact': 'API responses can expose application behavior or sensitive data to unauthorized clients.',
        'remediation': remediation,
        'api': True,
        'method': endpoint.get('method', 'GET'),
        'status_code': endpoint.get('status_code'),
        'content_type': endpoint.get('content_type', ''),
    })


def scan_api_endpoints(endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for endpoint in endpoints:
        url = endpoint.get('url')
        if not url:
            continue
        try:
            response = safe_request(url, timeout=5, allow_redirects=True)
            content_type = response.headers.get('Content-Type', '')
            body = response.text or ''
            lowered = body.lower()
            if response.headers.get('Access-Control-Allow-Origin') == '*':
                findings.append(_api_finding(endpoint, 'Wildcard CORS policy', 'medium', 'The API allows requests from every origin.', 'Access-Control-Allow-Origin: *', 'Restrict CORS to trusted origins and avoid wildcard access for authenticated APIs.'))
            if any(f'"{key}"' in lowered or f"'{key}'" in lowered for key in SENSITIVE_KEYS):
                findings.append(_api_finding(endpoint, 'Potential sensitive data exposure', 'medium', 'The API response contains a key commonly associated with secrets or credentials.', 'A sensitive field name was found in the response body.', 'Return only the fields required by the client and never expose credentials or private tokens.'))
            if any(error in lowered for error in ('traceback', 'stack trace', 'sql syntax', 'syntax error', 'exception at')):
                findings.append(_api_finding(endpoint, 'Error details exposed', 'medium', 'The API response appears to expose implementation or database error details.', 'Error-like text was found in the API response.', 'Return generic client errors and keep detailed diagnostics in server-side logs.'))

            existing_urls = [url]
            for finding in scan_xss(url, existing_urls) + scan_sql_injection(url, existing_urls):
                finding['title'] = f"API: {finding.get('title', 'Security finding')}"
                finding['api'] = True
                finding['method'] = endpoint.get('method', 'GET')
                finding['status_code'] = response.status_code
                finding['content_type'] = content_type
                findings.append(finding)
        except Exception:
            continue
    return findings
