from __future__ import annotations

import re
from typing import Any, Dict, List
from urllib.parse import parse_qsl, urlparse, urlunparse

from scanner.utils import ensure_finding, safe_request

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1 --",
    "1 OR 1=1",
]
MAX_SQLI_PARAMS = 2


def build_test_url(base_url: str, parameter: str, payload: str) -> str:
    parsed = urlparse(base_url)
    query_items = parse_qsl(parsed.query, keep_blank_values=True)
    filtered = [(key, value) for key, value in query_items if key != parameter]
    filtered.append((parameter, payload))
    new_query = '&'.join(f'{key}={value}' for key, value in filtered)
    return urlunparse(parsed._replace(query=new_query))


def scan_sql_injection(target_url: str, urls: List[str]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    seen = set()
    for url in urls:
        try:
            parsed = urlparse(url)
            params = [key for key, _ in parse_qsl(parsed.query, keep_blank_values=True) if key]
            if not params:
                continue

            baseline = safe_request(url, timeout=5)
            for parameter in params[:MAX_SQLI_PARAMS]:
                for payload in SQLI_PAYLOADS[:2]:
                    test_url = build_test_url(url, parameter, payload)
                    if test_url in seen:
                        continue
                    seen.add(test_url)
                    try:
                        result = safe_request(test_url, timeout=5)
                    except Exception:
                        continue
                    if result.status_code != baseline.status_code:
                        evidence = f'Status changed from {baseline.status_code} to {result.status_code} for parameter {parameter}.'
                        findings.append(
                            ensure_finding({
                                'title': 'Potential SQL injection behavior detected',
                                'severity': 'medium',
                                'url': test_url,
                                'parameter': parameter,
                                'description': 'A query parameter produced a different response profile when a SQL-like payload was supplied.',
                                'evidence': evidence,
                                'impact': 'Suspicious behavior may indicate insecure query construction or error-based SQL injection exposure.',
                                'remediation': 'Use parameterized queries and database abstraction layers to prevent injection vulnerabilities.'
                            })
                        )
                        continue
                    if abs(len(result.text or '') - len(baseline.text or '')) > 150:
                        evidence = f'Response length changed substantially for {parameter} (baseline: {len(baseline.text or "")}, mutated: {len(result.text or "")}).'
                        findings.append(
                            ensure_finding({
                                'title': 'Abnormal SQL injection response pattern',
                                'severity': 'medium',
                                'url': test_url,
                                'parameter': parameter,
                                'description': 'A payload introduced a large change in the response body, which can be consistent with injection or error handling behavior.',
                                'evidence': evidence,
                                'impact': 'Unexpected application behavior can reveal database errors or vulnerable query logic.',
                                'remediation': 'Inspect database query construction and ensure all SQL statements are parameterized and validated.'
                            })
                        )
                        continue
                    errors = ['sql syntax', 'mysql', 'sqlite3', 'syntax error', 'ora-', 'postgresql']
                    body_text = (result.text or '').lower()
                    if any(msg in body_text for msg in errors):
                        findings.append(
                            ensure_finding({
                                'title': 'Database error message exposed',
                                'severity': 'high',
                                'url': test_url,
                                'parameter': parameter,
                                'description': 'The application appears to expose a database-related error message when payloads are submitted.',
                                'evidence': f'Error-like content: {result.text[:200]}',
                                'impact': 'Detailed error messages can provide attackers with database schema and syntax details.',
                                'remediation': 'Hide database errors from end users and log them securely on the server side.'
                            })
                        )
        except Exception:
            continue
    return findings
