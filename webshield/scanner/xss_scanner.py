from __future__ import annotations

import re
from typing import Any, Dict, List
from urllib.parse import parse_qsl, urlparse, urlunparse

from scanner.utils import ensure_finding, extract_forms, safe_request

XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '";alert(1);//',
    '<img src=x onerror=alert(1)>',
]
MAX_XSS_PARAMS = 3


def build_test_url(base_url: str, parameter: str, payload: str) -> str:
    parsed = urlparse(base_url)
    query_items = parse_qsl(parsed.query, keep_blank_values=True)
    query_items = [(key, value) for key, value in query_items if key != parameter]
    query_items.append((parameter, payload))
    new_query = '&'.join(f'{key}={value}' for key, value in query_items)
    return urlunparse(parsed._replace(query=new_query))


def scan_xss(target_url: str, urls: List[str]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    seen = set()
    for url in urls:
        try:
            response = safe_request(url, timeout=5)
            html = response.text or ''
            if not html:
                continue

            url_params: List[str] = []
            parsed = urlparse(url)
            for key, _ in parse_qsl(parsed.query, keep_blank_values=True):
                if key and key not in url_params:
                    url_params.append(key)

            for form in extract_forms(html):
                for field in form.get('inputs', []):
                    if field and field not in url_params:
                        url_params.append(field)

            if not url_params:
                continue

            for parameter in url_params[:MAX_XSS_PARAMS]:
                for payload in XSS_PAYLOADS[:2]:
                    test_url = build_test_url(url, parameter, payload)
                    if test_url in seen:
                        continue
                    seen.add(test_url)
                    try:
                        detection = safe_request(test_url, timeout=5)
                    except Exception:
                        continue
                    body = detection.text or ''
                    if payload in body and re.search(r'alert\s*\(|<script|onerror=|<svg', body, flags=re.I):
                        findings.append(
                            ensure_finding({
                                'title': 'Reflected XSS indicator detected',
                                'severity': 'high',
                                'url': test_url,
                                'parameter': parameter,
                                'description': 'A payload appears to be reflected in the response, which may indicate a reflected cross-site scripting issue.',
                                'evidence': f'Test payload {payload} was returned in the HTML response.',
                                'impact': 'A malicious actor may be able to execute JavaScript in a victim browser.',
                                'remediation': 'Encode user-controlled input, sanitize output, and enforce a strict Content-Security-Policy.'
                            })
                        )
                        return findings
        except Exception:
            continue
    return findings
