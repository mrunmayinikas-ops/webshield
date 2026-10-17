from __future__ import annotations

from typing import Any, Dict, List

from scanner.utils import ensure_finding, safe_request

SENSITIVE_PATHS = [
    '/admin',
    '/login',
    '/dashboard',
    '/backup',
    '/config',
    '/.env',
]


def has_sensitive_content(response: Any) -> bool:
    body = str(getattr(response, 'text', '') or '').lower()
    indicators = (
        'logout',
        'sign out',
        'my account',
        'user profile',
        'admin panel',
        'administrator panel',
    )
    return any(indicator in body for indicator in indicators)


def scan_sensitive_paths(target_url: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    if not target_url:
        return findings
    base = target_url.rstrip('/')
    for path in SENSITIVE_PATHS:
        url = base + path
        try:
            response = safe_request(url, timeout=8)
            if response.status_code in {200, 201, 203, 401, 403, 302, 301}:
                description = 'The application exposes or responds to a common sensitive endpoint that is often associated with administrative or configuration functionality.'
                severity = 'medium'
                title = f'Sensitive path accessible: {path}'
                evidence = f'HTTP status {response.status_code} indicates the path is reachable.'
                if path == '/dashboard' and response.status_code == 200:
                    title = 'Potentially sensitive endpoint discovered'
                    severity = 'high' if has_sensitive_content(response) else 'low'
                    description = 'A potentially sensitive endpoint was discovered, but the response did not provide clear evidence of sensitive content or functionality.'
                    evidence = 'HTTP 200 returned content indicating sensitive functionality may be accessible without authentication.' if severity == 'high' else 'HTTP 200 indicates the path is reachable; no clear sensitive content was detected in the response.'
                elif response.status_code == 200:
                    severity = 'high'
                findings.append(
                    ensure_finding({
                        'title': title,
                        'severity': severity,
                        'url': url,
                        'parameter': 'Path',
                        'description': description,
                        'evidence': evidence,
                        'impact': 'Accessible admin or configuration paths can provide entry points for unauthorized access or sensitive information exposure.',
                        'remediation': 'Restrict access, enforce authentication, and disable unnecessary sensitive endpoints in production.'
                    })
                )
        except Exception:
            continue
    return findings
