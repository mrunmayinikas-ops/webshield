from __future__ import annotations

from typing import Any, Dict, List

from scanner.utils import ensure_finding, safe_request


def analyze_headers(target_url: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    try:
        response = safe_request(target_url, timeout=5)
    except Exception:
        return findings

    header_checks = {
        'Content-Security-Policy': {
            'title': 'Content Security Policy is missing',
            'description': 'The site is not sending a Content-Security-Policy header, which leaves the browser with fewer restrictions against inline scripts and unsafe resource loading.',
            'impact': 'Increased risk of XSS and content injection attacks.',
            'remediation': 'Configure a restrictive CSP policy that allows only trusted scripts, styles, images, and connections.'
        },
        'Strict-Transport-Security': {
            'title': 'HTTP Strict Transport Security is missing',
            'description': 'HSTS ensures browsers only connect to the site over HTTPS and blocks downgrade attacks.',
            'impact': 'Users may be vulnerable to protocol downgrade and man-in-the-middle attacks.',
            'remediation': 'Set a long-lived HSTS header such as Strict-Transport-Security: max-age=31536000; includeSubDomains.'
        },
        'X-Frame-Options': {
            'title': 'Frame protection is missing',
            'description': 'The application does not prevent clickjacking via frame embedding.',
            'impact': 'Attackers may overlay deceptive content to trick users into interacting with authenticated pages.',
            'remediation': 'Add X-Frame-Options: DENY or SAMEORIGIN to block untrusted framing.'
        },
        'X-Content-Type-Options': {
            'title': 'MIME sniffing protection is missing',
            'description': 'Browsers may attempt to reinterpret content types and expose content unexpectedly.',
            'impact': 'This can enable script execution or content confusion attacks.',
            'remediation': 'Set X-Content-Type-Options: nosniff to prevent MIME sniffing.'
        },
        'Referrer-Policy': {
            'title': 'Referrer policy is not defined',
            'description': 'The application does not control how much referrer information is shared with other sites.',
            'impact': 'Excessive URL leakage can reveal sensitive information to third parties.',
            'remediation': 'Add a restrictive policy such as Referrer-Policy: no-referrer or strict-origin.'
        },
        'Permissions-Policy': {
            'title': 'Permissions Policy is missing',
            'description': 'Browser permissions are not constrained, which can expose camera, microphone, geolocation, and other APIs.',
            'impact': 'Abusive or malicious scripts may gain access to powerful browser capabilities.',
            'remediation': 'Configure a conservative Permissions-Policy to disable unnecessary features.'
        },
    }

    for header_name, config in header_checks.items():
        if header_name in response.headers:
            severity = 'informational'
            evidence = f'{header_name}: {response.headers.get(header_name)}'
        else:
            severity = 'high'
            evidence = f'{header_name} was not found in the response headers.'

        findings.append(
            ensure_finding({
                'title': config['title'],
                'severity': severity,
                'url': target_url,
                'parameter': header_name,
                'description': config['description'],
                'evidence': evidence,
                'impact': config['impact'],
                'remediation': config['remediation'],
            })
        )
    return findings


def inspect_information_disclosure(target_url: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    try:
        response = safe_request(target_url, timeout=5)
    except Exception:
        return findings

    server_header = response.headers.get('Server')
    if server_header:
        findings.append(
            ensure_finding({
                'title': 'Server information is disclosed',
                'severity': 'low',
                'url': target_url,
                'parameter': 'Server',
                'description': 'The web server identifies itself in the HTTP headers, which may reveal version information and platform details.',
                'evidence': f'Server: {server_header}',
                'impact': 'Attackers can tailor exploitation attempts to the specific software stack.',
                'remediation': 'Hide or minimize server banner details in production environments.'
            })
        )

    x_powered_by = response.headers.get('X-Powered-By')
    if x_powered_by:
        findings.append(
            ensure_finding({
                'title': 'Technology stack exposure',
                'severity': 'low',
                'url': target_url,
                'parameter': 'X-Powered-By',
                'description': 'Framework or application server details are exposed via response headers.',
                'evidence': f'X-Powered-By: {x_powered_by}',
                'impact': 'Version and framework disclosure can aid targeted exploitation.',
                'remediation': 'Remove or generalize technology headers in production responses.'
            })
        )

    if len(response.headers) > 20:
        findings.append(
            ensure_finding({
                'title': 'Excessive response headers',
                'severity': 'informational',
                'url': target_url,
                'parameter': 'Headers',
                'description': 'The response exposes an unusually large number of headers, which may signal verbose debugging or configuration leakage.',
                'evidence': f'{len(response.headers)} headers were returned.',
                'impact': 'Operational details may help an attacker understand the deployment and reduce reconnaissance cost.',
                'remediation': 'Restrict and trim non-essential headers in production.'
            })
        )

    return findings
