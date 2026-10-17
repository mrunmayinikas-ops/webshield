from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import requests


HTTP_SESSION = requests.Session()


def validate_url(value: str) -> bool:
    if not value or not isinstance(value, str):
        return False
    parsed = urlparse(value)
    if parsed.scheme not in {'http', 'https'}:
        return False
    if not parsed.netloc:
        return False
    return True


def normalize_url(value: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        return cleaned
    if '://' not in cleaned:
        cleaned = f'https://{cleaned}'
    parsed = urlparse(cleaned)
    if not parsed.netloc:
        return cleaned
    if parsed.scheme not in {'http', 'https'}:
        return f'https://{parsed.netloc}{parsed.path or "/"}'
    return parsed._replace(path=parsed.path or '/').geturl()


def get_domain(url: str) -> str:
    parsed = urlparse(url)
    hostname = parsed.netloc.lower()
    return hostname


def same_domain(base_url: str, target_url: str) -> bool:
    try:
        return urlparse(base_url).netloc.lower() == urlparse(target_url).netloc.lower()
    except Exception:
        return False


def build_absolute_url(base_url: str, href: str) -> str:
    if not href:
        return ''
    return urljoin(base_url, href)


def response_snippet(text: str, max_len: int = 200) -> str:
    if not text:
        return 'No content returned.'
    cleaned = re.sub(r'\s+', ' ', text)
    return cleaned[:max_len].strip()


def safe_request(url: str, method: str = 'GET', **kwargs: Any) -> requests.Response:
    timeout = kwargs.pop('timeout', 10)
    headers = kwargs.pop('headers', {})
    default_headers = {'User-Agent': 'WebShieldBot/1.0'}
    default_headers.update(headers)
    kwargs['headers'] = default_headers
    kwargs['timeout'] = timeout
    if method.upper() == 'POST':
        return HTTP_SESSION.post(url, **kwargs)
    return HTTP_SESSION.get(url, **kwargs)


def extract_query_params(url: str) -> Dict[str, List[str]]:
    parsed = urlparse(url)
    params = {}
    for key, value in [pair.split('=', 1) if '=' in pair else (pair, '') for pair in parsed.query.split('&') if pair]:
        params.setdefault(key, []).append(value)
    return params


def extract_forms(html_text: str) -> List[Dict[str, Any]]:
    from bs4 import BeautifulSoup

    soup = BeautifulSoup(html_text, 'html.parser')
    forms: List[Dict[str, Any]] = []
    for form in soup.find_all('form'):
        method = (form.get('method') or 'GET').upper()
        action = form.get('action') or ''
        inputs = []
        for field in form.find_all(['input', 'textarea', 'select']):
            name = field.get('name')
            if name:
                inputs.append(name)
        forms.append({'action': action, 'method': method, 'inputs': inputs})
    return forms


def severity_rank(value: str) -> int:
    mapping = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'informational': 0}
    return mapping.get((value or 'informational').lower(), 0)


def ensure_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    finding.setdefault('severity', 'informational')
    finding.setdefault('title', 'Security finding')
    finding.setdefault('url', 'N/A')
    finding.setdefault('parameter', 'N/A')
    finding.setdefault('description', 'A potential security issue was identified.')
    finding.setdefault('evidence', 'No detailed evidence provided.')
    finding.setdefault('impact', 'Potential risk to confidentiality, integrity, or availability.')
    finding.setdefault('remediation', 'Review the application configuration and remediate the issue.')
    return finding
