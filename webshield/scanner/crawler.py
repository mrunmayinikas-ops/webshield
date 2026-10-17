from __future__ import annotations

import logging
from collections import deque
from typing import Any, Callable, Deque, Dict, List, Set
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from xml.etree import ElementTree

from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
from playwright.sync_api import sync_playwright

from scanner.utils import build_absolute_url, same_domain

logger = logging.getLogger(__name__)


MAX_PAGES = 100
PAGE_TIMEOUT_MS = 15_000
SKIPPED_PATH_PARTS = ('/logout', '/signout', '/delete', '/remove')
SKIPPED_EXTENSIONS = ('.pdf', '.zip', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.css', '.js', '.ico', '.woff', '.woff2')


def normalize_crawl_url(url: str) -> str:
    parsed = urlsplit(url)
    query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)))
    path = parsed.path or '/'
    if path != '/':
        path = path.rstrip('/')
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), path, query, ''))


def is_crawlable_link(url: str, target_url: str) -> bool:
    path = urlsplit(url).path.lower()
    return (
        same_domain(target_url, url)
        and not any(part in path for part in SKIPPED_PATH_PARTS)
        and not path.endswith(SKIPPED_EXTENSIONS)
    )


def discover_sitemap_urls(page: Any, target_url: str) -> Set[str]:
    sitemap_urls: Set[str] = set()
    origin = urlunsplit((urlsplit(target_url).scheme, urlsplit(target_url).netloc, '', '', ''))
    for sitemap_url in (f'{origin}/sitemap.xml', f'{origin}/sitemap_index.xml'):
        try:
            response = page.request.get(sitemap_url, timeout=PAGE_TIMEOUT_MS)
            if not response.ok:
                continue
            root = ElementTree.fromstring(response.body())
            for element in root.iter():
                if element.tag.rsplit('}', 1)[-1] != 'loc' or not element.text:
                    continue
                candidate = normalize_crawl_url(element.text.strip())
                if is_crawlable_link(candidate, target_url):
                    sitemap_urls.add(candidate)
        except Exception:
            continue
    return sitemap_urls


def crawl_website(target_url: str, max_pages: int = MAX_PAGES, progress_callback: Callable[..., None] | None = None) -> Dict[str, Any]:
    if not target_url:
        raise ValueError('A valid target URL is required.')

    max_pages = max(1, min(int(max_pages), MAX_PAGES))
    target_url = normalize_crawl_url(target_url)
    queue: Deque[str] = deque([target_url])
    visited: Set[str] = set()
    discovered: Set[str] = {target_url}
    pages: List[Dict[str, Any]] = []
    api_endpoints: Dict[str, Dict[str, Any]] = {}

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()
        current_page_url = target_url

        def record_response(response: Any) -> None:
            request = response.request
            content_type = response.headers.get('content-type', '')
            status_code = response.status
            is_api = request.resource_type in {'fetch', 'xhr'} or '/api/' in request.url.lower() or 'json' in content_type.lower()
            if not is_api or not same_domain(target_url, request.url):
                return
            endpoint = normalize_crawl_url(request.url)
            api_endpoints.setdefault(endpoint, {
                'url': endpoint,
                'method': request.method,
                'status_code': status_code,
                'content_type': content_type,
                'source_url': current_page_url,
            })

        page.on('response', record_response)
        try:
            for sitemap_url in discover_sitemap_urls(page, target_url):
                discovered.add(sitemap_url)
                if sitemap_url not in queue:
                    queue.append(sitemap_url)
            while queue and len(visited) < max_pages:
                current_url = queue.popleft()
                if current_url in visited:
                    continue
                visited.add(current_url)
                current_page_url = current_url
                if progress_callback:
                    progress_callback(
                        len(visited),
                        max_pages,
                        f'Crawling: {len(visited)}/{max_pages} pages',
                        {'pages_discovered': len(discovered), 'pages_crawled': len(pages)},
                    )

                page_data: Dict[str, Any] = {'url': current_url, 'title': '', 'status_code': None, 'links': []}
                try:
                    response = page.goto(current_url, wait_until='domcontentloaded', timeout=PAGE_TIMEOUT_MS)
                    page_data['status_code'] = response.status if response else None
                    page_data['title'] = page.title()
                    raw_links = page.locator('a[href]').evaluate_all('(links) => links.map(link => link.href)')
                    links = []
                    for link in raw_links:
                        normalized = normalize_crawl_url(build_absolute_url(current_url, link))
                        if normalized and is_crawlable_link(normalized, target_url):
                            links.append(normalized)
                            discovered.add(normalized)
                            if normalized not in visited and normalized not in queue:
                                queue.append(normalized)
                    page_data['links'] = sorted(set(links))
                    if progress_callback:
                        progress_callback(
                            len(visited),
                            max_pages,
                            f'Crawling: {len(visited)}/{max_pages} pages',
                            {'pages_discovered': len(discovered), 'pages_crawled': len(pages) + 1},
                        )
                except PlaywrightTimeoutError:
                    logger.warning('Timed out while crawling %s', current_url)
                except Exception as exc:  # pragma: no cover - defensive page isolation
                    logger.warning('Failed to crawl %s: %s', current_url, exc)
                pages.append(page_data)
        finally:
            context.close()
            browser.close()

    if progress_callback:
        progress_callback(len(pages), max_pages, f'Crawl complete: {len(pages)}/{max_pages} pages')
    return {
        'pages': pages,
        'visited_urls': sorted(visited),
        'discovered_urls': sorted(discovered),
        'api_endpoints': sorted(api_endpoints.values(), key=lambda item: item['url']),
        'pages_discovered': len(discovered),
        'pages_crawled': len(pages),
        'max_pages': max_pages,
        'crawl_limit_reached': len(pages) >= max_pages and bool(queue),
        'pages_remaining': max(0, len(discovered) - len(pages)),
    }
