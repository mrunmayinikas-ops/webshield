from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Any, Callable, Dict, List

from flask import Flask, jsonify, render_template, request

from scanner.api_scanner import scan_api_endpoints
from scanner.crawler import crawl_website
from scanner.headers import analyze_headers, inspect_information_disclosure
from scanner.path_scanner import scan_sensitive_paths
from scanner.sqli_scanner import scan_sql_injection
from scanner.utils import normalize_url, validate_url
from scanner.xss_scanner import scan_xss

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'scan_history.db')
ACTIVE_SCANS: Dict[str, Dict[str, Any]] = {}

app = Flask(__name__, template_folder='templates', static_folder='static')


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = get_db_connection()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_url TEXT NOT NULL,
            scanned_at TEXT NOT NULL,
            total_urls INTEGER NOT NULL,
            vulnerability_count INTEGER NOT NULL,
            critical INTEGER NOT NULL DEFAULT 0,
            high INTEGER NOT NULL DEFAULT 0,
            medium INTEGER NOT NULL DEFAULT 0,
            low INTEGER NOT NULL DEFAULT 0,
            informational INTEGER NOT NULL DEFAULT 0,
            results_json TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


def severity_counts(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'informational': 0}
    for item in findings:
        sev = (item.get('severity') or 'informational').lower()
        if sev == 'info':
            sev = 'informational'
        if sev in counts:
            counts[sev] += 1
    return counts


def compile_scan_result(target_url: str, urls: List[str], findings: List[Dict[str, Any]], crawl_data: Dict[str, Any] | None = None) -> Dict[str, Any]:
    counts = severity_counts(findings)
    total_findings = sum(counts.values())
    summary = {
        'target_url': target_url,
        'scanned_at': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
        'total_urls': len(urls),
        'vulnerability_count': total_findings,
        'critical': counts['critical'],
        'high': counts['high'],
        'medium': counts['medium'],
        'low': counts['low'],
        'informational': counts['informational'],
        'findings': findings,
        'pages_discovered': (crawl_data or {}).get('pages_discovered', len(urls)),
        'pages_crawled': (crawl_data or {}).get('pages_crawled', len(urls)),
        'max_pages': (crawl_data or {}).get('max_pages', 100),
        'pages_remaining': (crawl_data or {}).get('pages_remaining', 0),
        'crawl_limit_reached': (crawl_data or {}).get('crawl_limit_reached', False),
        'pages': (crawl_data or {}).get('pages', []),
        'api_endpoints': (crawl_data or {}).get('api_endpoints', []),
        'apis_discovered': len((crawl_data or {}).get('api_endpoints', [])),
        'apis_scanned': len((crawl_data or {}).get('api_endpoints', [])),
    }
    return summary


def store_scan(summary: Dict[str, Any]) -> int:
    conn = get_db_connection()
    cursor = conn.execute(
        """
        INSERT INTO scans (
            target_url, scanned_at, total_urls, vulnerability_count,
            critical, high, medium, low, informational, results_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            summary['target_url'],
            summary['scanned_at'],
            summary['total_urls'],
            summary['vulnerability_count'],
            summary['critical'],
            summary['high'],
            summary['medium'],
            summary['low'],
            summary['informational'],
            json.dumps(summary, indent=2),
        ),
    )
    conn.commit()
    scan_id = cursor.lastrowid
    conn.close()
    return scan_id


def set_scan_status(job_id: str, message: str, progress: int, status: str = 'running', **kwargs: Any) -> None:
    ACTIVE_SCANS.setdefault(job_id, {'status': 'queued', 'message': '🐾 Cat is waking up...', 'progress': 0, 'done': False})
    ACTIVE_SCANS[job_id].update({'message': message, 'progress': max(0, min(100, progress)), 'status': status, 'done': status in {'completed', 'error'}, **kwargs})


def scan_page_headers(page_url: str) -> List[Dict[str, Any]]:
    return analyze_headers(page_url) + inspect_information_disclosure(page_url)


def run_scan_job(job_id: str, target_url: str) -> None:
    normalized_url = normalize_url(target_url)
    try:
        set_scan_status(job_id, '🐾 Cat is waking up...', 5)
        def update_crawl_progress(current: int, total: int, message: str, metrics: Dict[str, Any] | None = None) -> None:
            set_scan_status(
                job_id,
                message,
                int((current / total) * 45) if total else 0,
                pages_discovered=(metrics or {}).get('pages_discovered', current),
                pages_crawled=(metrics or {}).get('pages_crawled', current),
                pages_remaining=max(0, (metrics or {}).get('pages_discovered', current) - (metrics or {}).get('pages_crawled', current)),
                max_pages=total,
            )

        crawl_data = crawl_website(normalized_url, max_pages=100, progress_callback=update_crawl_progress)
        visited_urls = crawl_data['visited_urls']
        discovered_urls = crawl_data['discovered_urls']

        findings: List[Dict[str, Any]] = []
        total_pages = max(1, len(visited_urls))
        set_scan_status(job_id, f'Checking headers on {total_pages} pages...', 48, pages_discovered=crawl_data['pages_discovered'], pages_crawled=total_pages, pages_remaining=crawl_data['pages_remaining'], max_pages=crawl_data['max_pages'], apis_discovered=len(crawl_data['api_endpoints']))
        with ThreadPoolExecutor(max_workers=8) as executor:
            for page_findings in executor.map(scan_page_headers, visited_urls):
                findings.extend(page_findings)

        set_scan_status(job_id, f"Checking {len(crawl_data['api_endpoints'])} APIs...", 68, pages_discovered=crawl_data['pages_discovered'], pages_crawled=crawl_data['pages_crawled'], pages_remaining=crawl_data['pages_remaining'], max_pages=crawl_data['max_pages'], crawl_limit_reached=crawl_data['crawl_limit_reached'], apis_discovered=len(crawl_data['api_endpoints']))
        findings.extend(scan_sensitive_paths(normalized_url))
        findings.extend(scan_api_endpoints(crawl_data['api_endpoints']))

        set_scan_status(job_id, f'Checking XSS on {len(visited_urls)} pages...', 78)
        findings.extend(scan_xss(normalized_url, visited_urls))

        set_scan_status(job_id, f'Checking SQL injection on {len(visited_urls)} pages...', 88)
        findings.extend(scan_sql_injection(normalized_url, visited_urls))

        set_scan_status(job_id, '🐾 Almost done...', 92)
        summary = compile_scan_result(normalized_url, visited_urls, findings, crawl_data)
        scan_id = store_scan(summary)
        set_scan_status(job_id, '🐾 Scan complete', 100, 'completed', scan_id=scan_id, results=summary)
    except ValueError as exc:
        set_scan_status(job_id, f'⚠ Validation issue: {str(exc)}', 100, 'error', error=str(exc))
    except Exception as exc:  # pragma: no cover - defensive guard
        app.logger.exception('Scan failed: %s', exc)
        set_scan_status(job_id, '⚠ The scan hit an unexpected error.', 100, 'error', error='The scan encountered an unexpected error. Please try again later.')


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/scan')
def scan_page():
    return render_template('scan.html')


@app.route('/history')
def history_page():
    return render_template('history.html')


@app.route('/about')
def about_page():
    return render_template('about.html')


@app.route('/results/<int:scan_id>')
def results_page(scan_id: int):
    conn = get_db_connection()
    row = conn.execute('SELECT * FROM scans WHERE id = ?', (scan_id,)).fetchone()
    conn.close()
    if row is None:
        return render_template('results.html', scan=None)
    result_data = json.loads(row['results_json'])
    return render_template('results.html', scan=result_data, scan_id=scan_id)


@app.route('/results/<int:scan_id>/report')
def generate_report(scan_id: int):
    conn = get_db_connection()
    row = conn.execute('SELECT * FROM scans WHERE id = ?', (scan_id,)).fetchone()
    conn.close()
    if row is None:
        return jsonify({'error': 'Scan not found.'}), 404

    data = json.loads(row['results_json'])
    findings = data.get('findings', [])
    severity_summary = {
        'Critical': data.get('critical', 0),
        'High': data.get('high', 0),
        'Medium': data.get('medium', 0),
        'Low': data.get('low', 0),
        'Informational': data.get('informational', 0),
    }
    color_map = {
        'Critical': '#7f1d1d',
        'High': '#7c2d12',
        'Medium': '#854d0e',
        'Low': '#1d4ed8',
        'Informational': '#374151',
    }
    severity_tags = ''.join(
        f'<span class="pill" style="background:{color_map.get(label, "#374151")};">{label}: {count}</span>'
        for label, count in severity_summary.items()
    )
    vulnerability_rows = ''.join(
        f'<tr><td>{item.get("title", "Finding")}</td><td>{item.get("severity", "Informational")}</td><td>{item.get("url", "N/A")}</td><td>{item.get("parameter", "N/A")}</td><td>{item.get("evidence", "N/A")}</td><td>{item.get("remediation", "N/A")}</td></tr>'
        for item in findings
    )
    html = f"""
    <!doctype html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>WebShield Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 32px; color: #0e172a; background: #f5f7fb; }}
            h1, h2 {{ color: #081426; }}
            .card {{ background: white; padding: 18px 20px; border-radius: 12px; margin-bottom: 20px; box-shadow: 0 8px 20px rgba(0,0,0,0.04); }}
            .pill {{ display: inline-block; padding: 5px 10px; border-radius: 999px; font-size: 12px; font-weight: bold; color: white; margin-right: 8px; }}
            table {{ width: 100%; border-collapse: collapse; }}
            th, td {{ border-bottom: 1px solid #dfe8f5; padding: 10px; text-align: left; }}
            th {{ background: #eef5ff; }}
        </style>
    </head>
    <body>
        <h1>WebShield Scan Report</h1>
        <div class="card">
            <p><strong>Target:</strong> {data['target_url']}</p>
            <p><strong>Scan date:</strong> {data['scanned_at']}</p>
            <p><strong>Executive summary:</strong> {data['vulnerability_count']} vulnerabilities identified across {data['total_urls']} URLs.</p>
        </div>
        <div class="card">
            <h2>Severity breakdown</h2>
            {severity_tags}
        </div>
        <div class="card">
            <h2>Detailed vulnerabilities</h2>
            <table>
                <thead>
                    <tr><th>Title</th><th>Severity</th><th>URL</th><th>Parameter</th><th>Evidence</th><th>Recommendation</th></tr>
                </thead>
                <tbody>
                    {vulnerability_rows}
                </tbody>
            </table>
        </div>
    </body>
    </html>
    """
    return html


@app.route('/api/history')
def history_api():
    conn = get_db_connection()
    rows = conn.execute(
        'SELECT id, target_url, scanned_at, total_urls, vulnerability_count, critical, high, medium, low, informational FROM scans ORDER BY id DESC'
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route('/api/results/<int:scan_id>')
def results_api(scan_id: int):
    conn = get_db_connection()
    row = conn.execute('SELECT * FROM scans WHERE id = ?', (scan_id,)).fetchone()
    conn.close()
    if row is None:
        return jsonify({'error': 'Scan not found.'}), 404
    return jsonify(json.loads(row['results_json']))


@app.route('/api/scan', methods=['POST'])
def run_scan():
    payload = request.get_json(silent=True) or request.form.to_dict()
    target_url = (payload.get('target_url') or '').strip()
    if not target_url:
        return jsonify({'error': 'Please provide a target URL.'}), 400

    normalized_url = normalize_url(target_url)
    if not validate_url(normalized_url):
        return jsonify({'error': 'Please enter a valid http or https URL.'}), 400

    job_id = str(uuid.uuid4())
    ACTIVE_SCANS[job_id] = {'status': 'queued', 'message': '🐾 Cat is waking up...', 'progress': 0, 'done': False}
    threading.Thread(target=run_scan_job, args=(job_id, normalized_url), daemon=True).start()
    return jsonify({'success': True, 'job_id': job_id, 'status': ACTIVE_SCANS[job_id]})


@app.route('/api/scan/status/<job_id>')
def scan_status(job_id: str):
    status = ACTIVE_SCANS.get(job_id)
    if not status:
        return jsonify({'status': 'not_found', 'message': 'No active scan found.', 'progress': 0}), 404
    return jsonify(status)


init_db()


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
