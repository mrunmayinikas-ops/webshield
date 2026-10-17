# WebShield – Web Vulnerability Scanner

WebShield is a Flask-based web vulnerability scanner built for cybersecurity education and portfolio demonstration. It performs real HTTP analysis, crawls a target site within the same domain, checks common security headers, and looks for basic XSS and SQL injection indicators without destructive payloads or unsafe behavior.

## Project overview

This project is designed to behave like a genuine, operational security tool rather than a static mockup. The scanning logic runs on the backend, stores scan results in SQLite, and presents them through a dark, cybersecurity-inspired dashboard.

## Features

- Target URL validation and safe request handling
- Same-domain website crawling with crawl limit controls
- Security header analysis for major HTTP protections
- Reflected XSS detection using safe payloads and parameter inspection
- Basic SQL injection detection using response-difference heuristics
- Sensitive path discovery for common admin and configuration endpoints
- Information disclosure checks for server and framework hints
- SQLite-backed historical scan storage
- Results pages and report generation
- Responsive dashboard UI with severity badges and charts

## Architecture

The project is organized as follows:

```text
webshield/
├── app.py
├── requirements.txt
├── scan_history.db
├── scanner/
│   ├── crawler.py
│   ├── headers.py
│   ├── xss_scanner.py
│   ├── sqli_scanner.py
│   ├── path_scanner.py
│   └── utils.py
├── templates/
│   ├── index.html
│   ├── scan.html
│   ├── results.html
│   ├── history.html
│   └── about.html
├── static/
│   ├── css/
│   │   └── style.css
│   └── js/
│       └── script.js
└── README.md
```

## Technologies used

- Python Flask
- SQLite
- Requests
- BeautifulSoup
- urllib.parse
- HTML, CSS, JavaScript

## Installation

From the project directory, install dependencies:

```bash
pip install -r requirements.txt
```

## How to run

```bash
python app.py
```

Then open:

```text
http://127.0.0.1:5000/
```

## How the scanner works

1. The user enters a URL and submits the scan.
2. The Flask backend validates the URL and normalizes it for safe crawling.
3. The crawler requests the site with a timeout and follows internal links while staying within the same domain.
4. Security checks evaluate HTTP headers such as CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy.
5. Reflected XSS detection tests query and form parameters using safe payloads and inspects whether the payload is echoed back in responses.
6. SQL injection detection checks parameter handling for suspicious response differences, status changes, or error signatures.
7. Sensitive path checks probe common administrative and configuration endpoints without exposing file contents.
8. Information disclosure analysis looks for server banners, framework hints, verbose headers, and debug-related metadata.
9. Results are summarized, stored in SQLite, and displayed in a results dashboard.

## Types of vulnerabilities detected

- Missing or weak security headers
- Reflected XSS indicators
- SQL injection testing signals
- Sensitive path exposure risks
- Information disclosure patterns

## Example scan workflow

1. Open the dashboard.
2. Paste a target URL you own or have permission to test.
3. Click Start Scan.
4. Wait for the backend to crawl and analyze the site.
5. Review the results and click the report button for a generated summary.
6. Visit the history page to open prior scans.

## Limitations

- This tool is intentionally designed for educational and authorized security testing.
- It performs passive and controlled probing and should not be used against websites without authorization.
- Some modern applications use protections such as WAFs, JavaScript-heavy routing, CSRF protections, or challenge pages that may reduce detection accuracy.
- It is not a replacement for a full enterprise vulnerability management platform.

## Ethical and legal usage

This project is for legitimate, authorized security testing only. You must have explicit permission to scan the target domain. Do not use this application against systems you do not own or are not authorized to test. The project is meant for learning, portfolio work, and responsible cybersecurity research.

## Notes

The application should be run locally and is intended for safe, permission-based testing in controlled environments.
