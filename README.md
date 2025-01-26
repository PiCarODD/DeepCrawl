# Web Application Crawler

A Python-based tool for discovering endpoints and functions in web applications, with real-time progress reporting and security-focused classification.

## Features

- Real-time crawling progress display
- Distinguishes between HTML pages and backend endpoints
- JavaScript function discovery
- Depth-controlled crawling
- JSON report generation
- Color-coded terminal output

## Installation

1. **Requirements**:
   - Python 3.6+
   - Chrome browser (for JavaScript rendering)

2. **Install dependencies**:
```bash
pip install requests beautifulsoup4
```

## Usage

### Basic Scan
```bash
python web_crawler.py -u http://example.com
```

### Scan with Custom Depth
```bash
python web_crawler.py -u http://example.com -d 2
```

### Command Line Options
| Option | Description                          | Default |
|--------|--------------------------------------|---------|
| `-u`   | Target URL (required)                | -       |
| `-d`   | Maximum crawl depth                  | 3       |

## Output

1. **Terminal Display**:
   - Real-time progress indicator
   - Immediate discovery alerts
   - Final summary statistics

2. **JSON Report**:
   - `[domain]_security_scan.json` file containing:
     - All discovered HTML pages
     - Backend endpoints (APIs, services)
     - JavaScript functions
     - Summary statistics

## Example Report
```json
{
  "html_pages": [
    "http://testasp.vulnweb.com/",
    "http://testasp.vulnweb.com/Login.asp"
  ],
  "backend_endpoints": [
    "http://testasp.vulnweb.com/api/checkuser",
    "http://testasp.vulnweb.com/search.php"
  ],
  "functions": ["validateForm", "initCart"],
  "stats": {
    "total_html": 5,
    "total_backend": 3,
    "total_functions": 12
  }
}
```

## Limitations

- Does not handle authentication-protected pages
- Limited JavaScript execution analysis
- May miss some dynamically loaded content
