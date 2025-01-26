#!/usr/bin/env python3
"""
Web Application Security Crawler

"""

import argparse
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re
import json
import time
import sys
import threading
from collections import deque
from threading import Thread, Event

class LiveCrawler:
    def __init__(self, base_url, max_depth=3):
        self.base_url = base_url
        self.domain = urlparse(base_url).netloc
        self.max_depth = max_depth
        self.visited_urls = set()
        self.queue = deque([(base_url, 0)])
        self.found = {
            'html_pages': set(),
            'backend_endpoints': set(),
            'functions': set()
        }
        self.stop_event = Event()
        self.lock = threading.Lock()
        self.progress = {
            'crawled': 0,
            'queued': 1,
            'depth': 0
        }

    def is_valid_url(self, url):
        """Validate URL belongs to target domain"""
        parsed = urlparse(url)
        return parsed.netloc == self.domain and parsed.scheme in ('http', 'https')

    def classify_endpoint(self, url):
        """Categorize URL as HTML page or backend endpoint"""
        backend_patterns = [
            r'\.(json|xml|ashx|asmx|php|jsp|do|action|api|rest)\b',
            r'/api/',
            r'/ws/',
            r'/rest/',
            r'\?(action|method|api_key)=',
            r'\.cgi\b'
        ]
        
        page_patterns = [
            r'\.(html|htm|asp|aspx|cfm)\b',
            r'/[^/.]+$'  # Extensionless paths
        ]

        if any(re.search(p, url, re.I) for p in backend_patterns):
            return 'backend'
        if any(re.search(p, url, re.I) for p in page_patterns):
            return 'html'
        return 'unknown'

    def find_links(self, soup, base_url):
        """Extract all links from page elements"""
        links = set()
        for element in soup.find_all(['a', 'form', 'frame', 'iframe', 'script', 'link']):
            attr = 'href' if element.name in ('a', 'link') else \
                   'src' if element.name in ('script', 'frame', 'iframe') else \
                   'action' if element.name == 'form' else None
            if attr:
                url = urljoin(base_url, element.get(attr, ''))
                if self.is_valid_url(url):
                    links.add(url)
        return links

    def process_endpoint(self, url):
        """Add endpoint to appropriate category"""
        with self.lock:
            classification = self.classify_endpoint(url)
            clean_url = url.split('?')[0].split('#')[0]
            
            if classification == 'html' and clean_url not in self.found['html_pages']:
                self.found['html_pages'].add(clean_url)
                self.print_finding('html', clean_url)
            elif classification == 'backend' and clean_url not in self.found['backend_endpoints']:
                self.found['backend_endpoints'].add(clean_url)
                self.print_finding('backend', clean_url)

    def analyze_js(self, url):
        """Analyze JavaScript files for API calls and functions"""
        try:
            response = requests.get(url, timeout=5)
            content = response.text
            
            # Find API calls
            api_calls = re.findall(
                r'(?:fetch|axios|\.ajax|XMLHttpRequest)\([\'"]([^\'"]+)',
                content,
                re.IGNORECASE
            )
            
            for ep in api_calls:
                full_url = urljoin(url, ep)
                if self.is_valid_url(full_url):
                    self.process_endpoint(full_url)
            
            # Extract function names
            functions = re.findall(
                r'\b(function|const|let|var)\s+([a-zA-Z_$][\w$]+)\b',
                content
            )
            return {fn[1] for fn in functions}
        except:
            return set()

    def display_progress(self):
        """Show animated progress indicator"""
        chars = ['⣾', '⣽', '⣻', '⢿', '⡿', '⣟', '⣯', '⣷']
        i = 0
        while not self.stop_event.is_set():
            with self.lock:
                sys.stdout.write(f"\r{chars[i]} Crawled: {self.progress['crawled']} | Queued: {self.progress['queued']} | Depth: {self.progress['depth']} | HTML: {len(self.found['html_pages'])} | Backend: {len(self.found['backend_endpoints'])} | Functions: {len(self.found['functions'])}")
                sys.stdout.flush()
            i = (i + 1) % len(chars)
            time.sleep(0.1)

    def print_finding(self, type, value):
        """Color-coded terminal output"""
        colors = {
            'html': '\033[94m',
            'backend': '\033[92m',
            'function': '\033[93m',
            'reset': '\033[0m'
        }
        print(f"\n{colors[type]}• {type.capitalize()} found: {value}{colors['reset']}")

    def crawl(self):
        """Main crawling process"""
        progress_thread = Thread(target=self.display_progress)
        progress_thread.start()

        try:
            while self.queue and not self.stop_event.is_set():
                url, depth = self.queue.popleft()
                
                with self.lock:
                    if url in self.visited_urls or depth > self.max_depth:
                        continue
                    self.visited_urls.add(url)
                    self.progress['depth'] = depth
                    self.progress['crawled'] += 1
                    self.progress['queued'] = len(self.queue)

                try:
                    response = requests.get(url, timeout=10)
                    self.process_endpoint(url)
                    
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Process discovered links
                    for link in self.find_links(soup, url):
                        self.process_endpoint(link)
                        if link not in self.visited_urls:
                            with self.lock:
                                self.queue.append((link, depth + 1))
                                self.progress['queued'] = len(self.queue)

                    # Analyze JavaScript files
                    for script in soup.find_all('script'):
                        if script.src:
                            js_url = urljoin(url, script.src)
                            functions = self.analyze_js(js_url)
                            with self.lock:
                                self.found['functions'].update(functions)
                                for fn in functions:
                                    self.print_finding('function', fn)

                    time.sleep(0.5)

                except Exception as e:
                    continue

        finally:
            self.stop_event.set()
            progress_thread.join()
            print("\n\nScan complete! Final results:")

    def generate_report(self):
        """Generate structured report"""
        return {
            'target': self.base_url,
            'html_pages': sorted(self.found['html_pages']),
            'backend_endpoints': sorted(self.found['backend_endpoints']),
            'functions': sorted(self.found['functions']),
            'stats': {
                'total_html': len(self.found['html_pages']),
                'total_backend': len(self.found['backend_endpoints']),
                'total_functions': len(self.found['functions']),
                'max_depth': self.max_depth
            }
        }

def main():
    """Command-line interface"""
    parser = argparse.ArgumentParser(
        description='Discover web application endpoints and functions',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('-u', '--url', required=True,
                      help='Target URL to scan (e.g., http://example.com)')
    parser.add_argument('-d', '--depth', type=int, default=3,
                      help='Maximum crawl depth (0 for unlimited)')
    args = parser.parse_args()

    # Validate and normalize URL
    target_url = args.url.strip()
    if not urlparse(target_url).scheme:
        target_url = f'http://{target_url}'

    crawler = LiveCrawler(target_url, max_depth=args.depth)
    
    print(f"\nStarting security scan for: {target_url}")
    print(f"Maximum crawl depth: {args.depth if args.depth > 0 else 'unlimited'}")
    print("Press Ctrl+C to stop early...\n")
    
    try:
        crawler.crawl()
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user!")

    # Generate report
    report = crawler.generate_report()
    domain = urlparse(target_url).netloc.replace(':', '_')
    filename = f"{domain}_security_scan.json"
    with open(filename, "w") as f:
        json.dump(report, f, indent=2)
    
    # Print summary
    print("\nScan Summary:")
    print(f"- HTML Pages: {report['stats']['total_html']}")
    print(f"- Backend Endpoints: {report['stats']['total_backend']}")
    print(f"- JavaScript Functions: {report['stats']['total_functions']}")
    print(f"- Report saved to: {filename}")

if __name__ == "__main__":
    main()
