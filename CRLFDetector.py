import requests
import argparse
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import os

class CRLFDetector:
    def __init__(self, payload_file, timeout=10, user_agent=None, proxy=None):
        self.payloads = self.load_payloads(payload_file)
        self.timeout = timeout
        self.session = requests.Session()
        self.results = []
        self.tested_urls = set()

        self.session.headers.update({
            'User-Agent': user_agent or 'Mozilla/5.0 (X11; Linux x86_64)'
        })

        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}

    def load_payloads(self, payload_file):
        if not os.path.isfile(payload_file):
            raise FileNotFoundError(f"Payload file not found: {payload_file}")
        with open(payload_file, 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]

    def generate_test_urls(self, url, payload):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            return []

        test_urls = []
        for key in params:
            new_params = params.copy()
            new_params[key] = payload
            new_query = urlencode(new_params, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))
            test_urls.append(test_url)

        return test_urls

    def detect_crlf(self, url):
        print(f"\n[*] Testing: {url}")
        for payload in self.payloads:
            test_urls = self.generate_test_urls(url, payload)
            for test_url in test_urls:
                try:
                    response = self.session.get(test_url, timeout=self.timeout, allow_redirects=False)

                    # Check for header injection or malformed response headers
                    if any(suspicious in response.headers for suspicious in ["Injected-Header", payload.split(":")[0]]):
                        print(f"[!] Possible CRLF Injection at: {test_url}")
                        self.results.append((test_url, payload))
                    elif payload in response.text:
                        print(f"[?] Payload reflected in body (possible low-risk CRLF): {test_url}")
                except requests.RequestException as e:
                    print(f"[-] Error testing {test_url}: {e}")

    def scan(self, urls):
        for url in urls:
            if url not in self.tested_urls:
                self.tested_urls.add(url)
                self.detect_crlf(url)

    def save_results(self, output_file="crlf_results.txt"):
        if not self.results:
            print("No CRLF vulnerabilities detected.")
            return

        with open(output_file, "w") as f:
            for url, payload in self.results:
                f.write(f"Vulnerable URL: {url}\nPayload: {payload}\n{'-' * 40}\n")

        print(f"\n[+] Results saved to {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Advanced CRLF Injection Detector")
    parser.add_argument("-u", "--url", help="Single URL to test")
    parser.add_argument("-l", "--url-file", help="File containing list of URLs")
    parser.add_argument("-p", "--payloads", required=True, help="CRLF payload file")
    parser.add_argument("-o", "--output", default="crlf_results.txt", help="Output result file")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout")
    parser.add_argument("--user-agent", help="Custom User-Agent")
    parser.add_argument("--proxy", help="Proxy server (e.g., http://127.0.0.1:8080)")
    args = parser.parse_args()

    if not args.url and not args.url_file:
        parser.error("Provide either --url or --url-file")

    detector = CRLFDetector(
        payload_file=args.payloads,
        timeout=args.timeout,
        user_agent=args.user_agent,
        proxy=args.proxy
    )

    urls = []
    if args.url:
        urls.append(args.url.strip())
    if args.url_file:
        with open(args.url_file, 'r') as f:
            urls.extend([line.strip() for line in f if line.strip()])

    detector.scan(urls)
    detector.save_results(args.output)

if __name__ == "__main__":
    main()
