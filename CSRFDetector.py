import requests
from bs4 import BeautifulSoup
import argparse
from urllib.parse import urljoin, urlparse
import os

COMMON_CSRF_TOKEN_NAMES = {
    "csrf_token", "csrf", "__csrf", "_csrf", "__RequestVerificationToken",
    "authenticity_token", "token", "csrfmiddlewaretoken"
}

class CSRFDetector:
    def __init__(self, timeout=10, user_agent=None, proxy=None):
        self.session = requests.Session()
        self.timeout = timeout
        self.user_agent = user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        self.session.headers.update({'User-Agent': self.user_agent})
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}
        self.vulnerable_forms = []

    def load_urls(self, single_url=None, url_file=None):
        if single_url:
            return [single_url.strip()]
        elif url_file and os.path.isfile(url_file):
            with open(url_file, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        else:
            raise ValueError("Please provide either a --url or --url-file")

    def is_potentially_vulnerable_form(self, form):
        method = form.get("method", "get").lower()
        if method != "post":
            return False  # Only POST forms are relevant for CSRF

        inputs = form.find_all("input")
        for input_field in inputs:
            name = input_field.get("name", "").lower()
            if name in COMMON_CSRF_TOKEN_NAMES:
                return False  # Has a CSRF token

        return True  # POST form without known CSRF token

    def analyze_url(self, url):
        print(f"\n[*] Analyzing: {url}")
        try:
            res = self.session.get(url, timeout=self.timeout)
            soup = BeautifulSoup(res.text, "html.parser")
            forms = soup.find_all("form")

            for form in forms:
                if self.is_potentially_vulnerable_form(form):
                    action = form.get("action")
                    form_url = urljoin(url, action) if action else url
                    self.vulnerable_forms.append((url, form_url))
                    print(f"[!] CSRF Risk Form Found => {form_url}")

        except requests.RequestException as e:
            print(f"[-] Failed to fetch {url}: {e}")

    def scan(self, urls):
        for url in urls:
            self.analyze_url(url)

    def save_results(self, filename="csrf_results.txt"):
        if not self.vulnerable_forms:
            print("No vulnerable forms found.")
            return
        with open(filename, "w") as f:
            for page_url, form_url in self.vulnerable_forms:
                f.write(f"Page URL: {page_url}\nForm Action: {form_url}\n")
                f.write("-" * 40 + "\n")
        print(f"\n[+] Results saved to {filename}")

def main():
    parser = argparse.ArgumentParser(description="Simple CSRF Vulnerability Scanner")
    parser.add_argument("-u", "--url", help="Target URL")
    parser.add_argument("-l", "--url-file", help="File with list of URLs")
    parser.add_argument("-o", "--output", default="csrf_results.txt", help="Output file")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout in seconds")
    parser.add_argument("--user-agent", help="Custom User-Agent")
    parser.add_argument("--proxy", help="HTTP proxy (e.g., http://127.0.0.1:8080)")

    args = parser.parse_args()

    detector = CSRFDetector(timeout=args.timeout, user_agent=args.user_agent, proxy=args.proxy)
    urls = detector.load_urls(args.url, args.url_file)

    print(f"[*] Starting CSRF scan on {len(urls)} URLs...")
    detector.scan(urls)
    detector.save_results(args.output)

if __name__ == "__main__":
    main()
