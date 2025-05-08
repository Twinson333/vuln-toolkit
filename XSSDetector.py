import requests
import sys
import urllib.parse
from bs4 import BeautifulSoup
import argparse
from typing import List

def load_payloads(file_path: str) -> List[str]:
    with open(file_path, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def load_urls(input_url: str = None, url_file: str = None) -> List[str]:
    if input_url:
        return [input_url.strip()]
    elif url_file:
        with open(url_file, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    else:
        raise ValueError("Provide either --url or --url-file.")

def inject_payloads(url: str, payloads: List[str]):
    parsed = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed.query)

    if not query_params:
        print(f"[!] No query parameters found in URL: {url}")
        return

    print(f"\n[*] Testing URL: {url}")
    for payload in payloads:
        test_params = {k: payload for k in query_params}
        new_query = urllib.parse.urlencode(test_params, doseq=True)
        test_url = parsed._replace(query=new_query).geturl()

        try:
            res = requests.get(test_url, timeout=10)
            if payload in res.text:
                print(f"[+] Reflected XSS possible with payload: {payload}")
                print(f"    => {test_url}")
        except Exception as e:
            print(f"[!] Error with payload: {payload} => {e}")

def main():
    parser = argparse.ArgumentParser(description="Advanced XSS Detector")
    parser.add_argument("--url", help="Target URL with parameters (e.g. http://site.com/page?q=test)")
    parser.add_argument("--url-file", help="File containing list of URLs")
    parser.add_argument("--payloads", required=True, help="File containing XSS payloads")
    args = parser.parse_args()

    payloads = load_payloads(args.payloads)
    urls = load_urls(args.url, args.url_file)

    for url in urls:
        inject_payloads(url, payloads)

if __name__ == "__main__":
    main()
