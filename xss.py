import os
import requests
import time
import base64
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor

# Rate-limiting configuration
RATE_LIMIT = 0.5  # 2 requests per second


def load_payloads():
    """Prompt the user for the payload file and load the payloads."""
    while True:
        payload_file = input("Enter the path to the payload file: ").strip()
        if os.path.exists(payload_file) and os.path.isfile(payload_file):
            with open(payload_file, "r") as file:
                return [line.strip() for line in file.readlines() if line.strip()]
        else:
            print("Invalid file path. Please try again.")


# Load payloads at runtime
PAYLOADS = load_payloads()


def send_request(method, url, params=None, headers=None, data=None, cookies=None):
    """Send an HTTP request with the specified method."""
    try:
        response = requests.request(
            method,
            url,
            params=params,
            headers=headers,
            data=data,
            cookies=cookies,
            timeout=10,
        )
        return response
    except requests.exceptions.RequestException as e:
        print(f"Error with {method} request: {e}")
        return None


def test_xss(method, url, payload, params=None, headers=None, body=None, cookies=None):
    """Test the URL for XSS vulnerabilities with various HTTP methods."""
    vulnerable = False
    print(f"Testing with payload: {payload} on {url} using {method}")

    # Modify parameters, headers, and body to include the payload
    if params:
        params = {k: payload if k in params else v for k, v in params.items()}
    if headers:
        headers = {k: payload if payload in v else v for k, v in headers.items()}
    if body:
        body = {k: payload if k in body else v for k, v in body.items()}
    if cookies:
        cookies = {k: payload if k in cookies else v for k, v in cookies.items()}

    response = send_request(method, url, params=params, headers=headers, data=body, cookies=cookies)

    if response:
        if response.status_code in [403, 406]:
            print(f"[!] Request blocked by firewall: {url} with payload {payload}")
            with open("blocked_requests.txt", "a") as file:
                file.write(f"Blocked | {method} | {url} | {payload}\n")
        elif payload in response.text:
            print(f"[+] XSS Found: {url} with payload {payload}")
            vulnerable = True
            with open("xss_results.txt", "a") as file:
                file.write(f"XSS | {method} | {url} | {payload}\n")

    # Test with Base64 encoded payload
    encoded_payload = base64.b64encode(payload.encode()).decode()
    response = send_request(method, url, params=params, headers=headers, data=body, cookies=cookies)

    if response:
        if response.status_code in [403, 406]:
            print(f"[!] Request blocked by firewall (Base64): {url} with payload {encoded_payload}")
            with open("blocked_requests.txt", "a") as file:
                file.write(f"Blocked | {method} | {url} | {encoded_payload}\n")
        elif encoded_payload in response.text:
            print(f"[+] XSS Found (Base64): {url} with payload {encoded_payload}")
            vulnerable = True
            with open("xss_results.txt", "a") as file:
                file.write(f"XSS (Base64) | {method} | {url} | {encoded_payload}\n")

    if vulnerable:
        print(f"Vulnerability detected on {url} with payload: {payload}")
    time.sleep(RATE_LIMIT)


def test_dom_xss(url):
    """Check for DOM-based XSS vulnerabilities."""
    try:
        response = send_request("GET", url)
        if response:
            soup = BeautifulSoup(response.text, "html.parser")
            scripts = soup.find_all("script")
            for script in scripts:
                if "document.write" in script.text or "innerHTML" in script.text:
                    print(f"[!] Potential DOM-Based XSS Found on {url}")
                    with open("xss_results.txt", "a") as file:
                        file.write(f"DOM XSS | {url}\n")
    except Exception as e:
        print(f"Error testing DOM XSS: {e}")


def detect_parameters(url):
    """Extract parameters from the URL."""
    parsed_url = urlparse(url)
    params = parse_qs(parsed_url.query)
    return {key: value[0] if value else "" for key, value in params.items()}


def detect_headers_and_body():
    """Prompt the user for headers and body to include in requests."""
    headers = {}
    body = {}

    add_headers = input("Do you want to add custom headers? (y/n): ").strip().lower() == "y"
    if add_headers:
        while True:
            header = input("Enter header in 'Key:Value' format (or press Enter to finish): ").strip()
            if not header:
                break
            key, value = header.split(":", 1)
            headers[key.strip()] = value.strip()

    add_body = input("Do you want to add a request body? (y/n): ").strip().lower() == "y"
    if add_body:
        while True:
            param = input("Enter body parameter in 'Key=Value' format (or press Enter to finish): ").strip()
            if not param:
                break
            key, value = param.split("=", 1)
            body[key.strip()] = value.strip()

    return headers, body


def scan_url(url):
    """Scan a single URL for vulnerabilities."""
    params = detect_parameters(url)
    headers, body = detect_headers_and_body()
    methods = ["GET", "POST", "PATCH", "PUT", "DELETE"]

    for payload in PAYLOADS:
        for method in methods:
            test_xss(method, url, payload, params=params, headers=headers, body=body)
    test_dom_xss(url)


def main():
    urls = input("Enter the URL(s) (comma-separated or file path): ").strip()
    if "," in urls:
        urls = [url.strip() for url in urls.split(",")]
    elif urls.endswith(".txt"):
        with open(urls, "r") as file:
            urls = [line.strip() for line in file.readlines() if line.strip()]
    else:
        urls = [urls]

    print(f"Loaded {len(urls)} URL(s) for testing.")

    with ThreadPoolExecutor(max_workers=5) as executor:
        for url in urls:
            executor.submit(scan_url, url)


if __name__ == "__main__":
    main()
