import concurrent.futures
import requests
import time
from urllib.parse import urlparse, parse_qs, urlencode
from termcolor import colored

# Rate-limiting configuration (adjusted for higher speed)
RATE_LIMIT = 0.1  # Delay between requests (in seconds)

# Load payloads
def load_payloads():
    payload_file = input("Enter the payload file path: ").strip()
    with open(payload_file, "r") as file:
        return [line.strip() for line in file if line.strip()]

PAYLOADS = load_payloads()

def detect_methods(url):
    """Detect allowed HTTP methods using an OPTIONS request."""
    try:
        response = requests.options(url, timeout=10)
        if response.status_code == 200 and "Allow" in response.headers:
            return response.headers["Allow"].split(", ")
    except Exception as e:
        print(f"[!] Error detecting methods: {e}")
    # Default methods if OPTIONS fails
    return ["GET", "POST"]

def test_payloads(url, methods, parameters):
    """Inject payloads into each parameter and test with all methods."""
    for method in methods:
        for param in parameters:
            for payload in PAYLOADS:
                # Inject payload into the current parameter
                modified_params = parameters.copy()
                modified_params[param] = payload
                query_string = urlencode(modified_params)

                # Construct the test URL
                test_url = f"{url.scheme}://{url.netloc}{url.path}?{query_string}"

                print(f"Testing with payload: {payload} on {test_url} using {method}")
                send_request(method, test_url, payload, param)

                time.sleep(RATE_LIMIT)

def send_request(method, url, payload, param):
    """Send an HTTP request and check for XSS vulnerabilities."""
    try:
        response = requests.request(method, url, timeout=10)

        if response.status_code in [403, 406]:
            print(colored(f"[!] WAF Blocked: {url} with payload {payload}", "yellow"))
            with open("waf_logs.txt", "a") as waf_log:
                waf_log.write(f"Blocked | {method} | {url} | {payload}\n")
        elif payload in response.text:
            print(colored(f"[+] XSS Found: {url} | Parameter: {param} | Payload: {payload}", "red"))
            with open("xss_results.txt", "a") as result_file:
                result_file.write(f"XSS | {method} | {url} | {param} | {payload}\n")
        else:
            print(colored(f"[-] No XSS: {url} with payload {payload}", "green"))

    except Exception as e:
        print(colored(f"[!] Error testing {url}: {e}", "yellow"))

def scan_url(target_url):
    """Scan a single URL for XSS vulnerabilities."""
    # Parse the URL and detect parameters
    parsed_url = urlparse(target_url)
    parameters = parse_qs(parsed_url.query)
    parameters = {k: v[0] if v else "" for k, v in parameters.items()}

    # Detect allowed methods
    methods = detect_methods(target_url)
    print(f"[+] Detected methods for {target_url}: {', '.join(methods)}")

    # Test payloads with detected methods
    test_payloads(parsed_url, methods, parameters)

def main():
    """Main function to run the script."""
    target = input("Enter the target URL or file path: ").strip()
    urls = []

    if target.endswith(".txt"):
        with open(target, "r") as file:
            urls = [line.strip() for line in file if line.strip()]
    else:
        urls.append(target)

    print(f"[+] Loaded {len(urls)} URL(s) for testing.")

    # Use ThreadPoolExecutor to run scans in parallel (increased workers)
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        executor.map(scan_url, urls)

if __name__ == "__main__":
    main()
