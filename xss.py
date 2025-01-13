import os
import random
import string
import base64
import requests
import asyncio
import aiohttp
from urllib.parse import urljoin
from flask import Flask, request, jsonify
import time
import logging
from packaging import version
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
from requests.exceptions import RequestException
import subprocess
import json
from datetime import datetime

# Flask setup
app = Flask(__name__)

# Set up logging for security and reliability
logging.basicConfig(filename="scan_log.txt", level=logging.INFO, format="%(asctime)s - %(message)s")

# Secure communication (HTTPS)
SECURE_PROTOCOL = 'https'

# Rate limiting
MAX_REQUESTS_PER_SECOND = 2  # Adjustable rate
last_request_time = time.time()

# Retry logic for requests with exponential backoff
retry_strategy = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[500, 502, 503, 504],
    allowed_methods=["HEAD", "GET", "POST"]
)
http_adapter = HTTPAdapter(max_retries=retry_strategy)
http_session = requests.Session()
http_session.mount("https://", http_adapter)
http_session.mount("http://", http_adapter)

# Version management
GITHUB_REPO_URL = "https://api.github.com/repos/yourusername/yourrepo/releases/latest"
LOCAL_VERSION_FILE = "version.json"  # Store the local version info

def get_local_version():
    """Get the local version of the tool from version.json."""
    if os.path.exists(LOCAL_VERSION_FILE):
        with open(LOCAL_VERSION_FILE, 'r') as f:
            version_info = json.load(f)
            return version_info.get("version", "0.0.0")
    return "0.0.0"

def save_local_version(version):
    """Save the local version to version.json."""
    version_info = {"version": version}
    with open(LOCAL_VERSION_FILE, 'w') as f:
        json.dump(version_info, f)

def check_for_updates():
    """Check for updates by comparing the local version with the latest release on GitHub."""
    local_version = get_local_version()
    try:
        response = requests.get(GITHUB_REPO_URL)
        response.raise_for_status()  # Raise an exception for HTTP errors
        latest_release = response.json()
        print(f"GitHub API Response: {latest_release}")  # Print the full response for debugging

        # Check if 'tag_name' exists in the response
        if 'tag_name' in latest_release:
            latest_version = latest_release['tag_name']
            print(f"Latest Version: {latest_version}, Local Version: {local_version}")
            if version.parse(latest_version) > version.parse(local_version):
                print(f"\033[1;32m[UPDATE AVAILABLE]\033[0m A new version ({latest_version}) is available!")
                return latest_version
            else:
                print("\033[1;34m[UP TO DATE]\033[0m You are running the latest version.")
                return None
        else:
            print(f"\033[1;31m[ERROR]\033[0m 'tag_name' not found in the response.")
            return None
    except requests.RequestException as e:
        print(f"\033[1;31m[ERROR]\033[0m Failed to check for updates: {e}")
        return None

def update_tool():
    """Update the tool to the latest version by pulling from the GitHub repository."""
    print("Updating tool to the latest version...")
    try:
        subprocess.run(["git", "pull"], check=True)
        print("\033[1;32m[UPDATE SUCCESSFUL]\033[0m Tool has been updated.")
        latest_version = check_for_updates()
        if latest_version:
            save_local_version(latest_version)
    except subprocess.CalledProcessError as e:
        print(f"\033[1;31m[ERROR]\033[0m Failed to update tool: {e}")

# WAF Bypass Techniques
def generate_random_string(length=10):
    """Generate a random string of specified length."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def encode_payload(payload):
    """Apply encoding techniques to payloads to bypass WAFs."""
    encoded_payloads = []
    url_encoded = payload.replace('<', '%3C').replace('>', '%3E').replace('"', '%22').replace("'", '%27')
    encoded_payloads.append(url_encoded)
    
    double_url_encoded = base64.b64encode(url_encoded.encode()).decode('utf-8')
    encoded_payloads.append(double_url_encoded)
    
    base64_encoded = base64.b64encode(payload.encode()).decode('utf-8')
    encoded_payloads.append(base64_encoded)
    
    return encoded_payloads

def randomize_headers(headers):
    """Add random headers to requests to bypass WAFs."""
    headers['X-Forwarded-For'] = generate_random_string(12)
    headers['X-Requested-With'] = generate_random_string(8)
    headers['User-Agent'] = random.choice([
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.61 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/18.18363'
    ])
    return headers

def rate_limit_request():
    """Enforce rate limiting to ensure requests are not sent too quickly."""
    global last_request_time
    current_time = time.time()
    elapsed_time = current_time - last_request_time
    if elapsed_time < 1 / MAX_REQUESTS_PER_SECOND:
        time.sleep(1 / MAX_REQUESTS_PER_SECOND - elapsed_time)
    last_request_time = time.time()

async def async_submit_payload(session, url, payload, method, cookies, headers, max_retries=3):
    """Asynchronously submit a payload and attempt to bypass WAFs."""
    headers = randomize_headers(headers)
    encoded_payloads = encode_payload(payload)

    for encoded_payload in encoded_payloads:
        try:
            rate_limit_request()  # Enforce rate limiting before each request
            if method == "POST":
                async with session.post(url, cookies=cookies, headers=headers, data={'payload': encoded_payload}) as response:
                    response.raise_for_status()
                    text = await response.text()
                    if encoded_payload in text:
                        logging.info(f"Payload: {encoded_payload}, Response URL: {url}")
                        print(f"\033[1;32m[WAF BYPASS - XSS DETECTED]\033[0m Payload: {encoded_payload}, Response URL: {url}")
                        return {'type': 'WAF Bypass XSS', 'url': url, 'payload': encoded_payload}
            else:
                async with session.get(url, cookies=cookies, headers=headers, params={'payload': encoded_payload}) as response:
                    response.raise_for_status()
                    text = await response.text()
                    if encoded_payload in text:
                        logging.info(f"Payload: {encoded_payload}, Response URL: {url}")
                        print(f"\033[1;32m[WAF BYPASS - XSS DETECTED]\033[0m Payload: {encoded_payload}, Response URL: {url}")
                        return {'type': 'WAF Bypass XSS', 'url': url, 'payload': encoded_payload}
        except RequestException as e:
            print(f"\033[1;31m[ERROR]\033[0m Error with {url} during WAF bypass: {e}")
        except Exception as e:
            print(f"\033[1;31m[ERROR]\033[0m Unexpected error: {e}")

# Main execution block
if __name__ == "__main__":
    check_for_updates()
