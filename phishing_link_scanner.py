
import re
import requests
from urllib.parse import urlparse

def is_ip_address(url):
    ip_pattern = re.compile(r'http[s]?://\d{1,3}(\.\d{1,3}){3}')
    return bool(ip_pattern.match(url))

def has_suspicious_keywords(url):
    suspicious_keywords = ['login', 'verify', 'update', 'banking', 'secure', 'account']
    return any(keyword in url.lower() for keyword in suspicious_keywords)

def count_dots(url):
    return url.count('.')

def check_https(url):
    return url.startswith("https://")

# Optional: Use VirusTotal API
def check_virustotal(url, api_key):
    vt_url = "https://www.virustotal.com/api/v3/urls"
    data = {"url": url}
    headers = {
        "x-apikey": api_key
    }

    response = requests.post(vt_url, data=data, headers=headers)
    if response.status_code == 200:
        result_url_id = response.json()["data"]["id"]
        report_url = f"{vt_url}/{result_url_id}"
        report = requests.get(report_url, headers=headers)
        return report.json()
    else:
        return None

def scan_url(url):
    print(f"\nScanning: {url}")
    score = 0

    if is_ip_address(url):
        print("- Uses IP instead of domain (suspicious)")
        score += 1

    if has_suspicious_keywords(url):
        print("- Contains suspicious keywords")
        score += 1

    if count_dots(url) > 5:
        print("- Contains too many dots")
        score += 1

    if not check_https(url):
        print("- Does not use HTTPS")
        score += 1

    if score >= 2:
        print("\n>>> This link is potentially **phishing**")
    else:
        print("\n>>> This link looks safe (but stay cautious!)")

if __name__ == "__main__":
    user_url = input("Enter the URL to scan: ")
    scan_url(user_url)

    # Uncomment to use VirusTotal API
    # api_key = "YOUR_API_KEY"
    # result = check_virustotal(user_url, api_key)
    # print(result)
