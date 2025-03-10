import re
import requests
from urllib.parse import urlparse

# VirusTotal API Configuration
API_SECRET = "391be4990ae0b9501b7f7b0f67ac2045941dd5ac0ca15388a0505f80b48c4ba9"
VT_ENDPOINT = "https://www.virustotal.com/api/v3/urls"

# Function to identify potentially harmful keywords in URLs
def detect_suspicious_patterns(link):
    flagged_words = [r'auth', r'confirm', r'login', r'validate', r'account', r'update']
    return any(re.search(keyword, link, re.IGNORECASE) for keyword in flagged_words)

# Function to verify if a domain is blacklisted
def verify_blacklist(link):
    restricted_sites = {"malicious-link.org", "phishingsite.net", "fraudsite.com"}
    extracted_domain = urlparse(link).netloc
    return extracted_domain in restricted_sites

# Function to analyze URL reputation via VirusTotal API
def fetch_url_reputation(link):
    headers = {"x-apikey": API_SECRET, "Content-Type": "application/x-www-form-urlencoded"}
    
    try:
        response = requests.post(VT_ENDPOINT, headers=headers, data={"url": link})
        if response.status_code == 200:
            url_identifier = response.json().get("data", {}).get("id", "")
            
            if url_identifier:
                analysis_response = requests.get(f"{VT_ENDPOINT}/{url_identifier}", headers=headers)
                if analysis_response.status_code == 200:
                    stats = analysis_response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    malicious_hits = stats.get("malicious", 0)
                    return f"Unsafe ({malicious_hits} detections)" if malicious_hits > 0 else "No Threat Detected"
        
        return "Unable to Determine Reputation"
    except requests.exceptions.RequestException as err:
        return f"Error occurred: {str(err)}"

# Function to perform a comprehensive scan on a URL
def analyze_link(link):
    if verify_blacklist(link):
        return "Warning: The URL is listed as unsafe!"
    
    if detect_suspicious_patterns(link):
        return "Caution: The URL contains potentially harmful words!"
    
    return f"Final Verdict: {fetch_url_reputation(link)}"

# Execution Block
if __name__ == "__main__":
    test_urls = [
        "https://example.com",
        "https://login-secure.com",
        "http://phishingsite.net/reset-password",
        "https://banksecure-update.com"
    ]
    
    for url in test_urls:
        print(f"Scanning: {url}")
        print(analyze_link(url))
        print("-" * 50)
