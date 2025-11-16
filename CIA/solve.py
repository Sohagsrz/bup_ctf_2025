#!/usr/bin/env python3
import requests

url = "http://49.213.52.6:6969/"

# First, get the page to establish a session
session = requests.Session()
response = session.get(url)
print(f"GET Response: {response.text[:200]}")

# Now try POST with the same session
headers = {
    "Content-Type": "application/json",
    "Referer": url,
    "Origin": url,
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
}

data = {"flagDaw": True}
response = session.post(url, json=data, headers=headers)
print(f"\nPOST Response: {response.text}")
print(f"Status Code: {response.status_code}")
print(f"Headers: {dict(response.headers)}")

