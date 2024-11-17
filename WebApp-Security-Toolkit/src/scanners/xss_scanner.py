import requests

def test_xss(url):
    xss_payloads = ["<script>alert('XSS')</script>", "\"<script>alert('XSS')</script>"]
    for payload in xss_payloads:
        target_url = f"{url}{payload}"
        response = requests.get(target_url)
        if payload in response.text:
            print(f"[!] XSS vulnerability detected with payload: {payload}")