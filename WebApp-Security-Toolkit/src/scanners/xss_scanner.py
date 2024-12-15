import requests

def test_xss(url):
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "\"<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
    ]
    vulnerable = False
    for payload in xss_payloads:
        target_url = f"{url}{payload}"
        try:
            response = requests.get(target_url)
            if payload in response.text:
                print(f"[!] XSS vulnerability detected with payload: {payload}")
                vulnerable = True
                with open("../results/xss_results.txt", "a") as report:
                    report.write(f"Vulnerable URL: {target_url}\n")
        except requests.RequestException as e:
            print(f"[!] Request failed: {e}")

    if not vulnerable:
        print("[+] No XSS vulnerabilities found.")