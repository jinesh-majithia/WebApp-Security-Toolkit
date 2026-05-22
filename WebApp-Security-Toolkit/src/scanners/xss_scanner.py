import requests
from pathlib import Path

# Constants
RESULTS_PATH = Path("../results/xss_results.txt")

def test_xss(url: str) -> None:
    """
    Tests a URL for XSS vulnerabilities using predefined payloads.

    :param url: The base URL to test.
    """
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "\"<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
    ]

    vulnerable = False

    for payload in xss_payloads:
        target_url = f"{url.rstrip('/')}?input={payload}"  # Append payload as a query parameter
        try:
            response = requests.get(target_url, timeout=5)
            
            # Check if the payload is reflected in the response
            if payload in response.text:
                print(f"[!] XSS vulnerability detected with payload: {payload}")
                
                # Ensure the results directory exists
                RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
                
                # Write the result to the report
                with RESULTS_PATH.open("a", encoding="utf-8") as report:
                    report.write(f"Vulnerable URL: {target_url}\n")
                
                vulnerable = True
        except requests.RequestException as e:
            print(f"[!] Request failed for {target_url}: {e}")

    if not vulnerable:
        print("[+] No XSS vulnerabilities found.")
