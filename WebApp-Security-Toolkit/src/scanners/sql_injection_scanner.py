import requests
from pathlib import Path

# Constants
RESULTS_PATH = Path("../results/sql_results.txt")

def test_sql_injection(url: str) -> None:
    """
    Tests a URL for SQL Injection vulnerabilities using predefined payloads.

    :param url: The base URL to test.
    """
    sql_payloads = [
        "' OR '1'='1",
        "' OR 'a'='a",
        "' UNION SELECT NULL, NULL --",
    ]

    vulnerable = False

    for payload in sql_payloads:
        target_url = f"{url.rstrip('/')}?input={payload}"  # Append payload to the URL
        try:
            response = requests.get(target_url, timeout=5)
            response_text = response.text.lower()

            if "error" in response_text or "syntax" in response_text:
                print(f"[!] SQL Injection vulnerability detected with payload: {payload}")
                
                # Ensure the results directory exists
                RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
                
                # Write the result to the report
                with RESULTS_PATH.open("a", encoding="utf-8") as report:
                    report.write(f"Vulnerable URL: {target_url}\n")
                
                vulnerable = True
        except requests.RequestException as e:
            print(f"[!] Request failed for {target_url}: {e}")

    if not vulnerable:
        print("[+] No SQL Injection vulnerabilities found.")
