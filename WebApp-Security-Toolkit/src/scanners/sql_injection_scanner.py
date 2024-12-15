import requests

def test_sql_injection(url):
    sql_payloads = [
        "' OR '1'='1",
        "' OR 'a'='a",
        "' UNION SELECT NULL, NULL --",
    ]
    vulnerable = False
    for payload in sql_payloads:
        target_url = f"{url}{payload}"
        try:
            response = requests.get(target_url, timeout = 5)
            if "error" in response.text.lower() or "syntax" in response.text.lower():
                print(f"[!] SQL Injection vulnerability detected with payload: {payload}")
                vulnerable = True
                with open("../results/sql_results.txt", "a") as report:
                    report.write(f"Vulnerable URL: {target_url}\n")
        except requests.RequestException as e:
            print(f"[!] Request failed: {e}")
    
    if not vulnerable:
        print("[+] No SQL Injection vulnerabilities found.")
