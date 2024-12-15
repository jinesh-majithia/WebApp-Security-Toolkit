import requests
from pathlib import Path

wordlist_path = Path("D:\Projects\WebApp-Security-Toolkit\src\scanners\resources\wordList.txt")

def directory_scan(url, wordlist_path):
    #with open(wordlist_path, "r") as f:
    #    directories = f.read().splitlines()
    directories = ['admin', 'login', 'backup']
    vulnerable = False
    for directory in directories:
        full_url = f"{url}/{directory}"
        try:
            response = requests.get(full_url, timeout=5)
            if response.status_code == 200:
                print(f"[+] Found directory: {full_url}")
                with open("../results/directory_scan_results.txt", "a") as report:
                    report.write(f"Found: {full_url}\n")
                vulnerable = True
        except requests.RequestException as e:
            print(f"[!] Error accessing {full_url}: {e}")

    if not vulnerable:
         print("[+] No Directory Scan vulnerabilities found.")
