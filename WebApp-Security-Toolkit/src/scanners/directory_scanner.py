import requests
from pathlib import Path

# Constants
WORDLIST_PATH = Path("D:/Projects/WebApp-Security-Toolkit/src/scanners/resources/wordList.txt")
RESULTS_PATH = Path("../results/directory_scan_results.txt")

def directory_scan(url: str, wordlist_path: Path) -> None:
    """
    Scans for directories on a given URL using a wordlist.
    
    :param url: Base URL to scan.
    :param wordlist_path: Path to the wordlist file.
    """
    # Load directory names from the wordlist file
    try:
        with wordlist_path.open("r", encoding="utf-8") as file:
            directories = file.read().splitlines()
    except FileNotFoundError:
        print(f"[!] Wordlist file not found at {wordlist_path}. Using default directories.")
        directories = ['admin', 'login', 'backup']  # Default fallback directories

    vulnerable = False

    for directory in directories:
        full_url = f"{url.rstrip('/')}/{directory}"
        try:
            response = requests.get(full_url, timeout=5)
            if response.status_code == 200:
                print(f"[+] Found directory: {full_url}")
                RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)  # Ensure the directory exists
                with RESULTS_PATH.open("a", encoding="utf-8") as report:
                    report.write(f"Found: {full_url}\n")
                vulnerable = True
        except requests.RequestException as e:
            print(f"[!] Error accessing {full_url}: {e}")

    if not vulnerable:
        print("[+] No directory vulnerabilities found.")
