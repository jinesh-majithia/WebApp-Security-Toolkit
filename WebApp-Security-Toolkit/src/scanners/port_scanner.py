import socket
from pathlib import Path
from typing import List

# Constants
RESULTS_PATH = Path("../results/port_results.txt")

def port_scan(url: str, ports: List[int] = [80, 443, 8080]) -> None:
    """
    Scans a list of ports for a given URL.

    :param url: The URL or domain name to scan.
    :param ports: List of ports to scan. Defaults to [80, 443, 8080].
    """
    try:
        ip = socket.gethostbyname(url)
    except socket.gaierror as e:
        print(f"[!] Error resolving {url}: {e}")
        return

    vulnerable = False

    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    print(f"[+] Port {port} is open on {url} ({ip})")
                    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)  # Ensure the directory exists
                    with RESULTS_PATH.open("a", encoding="utf-8") as report:
                        report.write(f"Open Port Found: {url} ({ip}) - Port {port}\n")
                    vulnerable = True
        except socket.error as e:
            print(f"[!] Error connecting to {url}:{port} - {e}")

    if not vulnerable:
        print("[+] No open ports found on {url}.")
