import requests
import os

wordlist = "/resources/wordlist.txt"

def directory_scan(url, wordlist = wordlist):
    print(wordlist)
    with open(wordlist, "r") as f:
        directories = f.read().splitlines()
    for directory in directories:
        full_url = f"{url}/{directory}"
        response = requests.get(full_url)
        if response.status_code == 200:
            print(f"[+] Found directory: {full_url}")
