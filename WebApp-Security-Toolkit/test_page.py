
import urllib.request

resp = urllib.request.urlopen('http://127.0.0.1:5000/local')
print(f"Status: {resp.status}")
print(f"Content-Length: {len(resp.read())}")
print("SUCCESS")
