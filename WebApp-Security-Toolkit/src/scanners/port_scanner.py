import socket

def port_scan(url, ports=[80, 443, 8080]):
    ip = socket.gethostbyname(url)
    vulnerable = False
    try:
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                print(f"[+] Port {port} is open")
                vulnerable = True
                with open("../results/port_results.txt", "a") as report:
                    report.write(f"Vulnerable URL: {url}\n")
            sock.close()
    except:
        {}
    
    if not vulnerable:
         print("[+] No Port Scan vulnerabilities found.")
