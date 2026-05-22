# WebApp Security Toolkit

## Project Aim:
The aim of this project is to provide a set of tools for scanning web applications for common security vulnerabilities, including SQL Injection, XSS (Cross-Site Scripting), directory enumeration, and port scanning. It helps security professionals and developers identify potential vulnerabilities in web applications during the development or testing phases.

## Description:
This project consists of a set of scanners that target specific vulnerabilities commonly found in web applications:

- **SQL Injection Scanner**: Detects potential SQL injection vulnerabilities in web applications by testing various payloads.
- **XSS Scanner**: Tests for reflected Cross-Site Scripting (XSS) vulnerabilities by injecting malicious scripts.
- **Directory Scanner**: Identifies hidden directories on web servers using a wordlist of common directory names.
- **Port Scanner**: Scans common ports to identify open ports on the target server.

These scanners can be run independently or together to automate the process of security testing for web applications.

## Tools:
- **Python 3.x**: The programming language used to implement the scanners.
- **requests**: Python library used for making HTTP requests.
- **pathlib**: A standard library for handling paths in a way that is portable across operating systems.

## Outcome:
By using this toolkit, users can quickly identify vulnerabilities in their web applications and take proactive measures to secure them. The results of the scans are logged to a file for further analysis and reporting.

### Usage:
1. Clone the repository to your local machine.
2. Install the dependencies using `pip install -r requirements.txt`.
3. Run the `main.py` script to start scanning a web application:
    ```bash
    python main.py
    ```
4. Follow the on-screen prompts to test a target URL for vulnerabilities.

### Example Output:
```bash
[+] Starting SQL Injection Scanner...
[+] Starting XSS Scanner...
[+] Starting Directory Scanner...
[+] Starting Port Scanner...
