import requests
import socket
import ssl
import datetime
import os
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

# Try color, if no colorama, use plain
try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    GREEN = Fore.GREEN
    RED = Fore.RED
    YELLOW = Fore.YELLOW
    CYAN = Fore.CYAN
    WHITE = Fore.WHITE
except:
    GREEN = RED = YELLOW = CYAN = WHITE = ""
    class Style:
        RESET_ALL = ""

def banner():
    print(CYAN + r"""
  ____      _               ____                                  
 / ___|   _| |__   ___ _ __/ ___|  ___ __ _ _ __  _ __   ___ _ __ 
| |  | | | | '_ \ / _ \ '__\___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
| |__| |_| | |_) |  __/ |   ___) | (_| (_| | | | | | | |  __/ |   
 \____\__, |_.__/ \___|_|  |____/ \___\__,_|_| |_|_| |_|\___|_|   
     |___/                                                          
    PLUSCYBER VULN SCANNER - V5 PRO - By You!
    """)
    print(WHITE + "1. Quick Scan (Headers + SSL only - Fast)")
    print(WHITE + "2. Full Scan (Everything - Headers, SSL, Ports, Admin, SQLi, XSS, Files)")
    print(WHITE + "3. Scan Many Sites At Once (Batch Scan)")
    print(WHITE + "4. Exit")
    print("-" * 60)

def check_website(url, quick=False):
    print(f"\n{YELLOW}🔍 Scanning {url} ...\n")
    issues = []
    report_lines = [f"Scan Report for {url} - {datetime.datetime.now()}"]

    def log(msg, color=WHITE):
        print(color + msg)
        report_lines.append(msg)

    if not url.startswith("http"):
        url = "https://" + url

    if not url.startswith("https://"):
        log("❌ VULNERABILITY: Site no use HTTPS.", RED)
        issues.append("Use HTTPS")
    else:
        log("✅ HTTPS dey - Good", GREEN)

    headers_dict = {"User-Agent": "Mozilla/5.0"}

    try:
        response = requests.get(url, timeout=30, headers=headers_dict)
        headers = response.headers

        log("\n--- 1. Security Headers Check ---", CYAN)
        security_headers = {
            "Strict-Transport-Security": "Prevents downgrade attack",
            "X-Frame-Options": "Prevents clickjacking",
            "X-Content-Type-Options": "Prevents MIME sniffing",
            "Content-Security-Policy": "Prevents XSS attack",
            "X-XSS-Protection": "Prevents XSS"
        }
        for header, desc in security_headers.items():
            if header in headers:
                log(f"✅ {header} : Present", GREEN)
            else:
                log(f"❌ {header} : MISSING - {desc}", RED)
                issues.append(f"Add header: {header}")

        if "Server" in headers:
            log(f"\n⚠️ Server dey expose version: {headers['Server']}", YELLOW)
            issues.append("Hide Server version header")
        else:
            log("\n✅ Server version hidden", GREEN)

        # CORS + Cookies
        log("\n--- 1b. CORS + Cookies Check ---", CYAN)
        if "Access-Control-Allow-Origin" in headers and headers["Access-Control-Allow-Origin"] == "*":
            log("❌ CORS is * - Any site fit make request to your API", RED)
            issues.append("Fix CORS - Don't use *")
        else:
            log("✅ CORS not wide open - Good", GREEN)

    except Exception as e:
        log(f"Error: {e}", RED)
        return issues

    # SSL
    log("\n--- 2. SSL Certificate Check ---", CYAN)
    try:
        domain = urlparse(url).hostname
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            expiry = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            days_left = (expiry - datetime.datetime.now()).days
            if days_left < 30:
                log(f"❌ SSL go expire soon! Only {days_left} days left - {expiry}", RED)
                issues.append(f"Renew SSL - {days_left} days left")
            else:
                log(f"✅ SSL valid for {days_left} days - Expires {expiry}", GREEN)
    except Exception as e:
        log(f"⚠️ SSL check skip: {e}", YELLOW)

    if quick:
        log("\n========== QUICK SCAN DONE ==========", CYAN)
        return issues

    # PORTS
    log("\n--- 3. Port Scanner ---", CYAN)
    domain = urlparse(url).hostname
    ports = {21: "FTP", 23: "Telnet", 80: "HTTP", 443: "HTTPS", 3306: "MySQL", 3389: "RDP", 445: "SMB", 8080: "Alt HTTP", 8443: "Alt HTTPS"}
    def scan_port(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((socket.gethostbyname(domain), port))
        s.close()
        return port, result == 0
    try:
        ip = socket.gethostbyname(domain)
        log(f"Target IP: {ip}", WHITE)
        with ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(scan_port, ports.keys()))
            for port, is_open in results:
                if is_open:
                    if port in [21, 23, 3306, 3389, 445, 8080, 8443]:
                        log(f"❌ Port {port} OPEN - DANGEROUS! (If Cloudflare, fit be false positive)", RED)
                        issues.append(f"CLOSE Port {port}")
                    else:
                        log(f"✅ Port {port} OPEN - Normal", GREEN)
                else:
                    log(f"✅ Port {port} CLOSED - Good", GREEN)
    except Exception as e:
        log(f"Port scan error: {e}", RED)

    # ADMIN
    log("\n--- 4. Admin Panel Check ---", CYAN)
    for path in ["/admin", "/admin.php", "/login", "/wp-admin", "/administrator", "/dashboard", "/cpanel"]:
        try:
            test_url = url.rstrip("/") + path
            r = requests.get(test_url, timeout=15, headers=headers_dict)
            if r.status_code == 200:
                log(f"⚠️ Found: {test_url} - E dey exposed!", YELLOW)
                issues.append(f"Protect admin page: {path}")
            else:
                log(f"✅ {path} - Hidden / Not found ({r.status_code})", GREEN)
        except: pass

    # SQLi
    log("\n--- 5. SQL Injection Check ---", CYAN)
    vulnerable = False
    for payload in ["' OR '1'='1", "' OR 1=1--"]:
        try:
            r = requests.get(url.rstrip("/") + f"/?id={payload}", timeout=10, headers=headers_dict)
            text = r.text.lower()
            if "sql syntax" in text or ("mysql" in text and "error" in text):
                log(f"❌ VULNERABLE to SQLi: {payload}", RED)
                issues.append(f"Fix SQLi {payload}")
                vulnerable = True
                break
        except: pass
    if not vulnerable:
        log("✅ No SQL Injection error found - Good", GREEN)

    # XSS
    log("\n--- 6. XSS Check ---", CYAN)
    xss_payload = "<script>alert(123)</script>"
    xss_found = False
    for param in ["q", "search", "query", "name"]:
        try:
            r = requests.get(url.rstrip("/") + f"/?{param}={xss_payload}", timeout=10, headers=headers_dict)
            if xss_payload in r.text:
                log(f"❌ POSSIBLE XSS in ?{param}=", RED)
                issues.append(f"Fix XSS param {param}")
                xss_found = True
                break
        except: pass
    if not xss_found:
        log("✅ No XSS reflection found - Good", GREEN)

    # SENSITIVE FILES
    log("\n--- 7. Sensitive Files Check ---", CYAN)
    for path in ["/.env", "/.git/config", "/backup.zip", "/db.sql", "/config.php", "/wp-config.php", "/robots.txt"]:
        try:
            r = requests.get(url.rstrip("/") + path, timeout=10, headers=headers_dict)
            if path in ["/.env", "/.git/config", "/backup.zip", "/db.sql", "/wp-config.php"] and r.status_code == 200:
                log(f"❌ DANGEROUS! Sensitive file exposed: {path}", RED)
                issues.append(f"Remove exposed file: {path}")
            elif r.status_code == 200:
                log(f"ℹ️ Found: {path} - Normal, check wetin e dey expose", YELLOW)
            else:
                log(f"✅ {path} - Hidden ({r.status_code})", GREEN)
        except: pass

    log("\n========== FINAL REPORT ==========", CYAN)
    if not issues:
        log("🎉 Your site is SAFE!", GREEN)
    else:
        log(f"Found {len(issues)} issues:", RED)
        for i, fix in enumerate(issues, 1):
            log(f"{i}. FIX: {fix}", YELLOW)

    # Save
    filename = f"report_{urlparse(url).hostname}.txt"
    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines))
    log(f"\n📄 Report saved to {filename}", GREEN)
    return issues

# MAIN MENU LOOP
while True:
    banner()
    choice = input("Choose option (1-4): ")

    if choice == "1":
        site = input("Enter website: ")
        check_website(site, quick=True)
        input("\nPress ENTER to go back to menu...")
    elif choice == "2":
        site = input("Enter website: ")
        check_website(site, quick=False)
        input("\nPress ENTER to go back to menu...")
    elif choice == "3":
        print("\n--- Batch Scan ---")
        print("Type sites separated by comma, e.g: google.com, facebook.com, pluscyber-p3-8-pro.onrender.com")
        sites = input("Enter sites: ").split(",")
        for s in sites:
            s = s.strip()
            if s:
                check_website(s, quick=False)
                print("\n" + "="*60 + "\n")
        input("Batch done! Press ENTER...")
    elif choice == "4":
        print("Bye! Keep hacking ethically! 👋")
        break
    else:
        print("Invalid! Choose 1-4")