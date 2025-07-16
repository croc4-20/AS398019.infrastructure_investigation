import subprocess
import socket
import ssl
import csv
import os
from urllib.parse import urlparse
import requests
from concurrent.futures import ThreadPoolExecutor


# === CONFIGURATION ===
INPUT_IP_LIST = "live_ipv4.txt"  # One IP per line
OUTPUT_DIR = "ip_scans"
PORTS = [80, 443]
THREADS = 50
TIMEOUT = 5


# === HELPERS ===
def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return ""

def extract_cert_domains(ip):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((ip, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert()
                names = []
                if "subject" in cert:
                    for part in cert["subject"]:
                        if part[0][0] == "commonName":
                            names.append(part[0][1])
                if "subjectAltName" in cert:
                    for typ, name in cert["subjectAltName"]:
                        if typ == "DNS":
                            names.append(name)
                return list(set(names))
    except:
        return []

def fetch_status(domain):
    try:
        url = f"http://{domain}"
        resp = requests.get(url, timeout=TIMEOUT)
        content = resp.text.lower()
        status = resp.status_code
        if status == 200 and ("404" in content or "not found" in content):
            return (domain, 200, "fake_404")
        return (domain, status, "ok" if status == 200 else "other")
    except:
        return (domain, "error", "error")

def process_ip(ip):
    result = []
    rdns = reverse_dns(ip)
    domains = set()
    if rdns:
        domains.add(rdns)
    domains.update(extract_cert_domains(ip))

    rows = []
    for domain in domains:
        domain, status, tag = fetch_status(domain)
        rows.append({"ip": ip, "domain": domain, "http_code": status, "type": tag})

    # Save to CSV
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_path = os.path.join(OUTPUT_DIR, f"{ip}.csv")
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["ip", "domain", "http_code", "type"])
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    print(f"Done {ip}: {len(rows)} domains")


# === MAIN EXECUTION ===
if __name__ == "__main__":
    with open(INPUT_IP_LIST) as f:
        ip_list = [line.strip() for line in f if line.strip()]

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        executor.map(process_ip, ip_list)
