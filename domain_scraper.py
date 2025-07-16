import csv
import socket
import ssl
import requests
import re
from datetime import datetime
from urllib.parse import urlparse

def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return ""

def get_http_info(domain):
    try:
        url = f"http://{domain}"
        r = requests.get(url, timeout=5)
        fake_404 = "not found" in r.text.lower() and r.status_code == 200
        return r.status_code, fake_404
    except:
        return "error", False

def get_cert_info(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cn = cert.get('subject', [(('', ''),)])[0][0][1]
                san = ','.join(cert.get('subjectAltName', []))
                exp_date = cert.get('notAfter')
                return cn, san, exp_date
    except:
        return "", "", ""

def enrich_csv(filename):
    rows = []
    with open(filename, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        fieldnames = reader.fieldnames + ['Resolved_Domain', 'HTTP_Status', 'Fake_404', 'Cert_CN', 'Cert_SAN', 'Cert_Expiry']
        for row in reader:
            ip = row['IP']
            domain = reverse_dns(ip)
            row['Resolved_Domain'] = domain
            if domain:
                http_status, fake_404 = get_http_info(domain)
                cn, san, exp = get_cert_info(domain)
                row['HTTP_Status'] = http_status
                row['Fake_404'] = fake_404
                row['Cert_CN'] = cn
                row['Cert_SAN'] = san
                row['Cert_Expiry'] = exp
            else:
                row['HTTP_Status'] = "no_domain"
                row['Fake_404'] = ""
                row['Cert_CN'] = ""
                row['Cert_SAN'] = ""
                row['Cert_Expiry'] = ""
            rows.append(row)

    enriched_file = filename.replace(".csv", "_enriched.csv")
    with open(enriched_file, 'w', newline='') as outfile:
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"[✓] Enriched CSV saved as: {enriched_file}")

# Usage
if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 enrich_ip_data.py IP_207.174.3.1.csv")
        exit(1)
    enrich_csv(sys.argv[1])
