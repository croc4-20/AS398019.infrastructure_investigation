import csv
import sys
import socket
import ssl
import http.client
import datetime
import re

def check_http_status(domain):
    try:
        conn = http.client.HTTPSConnection(domain, timeout=5)
        conn.request("GET", "/")
        res = conn.getresponse()
        content = res.read().decode(errors="ignore")
        conn.close()
        fake_404 = res.status == 200 and re.search(r"404|not found", content, re.I) is not None
        return res.status, int(fake_404)
    except:
        return None, None

def get_cert_info(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cn = next((entry[0][1] for entry in cert['subject'] if entry[0][0] == 'commonName'), None)
                expiry = cert.get('notAfter')
                if expiry:
                    expiry_date = datetime.datetime.strptime(expiry, '%b %d %H:%M:%S %Y %Z')
                    return cn, expiry_date.date()
                return cn, None
    except:
        return None, None

def enrich_csv(input_file, output_file):
    with open(input_file, newline='', encoding='utf-8') as csvfile:
        reader = list(csv.DictReader(csvfile))

    fieldnames = reader[0].keys() | {'HTTP_Status', 'Fake_404', 'Cert_CN', 'Cert_Expiry'}

    with open(output_file, 'w', newline='', encoding='utf-8') as outcsv:
        writer = csv.DictWriter(outcsv, fieldnames=fieldnames)
        writer.writeheader()

        for row in reader:
            domain = row.get("Domain")
            if not domain:
                writer.writerow(row)
                continue

            status, fake_404 = check_http_status(domain)
            cn, expiry = get_cert_info(domain)

            row['HTTP_Status'] = status
            row['Fake_404'] = fake_404
            row['Cert_CN'] = cn
            row['Cert_Expiry'] = expiry

            writer.writerow(row)

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python domain_scraper.py input.csv output.csv")
        sys.exit(1)

    enrich_csv(sys.argv[1], sys.argv[2])
