import csv
import requests
import ssl
import socket
from urllib.parse import urlparse
from http.client import HTTPConnection, HTTPSConnection
from OpenSSL import crypto

TIMEOUT = 5


def get_http_info(domain):
    try:
        url = f"http://{domain}"
        response = requests.get(url, timeout=TIMEOUT)
        status_code = response.status_code
        body = response.text.lower()
        fake_404 = status_code == 200 and '404' in body
        return status_code, fake_404
    except Exception:
        return None, False


def get_cert_info(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                subject = dict(x[0] for x in cert['subject'])
                cn = subject.get('commonName', '')
                not_after = cert.get('notAfter', '')
                return cn, not_after
    except Exception:
        return '', ''


def enrich_csv(input_file, output_file):
    with open(input_file, newline='') as infile, open(output_file, 'w', newline='') as outfile:
        reader = csv.DictReader(infile)
        fieldnames = reader.fieldnames + ['HTTP_Status', 'Fake_404', 'Cert_CN', 'Cert_Expiry']
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()

        for row in reader:
            domain = row.get('domain') or row.get('Domain') or row.get('host')
            if not domain:
                continue

            status, fake_404 = get_http_info(domain)
            cn, expiry = get_cert_info(domain)

            row['HTTP_Status'] = status if status else 'N/A'
            row['Fake_404'] = 'Yes' if fake_404 else 'No'
            row['Cert_CN'] = cn
            row['Cert_Expiry'] = expiry

            writer.writerow(row)


if __name__ == '__main__':
    import sys
    if len(sys.argv) != 3:
        print("Usage: python3 IP_SCAN_PIPELINE.py input.csv output.csv")
        exit(1)

    enrich_csv(sys.argv[1], sys.argv[2])
