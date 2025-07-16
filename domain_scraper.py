import csv
import socket
import ssl
import requests
import sys

def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return ""

def get_http_info(domain):
    try:
        r = requests.get(f"http://{domain}", timeout=5)
        fake_404 = "not found" in r.text.lower() and r.status_code == 200
        return r.status_code, fake_404
    except:
        return "error", False

def get_cert_info(domain):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cn = next((t[0][1] for t in cert['subject'] if t[0][0] == 'commonName'), "")
                san = ", ".join(d[1] for d in cert.get('subjectAltName', []))
                expiry = cert.get('notAfter', '')
                return cn, san, expiry
    except:
        return "", "", ""

def enrich_csv(input_file):
    with open(input_file, newline='') as infile:
        reader = csv.DictReader(infile)
        if reader.fieldnames is None:
            raise ValueError("Fichier CSV vide ou corrompu.")
        
        fieldnames = reader.fieldnames.copy()
        new_fields = ['Resolved_Domain', 'HTTP_Status', 'Fake_404', 'Cert_CN', 'Cert_SAN', 'Cert_Expiry']
        for nf in new_fields:
            if nf not in fieldnames:
                fieldnames.append(nf)

        rows = []
        for row in reader:
            ip = row.get('IP', '').strip()
            if not ip:
                continue

            resolved_domain = reverse_dns(ip)
            row['Resolved_Domain'] = resolved_domain

            if resolved_domain:
                http_code, fake404 = get_http_info(resolved_domain)
                cn, san, exp = get_cert_info(resolved_domain)
                row['HTTP_Status'] = http_code
                row['Fake_404'] = fake404
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

    output_file = input_file.replace(".csv", "_enriched.csv")
    with open(output_file, "w", newline='') as outfile:
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"[✓] Enriched file written to: {output_file}")

# Usage
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 domain_enricher.py <filename.csv>")
        sys.exit(1)

    try:
        enrich_csv(sys.argv[1])
    except Exception as e:
        print(f"[!] Error: {e}")
