# ip_scan_pipeline.py

import subprocess
import os
import re
import httpx
import json
from pathlib import Path
from urllib.parse import urlparse

INPUT_FILE = "live_ips.txt"
CERT_DIR = Path("certs")
CERT_DIR.mkdir(exist_ok=True)

HTTP_PROBE_PORTS = [80, 443, 8080, 8096]

FAKE_404_KEYWORDS = ["404 not found", "page not found", "error 404"]
HEADERS = {"User-Agent": "Mozilla/5.0 (Cyber Investigator)"}


def run(cmd):
    print(f"[+] Running: {cmd}")
    return subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL)


def reverse_dns(ip):
    try:
        return run(f"dig -x {ip} +short").strip()
    except:
        return ""


def grab_cert(ip):
    path = CERT_DIR / f"{ip}.pem"
    try:
        output = run(f"echo | timeout 5 openssl s_client -connect {ip}:443 -showcerts")
        with open(path, "w") as f:
            f.write(output)
        return path
    except:
        return None


def parse_domains_from_cert(pem_path):
    if not pem_path or not pem_path.exists():
        return []
    raw = pem_path.read_text()
    sans = re.findall(r"DNS:([a-zA-Z0-9_.-]+)", raw)
    return list(set(sans))


def classify_domain(domain):
    result = {
        "domain": domain,
        "status": "unknown",
        "http_status": None,
        "title": None
    }
    
    for scheme in ["http", "https"]:
        try:
            url = f"{scheme}://{domain}"
            r = httpx.get(url, headers=HEADERS, timeout=10, follow_redirects=True)
            result["http_status"] = r.status_code
            content = r.text.lower()

            if any(k in content for k in FAKE_404_KEYWORDS):
                result["status"] = "fake_404"
            elif r.status_code == 200 and "index of /" in content:
                result["status"] = "directory_listing"
            elif r.status_code == 403:
                result["status"] = "forbidden"
            elif r.status_code == 404:
                result["status"] = "not_found"
            elif "phish" in content or "wallet" in content or "login" in content:
                result["status"] = "suspicious"
            else:
                result["status"] = "ok"

            result["title"] = re.search(r"<title>(.*?)</title>", r.text, re.I)
            if result["title"]:
                result["title"] = result["title"].group(1)

            break
        except:
            continue

    return result


def main():
    ips = Path(INPUT_FILE).read_text().splitlines()

    for ip in ips:
        ip_dir = Path(f"results/{ip}")
        ip_dir.mkdir(parents=True, exist_ok=True)

        # Step 1: reverse DNS
        rdns = reverse_dns(ip)
        Path(ip_dir / "rdns.txt").write_text(rdns + "\n")

        # Step 2: TLS cert
        cert_path = grab_cert(ip)
        domains = parse_domains_from_cert(cert_path)
        if rdns:
            domains.append(rdns.strip("."))
        domains = list(set(d for d in domains if d and not d.endswith(".local")))
        Path(ip_dir / "domains.txt").write_text("\n".join(domains))

        # Step 3: classification
        clean = []
        suspect = []
        for dom in domains:
            result = classify_domain(dom)
            if result["status"] in ["fake_404", "suspicious", "forbidden", "not_found"]:
                suspect.append(result)
            else:
                clean.append(result)

        Path(ip_dir / "clean.json").write_text(json.dumps(clean, indent=2))
        Path(ip_dir / "suspect.json").write_text(json.dumps(suspect, indent=2))


if __name__ == "__main__":
    main()
