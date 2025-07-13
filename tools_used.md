# 🛠️ Tools Used in the AS398019 Investigation

This page lists all the tools used during the investigation of the suspicious infrastructure related to AS398019 and potentially malicious IP blocks.

---

## 🕵️ Reconnaissance & Investigation

### 🔍 ViewDNS.info
**Purpose:** Passive DNS and reverse IP lookup  
**Usage:** Web interface at [viewdns.info](https://viewdns.info)  
**Use Case:** Identify all domains hosted on an IP (e.g., `Reverse IP Lookup`).

---

### 🌐 urlscan.io
**Purpose:** Scan and visualize website behavior  
**Usage:** [urlscan.io](https://urlscan.io) — input domain or URL  
**Use Case:** View external requests, redirects, JS behavior.

---

### 📬 WHOIS
**Purpose:** Domain and IP registration details  
**Command:**
```bash
whois example.com
whois 142.202.188.0
```
**Use Case:** Identify domain creation date, registrant, and registrar.

---

### 🌐 Dig / nslookup
**Purpose:** DNS queries and record inspection  
**Commands:**
```bash
dig A example.com
dig TXT example.com
nslookup example.com
```
**Use Case:** Get IP resolution, TXT records, and MX/NS info.

---

### 🧰 Burp Suite
**Purpose:** Intercept and analyze HTTP(S) traffic  
**Setup:** Run Burp, set browser proxy to `127.0.0.1:8080`  
**Use Case:** Intercept form submissions, identify hidden API calls, detect JS beacons.

---

### 🛠️ curl
**Purpose:** Command-line HTTP requests  
**Command:**
```bash
curl -v http://example.com
```
**Use Case:** Inspect redirections, HTTP headers, page responses (200/301/403 etc.)

---

## 🧅 Network & OSINT

### 🌐 BGPView / RIPEstat / Hurricane Electric BGP Toolkit
**Purpose:** Analyze BGP routes, ASNs, IP ownership  
**Use Case:** Trace IPs to AS398019, observe upstream (e.g., Telia AS1299), look for aggregation.

---

### 🔍 crt.sh
**Purpose:** View historical TLS certificates  
**Use Case:** Identify domains once linked to IPs via HTTPS certs.

---

### 🧪 Shodan (API)
**Purpose:** Search for services on IPs  
**Command:**
```bash
curl "https://api.shodan.io/shodan/host/142.202.188.84?key=<APIKEY>"
```
**Use Case:** Find open ports, banners, Emby panels, PowerDNS servers.

---

## 🧑‍💻 System Tools

### 📡 netstat / ss / lsof
**Purpose:** Check open ports and listening services  
**Commands:**
```bash
ss -tunlp
netstat -tuln
lsof -i
```
**Use Case:** Detect strange processes or ports open on investigation VM.

---

### 🧾 Bash scripts
**Purpose:** Check intrusion and networking activity  
**Use Case:** Run regular snapshots of listening ports, process trees.

---

## 📚 Documentation

### 📄 Obsidian / Markdown
**Purpose:** Note-taking and structuring investigation paths  
**Use Case:** Organize findings per domain, group by block or behavior.

---

## 🧰 Optional / Lightweight Web Tools

- **VirusTotal** – quick check for known malware/phishing reports
- **Browser DevTools (F12)** – detect JavaScript calls, redirects, network activity
- **Traceroute / mtr** – optionally used to understand path to IPs

---

> ✍️ Note: All tools were used on Debian-based systems in a VM to avoid contamination and allow full traffic inspection via proxies.
