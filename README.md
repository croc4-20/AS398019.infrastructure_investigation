# AS398019.infrastructure_investigation
## Summary
This repository documents an ongoing independent investigation into the infrastructure behind AS398019 (Dynu Systems Inc). This ASN is suspected of hosting potentially dormant or malicious infrastructure through a network of IPv4/IPv6 blocks, wildcard DNS records, and suspicious domain behavior.

## Findings
- Dozens of IPv4/IPv6 blocks announce hundreds of domains with identical behavior
- Domains resolve to wildcard DNS, invalid HTTPS certs, and respond HTTP 200 with blank or 404 pages
- Reverse DNS and reverse IP shows thousands of inactive domains parked on suspicious infrastructure
- Some domains redirect to residential IPs (e.g., UK VirginMedia), Emby servers, or phishing clones
- Likely use of Tier 1 provider (Telia AS1299) to make filtering harder

## Tools Used
- Burp Suite (manual interception)
- curl, dig, whois, nslookup
- Shodan, Censys, urlscan.io, viewdns.info
- Firefox (manual browsing), DNS leak detection
- bash (.sh) script to log connections on a monitored VM

## Investigation Timeline
- Start: July 2025
- Ongoing — no takedown or public attribution yet
ion
