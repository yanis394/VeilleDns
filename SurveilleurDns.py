from scapy.all import sniff, DNSQR, IP
from datetime import datetime
import re
import signal
import sys

BLACKLIST = {
    "malicious-domain.com",
    "suspiciousdomain.ru",
    "data-leak.xyz"
}

SUSPICIOUS_TLDS = {".ru", ".xyz", ".top"}

alerts = []
query_count = {}

def score_domain(domain, src_ip):
    score = 0
    if domain in BLACKLIST:
        score += 80
    if len(domain) > 50:
        score += 10
    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += 5
    if re.match(r"^[a-z0-9]{12,}\.(ru|xyz|top)$", domain):
        score += 15

    now = datetime.now()
    key = (src_ip, now.strftime("%Y-%m-%d %H:%M"))
    query_count[key] = query_count.get(key, 0) + 1
    if query_count[key] > 10:
        score += 10

    return min(score, 100)

def process_packet(packet):
    if packet.haslayer(DNSQR) and packet.haslayer(IP):
        domain = packet[DNSQR].qname.decode().strip(".")
        src_ip = packet[IP].src
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        score = score_domain(domain, src_ip)
        if score > 0:
            status = "INFO"
            if score >= 80:
                status = "CRITICAL"
            elif score >= 50:
                status = "WARNING"

            alert = f"[{timestamp}] ALERT - IP: {src_ip} - Domain: {domain} - Score: {score} - Status: {status}"
            alerts.append(alert)
            print(alert)