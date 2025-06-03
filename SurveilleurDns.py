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




fihrioeg