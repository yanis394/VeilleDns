from pydivert import WinDivert
from dnslib import DNSRecord
from datetime import datetime
import re

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
    if re.match(r"^[a-z0-9\-]{12,}\.(ru|xyz|top)$", domain):
        score += 15

    now = datetime.now()
    key = (src_ip, now.strftime("%Y-%m-%d %H:%M"))
    query_count[key] = query_count.get(key, 0) + 1
    if query_count[key] > 10:
        score += 10

    return min(score, 100)

def analyze_packet(packet):
    if packet.is_outbound and packet.dst_port == 53 and packet.payload:
        try:
            dns = DNSRecord.parse(packet.payload)
            qname = str(dns.q.qname).strip(".")
            src_ip = packet.src_addr
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            score = score_domain(qname, src_ip)

            if score > 0:
                if score >= 80:
                    status = "CRITICAL"
                elif score >= 50:
                    status = "WARNING"
                else:
                    status = "INFO"

                alert = f"[{timestamp}] ALERT - IP: {src_ip} - Domain: {qname} - Score: {score} - Status: {status}"
                alerts.append(alert)
                print(alert)
        except Exception as e:
            pass  # Ignorer les paquets non-DNS ou malformés

def save_reports():
    with open("dns_alerts.log", "w") as f_log:
        for alert in alerts:
            f_log.write(alert + "\n")

    unique_ips = set()
    domains_contacted = set()
    max_score = 0

    for alert in alerts:
        try:
            parts = alert.split(" - ")
            ip = parts[1].split(": ")[1]
            domain = parts[2].split(": ")[1]
            score = int(parts[3].split(": ")[1])
            unique_ips.add(ip)
            domains_contacted.add(domain)
            max_score = max(max_score, score)
        except:
            continue

    with open("summary_report.txt", "w") as f_summary:
        f_summary.write("===== Résumé du LAB-02 - Analyse DNS =====\n")
        f_summary.write(f"IPs suspectes : {', '.join(unique_ips)}\n")
        f_summary.write(f"Domaines contactés : {', '.join(domains_contacted)}\n")
        f_summary.write(f"Score de suspicion maximal : {max_score}\n")
        if max_score >= 80:
            f_summary.write("Recommandation : Blocage immédiat de l'IP source\n")
        elif max_score >= 50:
            f_summary.write("Recommandation : Surveillance accrue\n")
        else:
            f_summary.write("Recommandation : Aucune action urgente\n")

if __name__ == "__main__":
    print("Surveillance DNS (Windows) en cours... CTRL+C pour arrêter.")
    try:
        with WinDivert("outbound and udp.DstPort == 53") as w:
            for packet in w:
                analyze_packet(packet)
    except KeyboardInterrupt:
        print("\nArrêt détecté. Génération des rapports...")
        save_reports()
