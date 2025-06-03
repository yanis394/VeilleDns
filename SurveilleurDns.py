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

