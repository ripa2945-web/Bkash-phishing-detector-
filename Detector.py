# bKash Phishing Detector - Defensive Tool for Bangladesh
# Detects fake bKash links like bkash-offer-bd.tk, bkashbonus.com
# Legal & Defensive Only

import re

SUSPICIOUS_KEYWORDS = ['bkash', 'nagad', 'rocket', 'bonus', 'offer', 'win']
BAD_TLDS = ['.tk', '.ml', '.cf', '.xyz', '.top']

def is_phishing_url(url):
    url = url.lower()
    score = 0
    reasons = []
    
    if any(tld in url for tld in BAD_TLDS):
        score += 2
        reasons.append(f"Suspicious TLD")
    
    if "bkash" in url and "bkash.com" not in url:
        score += 3
        reasons.append("Fake bKash domain impersonation")
    
    if url.count('-') > 3 or url.count('.') > 4:
        score += 1
        reasons.append("Obfuscated URL")
    
    return score >= 3, reasons

# Test
tests = [
    "https://www.bkaash-offer-bd.tk/bonus",
    "https://www.bkash.com",
    "https://bkashbonus2026.xyz/login"
]

for u in tests:
    is_phish, why = is_phishing_url(u)
    print(f"{u} -> PHISHING: {is_phish} | {why}")
