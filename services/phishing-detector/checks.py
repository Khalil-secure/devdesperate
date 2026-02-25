import httpx
import os
import base64
import logging
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
ALIENVAULT_API_KEY = os.getenv("ALIENVAULT_API_KEY")
HEADERS_VT = {"x-apikey": VIRUSTOTAL_API_KEY}
HEADERS_AV = {"X-Api-Key": ALIENVAULT_API_KEY}

# ── VirusTotal ────────────────────────────────────────────────────

async def check_url_virustotal(url: str) -> dict:
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(endpoint, headers=HEADERS_VT)
        if r.status_code == 200:
            stats = r.json()["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            return {
                "source": "virustotal",
                "target": url,
                "malicious": malicious,
                "suspicious": suspicious,
                "verdict": "PHISHING" if malicious > 0 else "SUSPICIOUS" if suspicious > 0 else "SAFE"
            }
    except Exception as e:
        logger.error(f"VirusTotal URL check failed: {e}")
    return {"source": "virustotal", "target": url, "verdict": "UNKNOWN"}

async def check_domain_virustotal(domain: str) -> dict:
    endpoint = f"https://www.virustotal.com/api/v3/domains/{domain}"
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(endpoint, headers=HEADERS_VT)
        if r.status_code == 200:
            stats = r.json()["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            return {
                "source": "virustotal",
                "target": domain,
                "malicious": malicious,
                "suspicious": suspicious,
                "verdict": "PHISHING" if malicious > 0 else "SUSPICIOUS" if suspicious > 0 else "SAFE"
            }
    except Exception as e:
        logger.error(f"VirusTotal domain check failed: {e}")
    return {"source": "virustotal", "target": domain, "verdict": "UNKNOWN"}

# ── AbuseIPDB ─────────────────────────────────────────────────────

async def check_ip_abuseipdb(ip: str) -> dict:
    endpoint = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(endpoint, headers=headers, params=params)
        if r.status_code == 200:
            data = r.json()["data"]
            score = data.get("abuseConfidenceScore", 0)
            return {
                "source": "abuseipdb",
                "target": ip,
                "abuse_score": score,
                "verdict": "PHISHING" if score > 80 else "SUSPICIOUS" if score > 30 else "SAFE"
            }
    except Exception as e:
        logger.error(f"AbuseIPDB check failed: {e}")
    return {"source": "abuseipdb", "target": ip, "verdict": "UNKNOWN"}

# ── Verdict Engine ────────────────────────────────────────────────

def compute_verdict(results: list) -> str:
    verdicts = [r.get("verdict") for r in results]
    if "PHISHING" in verdicts:
        return "PHISHING"
    if verdicts.count("SUSPICIOUS") >= 2:
        return "SUSPICIOUS"
    if "SUSPICIOUS" in verdicts:
        return "SUSPICIOUS"
    return "SAFE"
# ── Typosquatting Detection ───────────────────────────────────────

KNOWN_BRANDS = [
    "paypal.com", "google.com", "microsoft.com", "apple.com",
    "amazon.com", "facebook.com", "instagram.com", "netflix.com",
    "linkedin.com", "twitter.com", "x.com", "dropbox.com",
    "zoom.us", "slack.com", "github.com", "outlook.com",
    "office365.com", "live.com", "yahoo.com", "dhl.com",
    "fedex.com", "ups.com", "bankofamerica.com", "chase.com",
    "wellsfargo.com", "amex.com", "americanexpress.com"
]

def levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current = [i + 1]
        for j, c2 in enumerate(s2):
            current.append(min(previous[j + 1] + 1, current[j] + 1, previous[j] + (c1 != c2)))
        previous = current
    return previous[-1]

def check_typosquatting(domain: str) -> dict:
    if not domain:
        return {"verdict": "UNKNOWN", "reason": "No domain"}
    
    # Strip subdomains
    parts = domain.split(".")
    root = ".".join(parts[-2:]) if len(parts) >= 2 else domain

    for brand in KNOWN_BRANDS:
        if root == brand:
            return {"verdict": "SAFE", "reason": f"Exact match: {brand}"}
        distance = levenshtein(root, brand)
        if distance <= 2:
            return {
                "verdict": "PHISHING",
                "reason": f"'{root}' looks like '{brand}' (distance: {distance})"
            }
    return {"verdict": "SAFE", "reason": "No brand similarity detected"}
# ── AlienVault OTX ────────────────────────────────────────────────
async def check_url_alienvault(url: str) -> dict:
    from urllib.parse import quote
    endpoint = f"https://otx.alienvault.com/api/v1/indicators/url/{quote(url, safe='')}/general"
    headers = {"X-OTX-API-KEY": ALIENVAULT_API_KEY}
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(endpoint, headers=headers)
        if r.status_code == 200:
            data = r.json()
            pulse_count = data.get("pulse_info", {}).get("count", 0)
            return {
                "source": "alienvault",
                "target": url,
                "pulse_count": pulse_count,
                "verdict": "PHISHING" if pulse_count > 0 else "SAFE"
            }
    except Exception as e:
        logger.error(f"AlienVault check failed: {e}")
    return {"source": "alienvault", "target": url, "verdict": "UNKNOWN"}

async def check_domain_alienvault(domain: str) -> dict:
    endpoint = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
    headers = {"X-OTX-API-KEY": ALIENVAULT_API_KEY}
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(endpoint, headers=headers)
        if r.status_code == 200:
            data = r.json()
            pulse_count = data.get("pulse_info", {}).get("count", 0)
            return {
                "source": "alienvault",
                "target": domain,
                "pulse_count": pulse_count,
                "verdict": "PHISHING" if pulse_count > 0 else "SAFE"
            }
    except Exception as e:
        logger.error(f"AlienVault domain check failed: {e}")
    return {"source": "alienvault", "target": domain, "verdict": "UNKNOWN"}

    # ── Google Safe Browsing ──────────────────────────────────────────

GOOGLE_SAFEBROWSING_API_KEY = os.getenv("GOOGLE_SAFEBROWSING_API_KEY")

async def check_url_safebrowsing(urls: list) -> dict:
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFEBROWSING_API_KEY}"
    payload = {
        "client": {"clientId": "devdesperate", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in urls]
        }
    }
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.post(endpoint, json=payload)
        if r.status_code == 200:
            matches = r.json().get("matches", [])
            if matches:
                flagged = [m["threat"]["url"] for m in matches]
                return {"source": "safebrowsing", "verdict": "PHISHING", "flagged_urls": flagged}
            return {"source": "safebrowsing", "verdict": "SAFE"}
    except Exception as e:
        logger.error(f"Safe Browsing check failed: {e}")
    return {"source": "safebrowsing", "verdict": "UNKNOWN"}