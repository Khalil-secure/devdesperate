import asyncio
from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
import re
import dns.resolver
import logging

from checks import (
    check_url_virustotal, check_domain_virustotal,
    check_ip_abuseipdb, compute_verdict, check_typosquatting,
    check_url_alienvault, check_domain_alienvault, check_url_safebrowsing
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="DevDesperate Phishing Detector API")

URL_REGEX = re.compile(r'https?://[^\s<>"\']+')
IP_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

def extract_urls(text): return list(set(URL_REGEX.findall(text)))
def extract_ips(text): return list(set(IP_REGEX.findall(text)))
def extract_domains(urls):
    domains = []
    for url in urls:
        match = re.search(r'https?://([^/\s]+)', url)
        if match: domains.append(match.group(1))
    return list(set(domains))
def extract_sender_domain(sender):
    match = re.search(r'@([\w\.-]+)', sender)
    return match.group(1) if match else None

def check_spf_dmarc(domain):
    results = {"spf": False, "dmarc": False}
    try:
        for r in dns.resolver.resolve(domain, 'TXT'):
            if 'v=spf1' in str(r): results["spf"] = True
    except: pass
    try:
        for r in dns.resolver.resolve(f'_dmarc.{domain}', 'TXT'):
            if 'v=DMARC1' in str(r): results["dmarc"] = True
    except: pass
    return results

class AnalyzeRequest(BaseModel):
    sender: str
    subject: Optional[str] = ""
    body: Optional[str] = ""

class AnalyzeResponse(BaseModel):
    verdict: str
    checks: list
    sender_domain: Optional[str]
    dns_checks: dict
    urls: list
    domains: list
    ips: list
    analyzed_at: str

@app.get("/health")
def health():
    return {"status": "ok", "service": "phishing-detector"}

@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze(request: AnalyzeRequest):
    urls = extract_urls(request.body)
    ips = extract_ips(request.body)
    domains = extract_domains(urls)
    sender_domain = extract_sender_domain(request.sender)
    dns_checks = check_spf_dmarc(sender_domain) if sender_domain else {}

    check_results = []

    # Typosquatting
    typosquat = check_typosquatting(sender_domain)
    check_results.append(typosquat)

    # URL + domain checks
    url_tasks = [check_url_virustotal(u) for u in urls] + [check_url_alienvault(u) for u in urls]
    domain_tasks = [check_domain_virustotal(d) for d in domains] + [check_domain_alienvault(d) for d in domains]
    ip_tasks = [check_ip_abuseipdb(ip) for ip in ips]

    results = await asyncio.gather(*url_tasks, *domain_tasks, *ip_tasks)
    check_results.extend(results)

    # Safe Browsing
    if urls:
        sb = await check_url_safebrowsing(urls)
        check_results.append(sb)

    verdict = compute_verdict(check_results)

    return AnalyzeResponse(
        verdict=verdict,
        checks=check_results,
        sender_domain=sender_domain,
        dns_checks=dns_checks,
        urls=urls,
        domains=domains,
        ips=ips,
        analyzed_at=datetime.utcnow().isoformat()
    )