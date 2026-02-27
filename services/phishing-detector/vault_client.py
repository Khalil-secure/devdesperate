import hvac
import os
import logging

logger = logging.getLogger(__name__)

VAULT_ADDR = os.getenv("VAULT_ADDR", "http://vault:8200")
VAULT_TOKEN = os.getenv("VAULT_TOKEN")

def get_secrets() -> dict:
    try:
        client = hvac.Client(url=VAULT_ADDR, token=VAULT_TOKEN)
        secret = client.read("mailguard/api-keys")
        if secret and "data" in secret:
            logger.info("✅ Secrets loaded from Vault")
            return secret["data"]
    except Exception as e:
        logger.warning(f"⚠️ Vault unavailable, falling back to env vars: {e}")
    
    # Fallback to .env if Vault is unreachable
    return {
        "VIRUSTOTAL_API_KEY": os.getenv("VIRUSTOTAL_API_KEY"),
        "ABUSEIPDB_API_KEY": os.getenv("ABUSEIPDB_API_KEY"),
        "ALIENVAULT_API_KEY": os.getenv("ALIENVAULT_API_KEY"),
        "GOOGLE_SAFEBROWSING_API_KEY": os.getenv("GOOGLE_SAFEBROWSING_API_KEY"),
        "HUGGINGFACE_API_KEY": os.getenv("HUGGINGFACE_API_KEY"),
        "JWT_SECRET": os.getenv("JWT_SECRET"),
    }
