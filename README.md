# MailGuard 🛡️

> A production-grade cybersecurity SaaS built by a junior dev who refused to give up.

**Live demo:** http://35.241.196.133

---

## What is this?

MailGuard is a microservices-based email phishing detection platform. You paste any suspicious email, and the system cross-references it against 5 global threat intelligence databases in real time, returning a clear verdict: **SAFE**, **SUSPICIOUS**, or **PHISHING**.

Built from scratch with Python, Node.js, Docker, and deployed on Google Cloud — this is both a portfolio project and a real, usable security tool.

---

## Architecture

```
Browser (Nginx :80)
        │
        ▼
API Gateway (Node.js/Express :3000)
        │                    │
        ▼                    ▼
AI Service            Phishing Detector
(FastAPI :8000)       (FastAPI :8001 + SMTP :1025)
                             │
                    ┌────────┼────────┬──────────┐
                    ▼        ▼        ▼          ▼
               VirusTotal  AlienVault  AbuseIPDB  Google
                  OTX                            SafeBrowsing
                             │
                    Typosquatting Engine (local)
                    SPF / DMARC DNS checks (local)
```

### Services

| Service | Stack | Port | Role |
|---|---|---|---|
| `gateway` | Node.js / Express | 3000 | Single entry point, routes all requests |
| `ai-service` | Python / FastAPI | 8000 | AI microservices (summarizer, etc.) |
| `phishing-detector` | Python / FastAPI + aiosmtpd | 8001 / 1025 | Email threat analysis engine |

---

## Features

### Phishing Detector
- **URL scanning** via VirusTotal (70+ antivirus engines) and AlienVault OTX
- **Domain reputation** check via VirusTotal and AlienVault
- **IP reputation** check via AbuseIPDB
- **Google Safe Browsing** URL threat check
- **Typosquatting detection** — catches `paypa1.com → paypal.com` style attacks using Levenshtein distance against 25+ known brands
- **SPF / DMARC validation** — DNS-level sender domain checks
- **SMTP server** — receives real emails on port 1025 for gateway-mode deployment
- **REST API** — `POST /analyze` accepts raw email data, returns structured JSON verdict
- **Auto-parsed email input** — paste a raw email, headers are extracted automatically

### AI Service
- **Text summarizer** — powered by HuggingFace Inference API (`facebook/bart-large-cnn`)
- Auto-generated Swagger docs at `/docs`

### API Gateway
- Single entry point for all services
- Manual proxy with 120s timeout for slow AI/threat API responses
- CORS enabled
- Nginx reverse proxy on port 80 for clean browser access

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend services | Python 3.11, FastAPI, uvicorn |
| Gateway | Node.js 20, Express |
| SMTP server | aiosmtpd |
| HTTP client | httpx (async), axios |
| DNS checks | dnspython |
| Containerization | Docker, Docker Compose |
| Reverse proxy | Nginx |
| Cloud | Google Cloud Compute Engine (e2-medium, Ubuntu 22.04) |
| Threat APIs | VirusTotal, AlienVault OTX, AbuseIPDB, Google Safe Browsing |

---

## Project Structure

```
MailGuard/
├── docker-compose.yml
├── .env.example
├── .gitignore
├── frontend/
│   └── index.html              # Single-page UI
└── services/
    ├── gateway/
    │   ├── index.js            # Express gateway + proxy
    │   ├── auth.js             # JWT auth (in progress)
    │   ├── package.json
    │   └── Dockerfile
    ├── ai-service/
    │   ├── main.py             # FastAPI app
    │   ├── requirements.txt
    │   └── Dockerfile
    └── phishing-detector/
        ├── smtp_server.py      # SMTP receiver + orchestrator
        ├── api.py              # FastAPI REST endpoint
        ├── checks.py           # All threat intelligence checks
        ├── requirements.txt
        └── Dockerfile
```

---

## Getting Started

### Prerequisites
- Docker Desktop
- Git
- API keys (see below)

### 1. Clone the repo

```bash
git clone https://github.com/YOUR_USERNAME/MailGuard.git
cd MailGuard
```

### 2. Set up environment variables

```bash
cp .env.example .env
```

Edit `.env` and fill in your API keys:

```env
HUGGINGFACE_API_KEY=hf_...
VIRUSTOTAL_API_KEY=...
ABUSEIPDB_API_KEY=...
GOOGLE_SAFEBROWSING_API_KEY=...
ALIENVAULT_API_KEY=...
JWT_SECRET=your_random_secret_here
```

### 3. Run locally

```bash
docker compose up
```

| Service | URL |
|---|---|
| Frontend | http://localhost (via Nginx) |
| Gateway | http://localhost:3000 |
| AI Service docs | http://localhost:8000/docs |
| Phishing Detector docs | http://localhost:8001/docs |

---

## API Reference

### Phishing Analysis

```
POST /phishing/analyze
```

**Request:**
```json
{
  "sender": "security@paypa1.com",
  "subject": "Urgent: Verify your account",
  "body": "Click here: http://suspicious-link.ru/login"
}
```

**Response:**
```json
{
  "verdict": "PHISHING",
  "checks": [
    {
      "verdict": "PHISHING",
      "reason": "'paypa1.com' looks like 'paypal.com' (distance: 1)"
    },
    {
      "source": "virustotal",
      "target": "http://suspicious-link.ru/login",
      "malicious": 10,
      "suspicious": 1,
      "verdict": "PHISHING"
    }
  ],
  "sender_domain": "paypa1.com",
  "dns_checks": { "spf": true, "dmarc": false },
  "urls": ["http://suspicious-link.ru/login"],
  "domains": ["suspicious-link.ru"],
  "ips": [],
  "analyzed_at": "2026-02-26T00:00:00.000000"
}
```

**Verdict logic:**
- Any single `PHISHING` signal → `PHISHING`
- 2+ `SUSPICIOUS` signals → `SUSPICIOUS`
- All clear → `SAFE`

### AI Summarizer

```
POST /ai/summarize
```

**Request:**
```json
{
  "text": "Long article or document text here..."
}
```

---

## Deployment (Google Cloud)

```bash
# Create VM
gcloud compute instances create MailGuard \
  --machine-type=e2-medium \
  --image-family=ubuntu-2204-lts \
  --image-project=ubuntu-os-cloud \
  --boot-disk-size=30GB \
  --tags=http-server,https-server \
  --zone=europe-west1-b

# SSH in
gcloud compute ssh MailGuard --zone=europe-west1-b

# Install Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker
sudo apt-get install -y docker-compose-plugin

# Clone and run
git clone https://github.com/YOUR_USERNAME/MailGuard.git
cd MailGuard
cp .env.example .env
nano .env  # fill in your keys
docker compose up -d

# Install and configure Nginx
sudo apt-get install -y nginx
sudo cp frontend/index.html /var/www/html/index.html
# Configure /etc/nginx/sites-available/default to proxy /api/ to localhost:3000
sudo systemctl restart nginx
```

---

## API Keys — Where to Get Them

| Service | Free Tier | Link |
|---|---|---|
| VirusTotal | 500 req/day | https://virustotal.com |
| AbuseIPDB | 1000 req/day | https://abuseipdb.com |
| AlienVault OTX | Unlimited | https://otx.alienvault.com |
| Google Safe Browsing | Free | https://developers.google.com/safe-browsing |
| HuggingFace | Free tier | https://huggingface.co |

---

## Roadmap

- [ ] JWT authentication — lock API behind user accounts
- [ ] File / attachment scanning via VirusTotal hash lookup
- [ ] Macro detection in Office files (oletools)
- [ ] Stripe integration — usage-based billing
- [ ] Admin dashboard — scan history, user management
- [ ] Domain name + HTTPS (Let's Encrypt)
- [ ] Telegram / WhatsApp bot integration
- [ ] Gmail plugin

---

## The Story

This project was built in a single session, layer by layer, with zero shortcuts. Every service was verified working before the next was built. Every problem was debugged in production. The "junior dev desperate for a job" is the author — and this is the proof of work.

If you're hiring, you just watched the whole process. Here's the repo.

---

## License

MIT

