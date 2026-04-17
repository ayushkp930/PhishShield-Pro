# PhishShield Pro

PhishShield Pro is an Enterprise CLI phishing detection tool designed for security teams, researchers, and SOC workflows. It performs parallel threat intelligence checks, dual-AI reasoning, offline failover analysis, and executive-grade reporting from a single command-line workflow.

## Key Features

- Async-first scanning engine built with Python `asyncio` + `httpx` for fast concurrent checks
- Dual-AI consensus pipeline using Groq (`llama3-8b-8192`) and Gemini (`gemini-1.5-flash`)
- Zero-day risk-aware logic (unknown intel is not automatically treated as safe)
- Enterprise whitelisting for trusted domains to reduce false positives and preserve API quotas
- Multi-source threat intelligence: VirusTotal, AbuseIPDB, RDAP/WHOIS, URLScan
- Offline dataset failover using local CSV intelligence when APIs are unavailable
- Professional reporting in terminal summary, TXT export, and PDF export

## How It Works (4-Layer Defense Workflow)

1. Input Normalization & Policy Layer
  URL/domain is normalized, base-domain extracted, and global whitelist policy is evaluated.
2. Parallel Intel Collection Layer
  Threat intelligence checks run concurrently across VT, AbuseIPDB, RDAP, URLScan, pattern detection, and offline datasets.
3. AI + Reasoning Layer
  AI verdicting is attempted with Groq/Gemini. If unavailable, a deterministic SOC-style fallback reasoning engine generates structured assessment text.
4. Verdict & Reporting Layer
  Signals are fused into risk scoring and final verdict, then rendered to Executive Summary and optional PDF/TXT reports.

## Setup Instructions

1. Clone the repository.
2. Create and activate a Python virtual environment.
3. Install dependencies.
4. Create your `.env` from `.env.example` and add your API keys.
5. Launch the tool.

```powershell
git clone <your-repo-url>
cd phishing-detector

python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

copy .env.example .env
# Edit .env and add your real keys

.\start_phishshield.bat
```

Alternative direct run:

```powershell
.\.venv\Scripts\python.exe detector.py
```

## Environment Variables

Create a local `.env` file (never commit it) and configure required keys:

- `GROQ_API_KEY`
- `GEMINI_API_KEY`
- `VIRUSTOTAL_API_KEY`
- `ABUSEIPDB_API_KEY`
- `URLSCAN_API_KEY`

## Tech Stack

- Python 3.10+
- Async runtime: `asyncio`, `httpx`
- CLI UX: `colorama`
- Reporting: `fpdf`
- AI Oracles: Groq API, Google GenAI SDK (`google.genai`)
- Threat Intel: VirusTotal v3, AbuseIPDB, RDAP/WHOIS, URLScan
- Offline intelligence: CSV datasets (Kaggle-derived sources)

## Security Notes

- Do not upload your real `.env` file to GitHub.
- Use `.env.example` for public repositories.
- Rotate keys immediately if accidental exposure occurs.

## Disclaimer

This tool is provided for educational, research, and defensive security purposes only. You are responsible for complying with all applicable laws, platform terms, and organizational policies. The authors are not liable for misuse or unauthorized activity.
