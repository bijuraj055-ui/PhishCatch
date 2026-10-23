# 🛡️ Phishing Link Detector

A lightweight, browser-based phishing URL analyser built with **Python** and **Streamlit**.  
Paste any URL and get an instant risk score with a detailed breakdown of suspicious indicators — no external API keys required.

---

## 🚀 Live Demo 

Run it locally in seconds (see [Quick Start](#quick-start) below).  
Deploy to the cloud for free via [Streamlit Community Cloud](https://streamlit.io/cloud).

---

## ✨ Features

| Category | What it checks |
|---|---|
| **Structure** | IP address used instead of domain, excessive dots, deep subdomains, non-standard port |
| **Security** | HTTPS presence, SSL certificate validity & issuer (deep-check mode) |
| **Obfuscation** | `@` symbol in URL, double-slash redirects, URL-encoded (hex) characters |
| **Content** | Suspicious keywords (login, verify, paypal, etc.), high digit ratio in hostname |
| **Brand abuse** | Known brand name appearing in hostname of a non-official domain |
| **Shorteners** | Detection of 10+ known URL shortening services + optional redirect resolution |
| **TLD analysis** | Flags uncommon / high-risk top-level domains |

### Risk Scoring

Every indicator adds a weighted penalty. The final **0–100 risk score** maps to three verdicts:

| Score | Verdict |
|---|---|
| 0 – 39 | ✅ Low Risk — Likely Safe |
| 40 – 69 | ⚠️ Medium Risk — Suspicious |
| 70 – 100 | ⛔ High Risk — Likely Phishing |

---

## 🗂️ Project Structure

```
phishing-link-detector/
├── app.py            # Main Streamlit application
├── requirements.txt  # Python dependencies
└── README.md         # This file
```

---

## ⚙️ Quick Start

### Prerequisites

- Python **3.9 or later**
- `pip`

### 1 — Clone the repository

```bash
git clone https://github.com/bijuraj055-ui/phishing-link-detector.git
cd phishing-link-detector
```

### 2 — Install dependencies

```bash
pip install -r requirements.txt
```

### 3 — Run the app

```bash
streamlit run app.py
```

The app opens automatically in your default browser at `http://localhost:8501`.

---

## 🌐 Deploy to Streamlit Community Cloud (free)

1. Push this repo to your GitHub account.
2. Go to [share.streamlit.io](https://share.streamlit.io) and sign in with GitHub.
3. Click **New app**, select your repo, set the main file to `app.py`, and click **Deploy**.

Your public URL will be live within a minute.

---

## 🔬 How It Works

```
User pastes URL
      │
      ▼
 normalize_url()   — ensures scheme is present
      │
      ▼
 extract_features() — parses 15+ structural & lexical features
      │
      ▼
 score_url()        — adds weighted penalties for each suspicious feature
      │
      ▼
 verdict()          — maps score to Low / Medium / High risk
      │
      ▼
 Streamlit UI       — renders banner, progress bar, findings, feature table
```

Optional **deep check** mode additionally:
- Resolves shortener URLs to their real destination via HTTP HEAD redirect.
- Connects to the host on port 443 and reads the SSL certificate (issuer, expiry).

---

## 🛠️ Configuration

No configuration files are needed.  
All scoring weights and keyword lists live at the top of [`app.py`](app.py) and can be tuned directly:

```python
SUSPICIOUS_KEYWORDS = ["login", "verify", "paypal", ...]   # line ~17
# Adjust score += N values inside score_url() to change weights
```

---

## ⚠️ Disclaimer

This tool performs **static heuristic analysis only**.  
It does **not** query live threat-intelligence databases (VirusTotal, Google Safe Browsing, etc.) and should **not** be used as the sole security decision-making tool.  
Always confirm suspicious links with professional security platforms before clicking.

---

## 📄 License

MIT — free to use, modify, and distribute.
