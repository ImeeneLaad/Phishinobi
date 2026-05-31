#  Real-Time Phishing URL Detection System
### Step 1 — Core Detection Engine (Lexical ML Classifier)

---

## Project Overview

This is **Step 1** of a full phishing detection system. We build a Python-based
URL classifier using lexical feature extraction + Random Forest. No deep learning,
no browser extension yet — just a solid, explainable ML pipeline.

---

## Folder Structure

```
phishing_detector/
├── data/                    # Raw and processed datasets
│   └── urls.csv             # Dataset (phishing + legitimate URLs)
├── models/                  # Saved trained models
│   └── phishing_model.pkl
├── src/                     # Core source code (modular)
│   ├── __init__.py
│   ├── features.py          # Feature extraction logic
│   ├── train.py             # Model training pipeline
│   ├── evaluate.py          # Evaluation utilities
│   └── predict.py           # predict_url() inference function
├── notebooks/               # Jupyter exploration notebooks
│   └── 01_exploration.ipynb
├── tests/                   # Unit tests
│   └── test_features.py
├── reports/                 # Auto-generated evaluation reports
├── requirements.txt
├── main.py                  # Entry point: train + evaluate + demo
└── README.md
```

---

## Quickstart

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Download dataset (see data/README or instructions below)

# 3. Train the model
python main.py --mode train

# 4. Predict a URL
python main.py --mode predict --url "http://paypal-login.suspicious-site.com/verify"
```

---

## Recommended Datasets

| Dataset | Source | Notes |
|---|---|---|
| **PhiUSIIL** | UCI ML Repository | 235k URLs, rich features |
| **PhishTank** | phishtank.com | Live + historical phishing URLs |
| **ISCX-URL-2016** | UNB | Balanced, labeled dataset |
| **Kaggle Phishing URLs** | kaggle.com | Easy download, CSV format |

For quickstart: use the **Kaggle Phishing URLs** dataset.
Download `phishing_site_urls.csv` and place it in `data/`.

---

## Features Extracted (Lexical)

| Feature | Description |
|---|---|
| `url_length` | Total character length of URL |
| `num_dots` | Count of `.` characters |
| `num_hyphens` | Count of `-` characters |
| `num_at` | Presence of `@` symbol |
| `num_slash` | Count of `/` characters |
| `num_subdomains` | Number of subdomain levels |
| `has_ip` | IP address used instead of domain |
| `has_https` | Whether URL uses HTTPS |
| `has_suspicious_keywords` | Keywords like login, verify, secure, etc. |
| `num_special_chars` | Count of special characters |
| `domain_length` | Length of domain only |
| `path_length` | Length of URL path |
| `has_port` | Non-standard port in URL |
| `digit_ratio` | Ratio of digits in URL |

---

## Model Performance (Expected)

| Metric | Score |
|---|---|
| Accuracy | ~95–97% |
| Precision | ~95–98% |
| Recall | ~94–96% |
| F1 Score | ~95–97% |

---

## Step Roadmap

- [x] Step 1 — Core ML detection engine (this repo)
- [x] Step 2 — WHOIS + DNS enrichment layer (`src/enrichment.py`)
- [x] Step 3 — REST API wrapper (FastAPI) (`api/`)
- [ ] Step 4 — Chrome Extension integration
- [ ] Step 5 — Real-time feed + retraining pipeline

---

## Step 2 — Live Enrichment (WHOIS + DNS)

`src/enrichment.py` adds two live network signals that run *after* the ML model
(the model itself is unchanged):

- **Domain age (WHOIS):** brand-new domains are a top phishing signal.
- **DNS resolution:** a link whose domain doesn't resolve is a red flag.

These adjust the risk score and add human-readable reasons. It's **opt-in** via
`predict_url(url, enrich=True)` so the core detector stays fast & offline by
default. Lookups are cached (1h) and have hard timeouts so they never hang.

## Step 3 — REST API (FastAPI)

```bash
# install (includes Step 2 + 3 deps)
pip install -r requirements.txt

# run from the project root
python -m uvicorn api.main:app --reload --port 8000
```

- Interactive docs: http://127.0.0.1:8000/docs
- `GET  /health`  → liveness + whether the model loaded
- `POST /predict` → body `{"url": "...", "enrich": true}` (enrich defaults true)

```bash
curl -X POST http://127.0.0.1:8000/predict \
  -H "Content-Type: application/json" \
  -d '{"url":"http://paypal-login.tk/verify","enrich":true}'
```

The model loads once at startup. CORS is open for local dev — **lock it to your
extension's origin before deploying.**
