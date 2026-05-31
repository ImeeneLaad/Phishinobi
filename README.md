# 🥷 Phishinobi — Real-Time Phishing Detection System

Phishinobi is a machine learning-powered phishing detection platform designed to identify malicious URLs before users interact with them.

The project combines lexical URL analysis, machine learning classification, and live domain intelligence to provide fast and explainable phishing detection.

---

## Key Features

### Machine Learning Detection

* Random Forest classifier trained on phishing and legitimate URLs
* Lexical feature extraction from raw URLs
* Explainable predictions based on URL characteristics
* Fast offline inference

### Live Threat Intelligence

* WHOIS domain age analysis
* DNS resolution verification
* Risk score enrichment
* Human-readable threat explanations

### REST API

* FastAPI backend
* JSON-based prediction endpoint
* Interactive Swagger documentation
* Easy integration with browser extensions or security tools

---

## Architecture

```text
User URL
    │
    ▼
Feature Extraction
    │
    ▼
Random Forest Model
    │
    ▼
Initial Risk Score
    │
    ▼
WHOIS + DNS Enrichment
    │
    ▼
Final Verdict
```

---

## Project Structure

```text
phishinobi/
│
├── api/
│   └── main.py
│
├── data/
│   └── urls.csv
│
├── models/
│   └── phishing_model.pkl
│
├── src/
│   ├── features.py
│   ├── train.py
│   ├── evaluate.py
│   ├── predict.py
│   └── enrichment.py
│
├── reports/
├── tests/
├── notebooks/
│
├── requirements.txt
├── main.py
└── README.md
```

---

## Detection Features

Phishinobi analyzes multiple URL characteristics commonly associated with phishing campaigns:

| Feature Category      | Examples                             |
| --------------------- | ------------------------------------ |
| URL Structure         | Length, dots, slashes, subdomains    |
| Domain Analysis       | Domain length, IP-based domains      |
| Security Signals      | HTTPS usage, non-standard ports      |
| Suspicious Indicators | login, verify, secure, update        |
| Statistical Features  | Digit ratio, special character ratio |

---

## Performance

| Metric    | Typical Score |
| --------- | ------------- |
| Accuracy  | 95–97%        |
| Precision | 95–98%        |
| Recall    | 94–96%        |
| F1 Score  | 95–97%        |

*Results depend on the dataset used and training configuration.*

---

## Quick Start

### Installation

```bash
git clone <repository-url>
cd phishinobi

pip install -r requirements.txt
```

### Train Model

```bash
python main.py --mode train
```

### Predict URL

```bash
python main.py --mode predict \
--url "http://paypal-login.suspicious-site.com/verify"
```

---

## API Usage

Run the API:

```bash
python -m uvicorn api.main:app --reload --port 8000
```

Swagger Documentation:

```text
http://127.0.0.1:8000/docs
```

Example Request:

```bash
curl -X POST http://127.0.0.1:8000/predict \
-H "Content-Type: application/json" \
-d '{"url":"http://paypal-login.tk/verify","enrich":true}'
```

---



## Disclaimer

Phishinobi is intended for educational, research, and defensive cybersecurity purposes. Detection results should not be considered a substitute for professional security analysis.

---

Built with Python, Scikit-Learn, FastAPI, and a healthy distrust of suspicious links.
