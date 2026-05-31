"""
src/predict.py
--------------
Inference module — the final product of Step 1.

Exposes:
    predict_url(url)  →  dict with label, confidence, and reasons

This is the function that will later be called by:
  - A FastAPI endpoint (Step 3)
  - The Chrome Extension backend (Step 4)
  - Any Python script or CLI

Design principle: fast, self-contained, no I/O at runtime.
"""

import os
import sys
import time
import joblib

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from src.features import extract_features, FEATURE_NAMES

DEFAULT_MODEL_PATH = "models/phishing_model.pkl"

# Cached model reference (loaded once, reused across calls)
_MODEL = None


# ---------------------------------------------------------------------------
# Model Loading
# ---------------------------------------------------------------------------

def get_model(model_path: str = DEFAULT_MODEL_PATH):
    """
    Load model once and cache it in memory.
    Subsequent calls return the cached instance.
    """
    global _MODEL
    if _MODEL is None:
        if not os.path.exists(model_path):
            raise FileNotFoundError(
                f"No model found at '{model_path}'.\n"
                "Run training first:  python main.py --mode train"
            )
        _MODEL = joblib.load(model_path)
    return _MODEL


# ---------------------------------------------------------------------------
# Reason Generator
# ---------------------------------------------------------------------------

# Thresholds and signals that trigger human-readable reasons
# Format: (feature_name, condition_fn, reason_string)
REASON_RULES = [
    ("brand_similarity",        lambda v: v == 1,    "Domain closely mimics a well-known brand (likely typo-squatting)"),
    ("has_homograph",           lambda v: v == 1,    "Contains look-alike characters impersonating a real domain (homograph attack)"),
    ("has_non_ascii",           lambda v: v == 1,    "Domain contains non-standard (non-ASCII) characters"),
    ("has_ip",                  lambda v: v == 1,    "Uses raw IP address instead of domain name"),
    ("has_https",               lambda v: v == 0,    "No HTTPS — connection is not encrypted"),
    ("has_suspicious_keyword",  lambda v: v == 1,    "Contains suspicious keywords (login/verify/secure/etc.)"),
    ("num_suspicious_keywords", lambda v: v >= 2,    "Multiple suspicious keywords detected"),
    ("has_suspicious_tld",      lambda v: v == 1,    "Uses a TLD commonly associated with phishing (.tk/.ml/.xyz/etc.)"),
    ("num_subdomains",          lambda v: v >= 3,    f"Excessive subdomains ({'{v}'} levels) — possible domain spoofing"),
    ("url_length",              lambda v: v > 100,   "Unusually long URL (>100 chars) — common obfuscation tactic"),
    ("num_hyphens",             lambda v: v >= 3,    "Multiple hyphens — often used to mimic legitimate domains"),
    ("num_dots",                lambda v: v >= 5,    "Many dots in URL — possible subdomain stacking"),
    ("num_at",                  lambda v: v == 1,    "Contains '@' symbol — browser redirects to post-@ content"),
    ("has_port",                lambda v: v == 1,    "Non-standard port number detected"),
    ("digit_ratio",             lambda v: v > 0.3,   "High ratio of digits in URL — suspicious randomness"),
    ("has_double_slash",        lambda v: v == 1,    "Double slash (//) in path — possible redirect abuse"),
    ("domain_length",           lambda v: v > 30,    "Very long domain name — often seen in phishing domains"),
    ("query_length",            lambda v: v > 50,    "Long query string — may contain hidden parameters"),
]


def _risk_level_from_score(score: int) -> str:
    """Map a 0-100 risk score to a human label. Single source of truth."""
    if score < 30:
        return "LOW"
    elif score < 60:
        return "MEDIUM"
    elif score < 85:
        return "HIGH"
    else:
        return "CRITICAL"


def generate_reasons(features: dict) -> list:
    """
    Return a list of human-readable strings explaining why a URL is suspicious.
    Only includes reasons where the threshold is triggered.
    """
    reasons = []
    for feat_name, condition, reason_template in REASON_RULES:
        value = features.get(feat_name, 0)
        if condition(value):
            # Fill in the {v} placeholder if present
            reason = reason_template.replace("{v}", str(value))
            reasons.append(reason)
    return reasons


# ---------------------------------------------------------------------------
# Core predict_url Function
# ---------------------------------------------------------------------------

def predict_url(url: str, model_path: str = DEFAULT_MODEL_PATH,
                enrich: bool = False) -> dict:
    """
    Analyze a single URL and return a phishing risk assessment.

    Parameters
    ----------
    url         : str  — the URL to analyze
    model_path  : str  — path to the trained .pkl model file
    enrich      : bool — if True, also run live WHOIS/DNS lookups (Step 2)
                         and fold their signals into the risk score. This makes
                         a network call (slower, ~0.3–5s), so it's OFF by
                         default to keep the core predictor fast and offline.

    Returns
    -------
    dict with the following keys:
        url          : str   — input URL (echoed back)
        label        : str   — "PHISHING" or "SAFE"
        is_phishing  : bool  — True if predicted phishing
        confidence   : float — model's confidence (0.0–1.0), from the ML model
        risk_score   : int   — 0–100 risk score (combined if enriched)
        risk_level   : str   — "LOW" / "MEDIUM" / "HIGH" / "CRITICAL"
        reasons      : list  — human-readable reasons for the prediction
        features     : dict  — raw extracted features
        inference_ms : float — time taken for inference in milliseconds
        enrichment   : dict  — (only if enrich=True) the WHOIS/DNS findings

    Example
    -------
    >>> result = predict_url("http://paypal-login.tk/verify?user=abc")
    >>> print(result['label'], result['confidence'])
    PHISHING 0.97
    """
    start = time.perf_counter()

    # ── NORMALIZE URL (must match training preprocessing) ──
    url = url.lower().strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    # 1. Extract features
    features = extract_features(url)

    # 2. Prepare input for sklearn
    import pandas as pd
    X = pd.DataFrame([features], columns=FEATURE_NAMES)

    # 3. Load model (cached after first call)
    model = get_model(model_path)

    # 4. Predict using standard 0.50 threshold
    PHISHING_THRESHOLD = 0.50
    probabilities = model.predict_proba(X)[0]    # [p_safe, p_phishing]
    confidence    = float(probabilities[1])
    prediction    = 1 if confidence >= PHISHING_THRESHOLD else 0

    # 5. Derive risk score + level from the model
    risk_score = int(confidence * 100)
    risk_level = _risk_level_from_score(risk_score)

    # 6. Generate human-readable reasons
    reasons = generate_reasons(features)

    # 7. (Step 2) Optional live enrichment — fold WHOIS/DNS signals in.
    #    We adjust the risk SCORE (not the model's raw confidence), then
    #    recompute the level/verdict from the combined score. This lets a
    #    brand-new or non-resolving domain raise the alarm even when the
    #    lexical model alone was unsure.
    enrichment = None
    if enrich:
        from src.enrichment import enrich_url
        enrichment = enrich_url(url)
        enrichment["base_risk_score"] = risk_score          # before the boost
        risk_score = max(0, min(100, risk_score + enrichment["risk_boost"]))
        enrichment["combined_risk_score"] = risk_score
        risk_level = _risk_level_from_score(risk_score)
        reasons = reasons + enrichment["reasons"]
        # Re-derive the verdict from the combined score (threshold 50/100).
        prediction = 1 if risk_score >= 50 else 0

    # 8. Timing
    inference_ms = (time.perf_counter() - start) * 1000

    result = {
        "url":          url,
        "label":        "PHISHING" if prediction == 1 else "SAFE",
        "is_phishing":  bool(prediction == 1),
        "confidence":   round(confidence, 4),
        "risk_score":   risk_score,
        "risk_level":   risk_level,
        "reasons":      reasons,
        "features":     features,
        "inference_ms": round(inference_ms, 3),
    }
    if enrichment is not None:
        result["enrichment"] = enrichment
    return result


def predict_urls_batch(urls: list, model_path: str = DEFAULT_MODEL_PATH) -> list:
    """
    Analyze a list of URLs. More efficient than calling predict_url() in a loop
    because it batches the sklearn inference call.

    Returns a list of result dicts (same format as predict_url).
    """
    import pandas as pd

    start = time.perf_counter()
    model = get_model(model_path)

    # Normalize all URLs to match training preprocessing
    urls = [u.lower().strip() for u in urls]
    urls = [u if u.startswith(("http://", "https://")) else "http://" + u for u in urls]

    # Extract features for all URLs at once
    all_features = [extract_features(url) for url in urls]
    X = pd.DataFrame(all_features, columns=FEATURE_NAMES)

    PHISHING_THRESHOLD = 0.50
    probabilities = model.predict_proba(X)[:, 1]
    predictions   = (probabilities >= PHISHING_THRESHOLD).astype(int)

    results = []
    for i, url in enumerate(urls):
        confidence = float(probabilities[i])
        risk_score = int(confidence * 100)
        if confidence < 0.3:
            risk_level = "LOW"
        elif confidence < 0.6:
            risk_level = "MEDIUM"
        elif confidence < 0.85:
            risk_level = "HIGH"
        else:
            risk_level = "CRITICAL"

        results.append({
            "url":         url,
            "label":       "PHISHING" if predictions[i] == 1 else "SAFE",
            "is_phishing": bool(predictions[i] == 1),
            "confidence":  round(confidence, 4),
            "risk_score":  risk_score,
            "risk_level":  risk_level,
            "reasons":     generate_reasons(all_features[i]),
            "features":    all_features[i],
        })

    total_ms = (time.perf_counter() - start) * 1000
    print(f"Batch of {len(urls)} URLs analyzed in {total_ms:.1f}ms "
          f"({total_ms/len(urls):.2f}ms/url)")

    return results


# ---------------------------------------------------------------------------
# Pretty Printer
# ---------------------------------------------------------------------------

def print_result(result: dict):
    """Print a formatted, human-readable version of a predict_url() result."""
    label = result["label"]
    icon  = "🚨" if result["is_phishing"] else "✅"

    print("\n" + "─"*55)
    print(f"  {icon}  {label}  —  Risk: {result['risk_level']}  ({result['risk_score']}/100)")
    print(f"  URL:        {result['url'][:70]}{'...' if len(result['url'])>70 else ''}")
    print(f"  Confidence: {result['confidence']:.1%}")
    print(f"  Inference:  {result['inference_ms']}ms")

    if result["reasons"]:
        print("  Reasons:")
        for r in result["reasons"]:
            print(f"    • {r}")
    else:
        print("  Reasons: No suspicious signals detected.")
    print("─"*55)


# ---------------------------------------------------------------------------
# Quick Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    demo_urls = [
        # Clearly safe
        "https://www.github.com/openai/gpt-4",
        "https://stackoverflow.com/questions/python",

        # Clearly phishing
        "http://paypal-secure-verify.login-account.tk/update?user=victim@mail.com",
        "http://192.168.0.1/admin/banking/login.php?redirect=paypal",

        # Edge cases
        "https://accounts.google.com.phishing-test.com/signin",
        "http://amaz0n-support.com/verify-account",
    ]

    print("\n🛡️  PHISHING DETECTOR — DEMO\n")
    for url in demo_urls:
        result = predict_url(url)
        print_result(result)
