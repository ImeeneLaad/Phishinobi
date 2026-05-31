"""
data/download_dataset.py
------------------------
Helper script to download and prepare a phishing URL dataset.

This script creates a SAMPLE synthetic dataset for immediate testing.
For production, replace it with a real dataset (see instructions below).

RECOMMENDED REAL DATASETS:
===========================

1. Kaggle — Phishing Site URLs (easiest):
   URL: https://www.kaggle.com/datasets/taruntiwarihp/phishing-site-urls
   File: phishing_site_urls.csv
   Columns: URL, Label ('phishing'/'legitimate')
   Size: ~549,000 URLs

2. PhiUSIIL Phishing URL Dataset (most comprehensive):
   URL: https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset
   Size: 235,795 URLs

3. PhishTank (raw phishing URLs):
   URL: https://www.phishtank.com/developer_info.php
   Note: Phishing only — you'll need to combine with legit URLs

4. ISCX-URL-2016 (academic, balanced):
   Search: "ISCX URL 2016 dataset" on GitHub

HOW TO USE KAGGLE DATASET:
===========================
1. pip install kaggle
2. kaggle datasets download taruntiwarihp/phishing-site-urls
3. unzip phishing-site-urls.zip -d data/
4. mv data/phishing_site_urls.csv data/urls.csv
5. python main.py --mode train

"""

import os
import csv
import random
import sys


def create_sample_dataset(output_path: str = "data/urls.csv", n_samples: int = 2000):
    """
    Creates a small synthetic dataset for pipeline testing.

    ⚠️  WARNING: This is for TESTING THE PIPELINE ONLY.
    DO NOT use this synthetic data to train a production model.
    Download a real dataset (see instructions above) for real training.

    The synthetic data is generated based on known phishing patterns
    and is good enough to verify the full pipeline works end-to-end.
    """

    print(f"Creating synthetic sample dataset at: {output_path}")
    print("⚠️  This is for pipeline testing only! Use a real dataset for production.\n")

    # Legitimate URL templates
    safe_domains = [
        "google.com", "github.com", "stackoverflow.com", "wikipedia.org",
        "amazon.com", "youtube.com", "twitter.com", "linkedin.com",
        "microsoft.com", "apple.com", "reddit.com", "facebook.com",
        "netflix.com", "spotify.com", "dropbox.com", "slack.com",
    ]
    safe_paths = [
        "/", "/search", "/about", "/products", "/docs", "/help",
        "/news", "/blog", "/login", "/signup", "/profile", "/settings",
        "/api/v1/users", "/en/articles/how-to", "/downloads",
    ]

    # Phishing URL templates
    phishing_patterns = [
        "http://{brand}-secure-login.{tld}/verify-account",
        "http://{brand}-account-update.{tld}/signin.php",
        "http://192.168.{a}.{b}/admin/login.php",
        "http://10.{a}.{b}.{c}/phishing/form.html",
        "http://secure-{brand}-verify.{tld}/update?user=victim@email.com",
        "http://{brand}.verify-now.{tld}/urgent-action",
        "http://login-{brand}-support.{tld}/confirm",
        "http://www.{brand}-suspended.{tld}/restore-access",
        "http://account-{brand}-validation.{tld}/check",
        "http://{random_sub}.{brand}.{tld}/login.php?token={token}",
    ]

    phishing_brands = [
        "paypal", "amazon", "ebay", "apple", "microsoft", "google",
        "facebook", "netflix", "wellsfargo", "chase", "bankofamerica",
        "instagram", "twitter", "linkedin", "dropbox",
    ]

    phishing_tlds = ["tk", "ml", "ga", "cf", "xyz", "top", "club", "online"]

    rows = []
    half = n_samples // 2

    # Generate safe URLs
    for _ in range(half):
        domain = random.choice(safe_domains)
        path   = random.choice(safe_paths)
        scheme = "https" if random.random() > 0.05 else "http"
        url    = f"{scheme}://www.{domain}{path}"
        rows.append({"url": url, "label": "legitimate"})

    # Generate phishing URLs
    for _ in range(half):
        pattern = random.choice(phishing_patterns)
        brand   = random.choice(phishing_brands)
        tld     = random.choice(phishing_tlds)
        token   = "".join(random.choices("abcdef0123456789", k=16))

        url = pattern.format(
            brand=brand, tld=tld,
            a=random.randint(0, 255),
            b=random.randint(0, 255),
            c=random.randint(0, 255),
            random_sub=f"sub{random.randint(1,9)}",
            token=token,
        )
        rows.append({"url": url, "label": "phishing"})

    # Shuffle
    random.shuffle(rows)

    # Write CSV
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["url", "label"])
        writer.writeheader()
        writer.writerows(rows)

    phishing_count = sum(1 for r in rows if r["label"] == "phishing")
    legit_count    = sum(1 for r in rows if r["label"] == "legitimate")

    print(f"✅ Synthetic dataset created: {output_path}")
    print(f"   Total URLs : {len(rows):,}")
    print(f"   Phishing   : {phishing_count:,}")
    print(f"   Legitimate : {legit_count:,}")
    print("\n⚠️  Replace with a real dataset before training a production model!")


if __name__ == "__main__":
    output = sys.argv[1] if len(sys.argv) > 1 else "data/urls.csv"
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 2000
    create_sample_dataset(output, n)
