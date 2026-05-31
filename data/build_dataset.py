"""
data/build_dataset.py
---------------------
Build a clean, balanced phishing URL dataset from scratch.

This generates ~20,000 high-quality URLs:
  - 10,000 LEGITIMATE URLs (real popular sites with realistic paths)
  - 10,000 PHISHING URLs (using real phishing patterns from PhishTank reports)

Why we build our own:
  - Public datasets often have labeling errors
  - Many lack protocol consistency (https vs http bias)
  - We control quality and balance

Run:
    python data/build_dataset.py
"""

import os
import csv
import random
import string

random.seed(42)  # Reproducible


# ═══════════════════════════════════════════════════════════════════
# LEGITIMATE URL COMPONENTS
# ═══════════════════════════════════════════════════════════════════

# Real popular domains across categories
LEGIT_DOMAINS = [
    # Tech / Big sites
    "google.com", "youtube.com", "facebook.com", "twitter.com", "instagram.com",
    "linkedin.com", "github.com", "stackoverflow.com", "reddit.com", "wikipedia.org",
    "amazon.com", "apple.com", "microsoft.com", "netflix.com", "spotify.com",
    "dropbox.com", "slack.com", "zoom.us", "discord.com", "twitch.tv",
    # News
    "bbc.com", "cnn.com", "nytimes.com", "theguardian.com", "reuters.com",
    "bloomberg.com", "wsj.com", "forbes.com", "techcrunch.com", "wired.com",
    # E-commerce
    "ebay.com", "etsy.com", "shopify.com", "walmart.com", "target.com",
    "bestbuy.com", "alibaba.com", "aliexpress.com",
    # Finance (real banks)
    "paypal.com", "chase.com", "wellsfargo.com", "bankofamerica.com",
    "americanexpress.com", "visa.com", "mastercard.com",
    # Education / Reference
    "mit.edu", "stanford.edu", "harvard.edu", "coursera.org", "edx.org",
    "khanacademy.org", "duolingo.com", "wolframalpha.com",
    # Dev / Tools
    "npmjs.com", "pypi.org", "docker.com", "kubernetes.io", "mozilla.org",
    "gitlab.com", "bitbucket.org", "atlassian.com", "notion.so", "figma.com",
    # Travel / Lifestyle
    "airbnb.com", "booking.com", "tripadvisor.com", "expedia.com",
    "uber.com", "lyft.com", "doordash.com",
    # Productivity / Cloud
    "office.com", "outlook.com", "gmail.com", "icloud.com",
    "adobe.com", "canva.com", "trello.com", "asana.com",
    # Misc
    "imdb.com", "yelp.com", "pinterest.com", "tumblr.com", "medium.com",
    "quora.com", "tiktok.com", "snapchat.com", "whatsapp.com",
    "stackoverflow.com", "kaggle.com", "huggingface.co",
]

# Common legitimate path patterns
LEGIT_PATHS = [
    "/", "/about", "/contact", "/help", "/support", "/faq",
    "/login", "/signin", "/signup", "/register", "/profile", "/settings",
    "/account", "/dashboard", "/home", "/news", "/blog", "/products",
    "/services", "/pricing", "/terms", "/privacy", "/careers",
    "/search?q=python", "/search?q=machine+learning", "/search?q=news",
    "/docs", "/documentation", "/api", "/api/v1/users", "/api/v2/items",
    "/en/articles/getting-started", "/category/technology",
    "/post/12345", "/article/2024/05/news",
    "/user/john", "/user/profile/edit", "/u/alice",
    "/watch?v=dQw4w9WgXcQ", "/playlist?list=PLrAXtm",
    "/r/programming", "/r/python/comments/abc123",
    "/repo/owner/name", "/owner/repo/issues/42", "/owner/repo/pull/100",
    "/questions/12345/how-to-do-x", "/tagged/python",
    "/wiki/Machine_learning", "/wiki/Phishing",
    "/dp/B08N5WRWNW", "/gp/cart", "/checkout",
    "/c/electronics", "/p/laptop-thinkpad-x1",
    "/news/world/2024/may/article",
    "/courses/data-science", "/learn/python-basics",
]

# Subdomains commonly used by legitimate sites
LEGIT_SUBDOMAINS = ["www", "mail", "blog", "shop", "store", "app", "api",
                    "docs", "help", "support", "developer", "cloud", "secure",
                    "accounts", "login", "m", "mobile", ""]


# ═══════════════════════════════════════════════════════════════════
# PHISHING URL COMPONENTS
# ═══════════════════════════════════════════════════════════════════

# Brands frequently impersonated in phishing attacks
PHISHING_TARGET_BRANDS = [
    "paypal", "amazon", "apple", "microsoft", "google", "facebook",
    "instagram", "netflix", "spotify", "ebay", "linkedin", "dropbox",
    "wellsfargo", "chase", "bankofamerica", "citibank", "hsbc",
    "americanexpress", "visa", "mastercard", "discover",
    "fedex", "ups", "dhl", "usps", "irs", "ssa",
    "office365", "outlook", "icloud", "adobe", "docusign",
    "whatsapp", "telegram", "binance", "coinbase", "metamask",
]

# Common typo-squatting variations
TYPO_PATTERNS = [
    "{brand}-secure",       # paypal-secure
    "{brand}-login",        # paypal-login
    "{brand}-verify",       # paypal-verify
    "{brand}-support",      # paypal-support
    "{brand}-account",      # paypal-account
    "{brand}-update",       # paypal-update
    "{brand}-confirm",      # paypal-confirm
    "secure-{brand}",       # secure-paypal
    "verify-{brand}",       # verify-paypal
    "login-{brand}",        # login-paypal
    "my-{brand}",           # my-paypal
    "{brand}services",      # paypalservices
    "{brand}-help",
    "{brand}-billing",
    "account-{brand}",
    "{brand}.account-verify",
    "{brand}-security-alert",
]

# Character substitutions (homograph attacks)
def make_typo(brand):
    """Apply random character substitution to mimic a brand."""
    substitutions = {
        "a": "4", "o": "0", "i": "1", "l": "1", "e": "3", "s": "5"
    }
    if random.random() < 0.5:
        chars = list(brand)
        idx = random.randint(0, len(chars) - 1)
        if chars[idx] in substitutions:
            chars[idx] = substitutions[chars[idx]]
        return "".join(chars)
    return brand

# Suspicious TLDs heavily abused for phishing
PHISHING_TLDS = ["tk", "ml", "ga", "cf", "gq",       # Free Freenom TLDs
                 "xyz", "top", "club", "online",       # Cheap registrar TLDs
                 "info", "biz", "site", "website",
                 "icu", "fit", "pw", "buzz", "monster"]

# Phishing path patterns
PHISHING_PATHS = [
    "/login.php?user={token}",
    "/signin?session={token}&redirect={brand}.com",
    "/verify-account.php?token={token}",
    "/update-payment-info?id={token}",
    "/confirm-identity?session={token}",
    "/security-alert?case={token}",
    "/suspended-account?reason=unusual_activity",
    "/restore-access.php?ref={token}",
    "/billing/update?invoice={token}",
    "/account/locked?unlock_token={token}",
    "/secure/login?redirect_uri=https%3A%2F%2F{brand}.com",
    "/auth/{brand}/callback?code={token}",
    "/wp-admin/login.php?redirect_to=/admin",
    "/.well-known/{brand}/verify",
    "/cgi-bin/webscr?cmd=_login-run",
    "/{brand}/login/{token}",
    "/index.php?action=verify&id={token}",
    "/{token}/login.html",
]


def random_token(length=12):
    """Generate a random alphanumeric token."""
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def _make_brand_typo(brand):
    """
    Create a realistic typo of a brand name (edit distance 1-2).
    Techniques: double a letter, drop a letter, swap adjacent, insert a letter.
    e.g. youtube → youtuube / youtub / yotube
    """
    technique = random.choice(["double", "drop", "swap", "insert"])
    chars = list(brand)
    if len(chars) < 4:
        return brand + brand[-1]  # just double last letter

    if technique == "double":
        i = random.randint(0, len(chars) - 1)
        chars.insert(i, chars[i])
    elif technique == "drop":
        i = random.randint(1, len(chars) - 1)
        chars.pop(i)
    elif technique == "swap":
        i = random.randint(0, len(chars) - 2)
        chars[i], chars[i + 1] = chars[i + 1], chars[i]
    elif technique == "insert":
        i = random.randint(1, len(chars) - 1)
        chars.insert(i, random.choice("aeiou"))
    return "".join(chars)


# ═══════════════════════════════════════════════════════════════════
# URL GENERATORS
# ═══════════════════════════════════════════════════════════════════

def generate_legitimate_url():
    """Generate a realistic legitimate URL."""
    domain    = random.choice(LEGIT_DOMAINS)
    subdomain = random.choice(LEGIT_SUBDOMAINS)
    path      = random.choice(LEGIT_PATHS)
    # 90% of legit sites use HTTPS
    scheme = "https" if random.random() < 0.90 else "http"

    # 20% of the time, generate a BARE domain (no subdomain, no path)
    # This teaches the model that "google.com" / "github.com" are SAFE,
    # even over plain http and even with no path.
    if random.random() < 0.20:
        scheme = "https" if random.random() < 0.75 else "http"
        bare = random.random() < 0.5
        host = domain if bare else f"www.{domain}"
        path = "" if random.random() < 0.5 else "/"
        return f"{scheme}://{host}{path}"

    if subdomain:
        host = f"{subdomain}.{domain}"
    else:
        host = domain

    return f"{scheme}://{host}{path}"


def generate_phishing_url():
    """Generate a realistic phishing URL using real attack patterns."""
    pattern_type = random.choice([
        "typo_squat", "subdomain_spoof", "ip_address",
        "long_random", "homograph", "free_tld_brand",
        "brand_typo", "brand_homograph"   # NEW: target legit TLDs too
    ])

    brand = random.choice(PHISHING_TARGET_BRANDS)
    tld   = random.choice(PHISHING_TLDS)
    token = random_token()
    path  = random.choice(PHISHING_PATHS).format(brand=brand, token=token)
    # Phishing sites use HTTPS ~40% of the time (Let's Encrypt is free)
    scheme = "https" if random.random() < 0.40 else "http"

    if pattern_type == "typo_squat":
        # paypal-secure-login.tk/...
        pattern = random.choice(TYPO_PATTERNS).format(brand=brand)
        host = f"{pattern}.{tld}"

    elif pattern_type == "subdomain_spoof":
        # accounts.google.com.evil-phishing.tk/...
        real_tld = random.choice(["com", "org", "net"])
        host = f"accounts.{brand}.{real_tld}.{random_token(8)}.{tld}"

    elif pattern_type == "ip_address":
        # http://192.168.x.x/banking/login.php
        ip = f"{random.randint(1, 254)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        if random.random() < 0.3:
            port = random.choice([8080, 8888, 8443, 81, 8000])
            host = f"{ip}:{port}"
        else:
            host = ip

    elif pattern_type == "long_random":
        # Long random subdomain prefix
        prefix = random_token(random.randint(15, 30))
        host = f"{prefix}-{brand}.{tld}"

    elif pattern_type == "homograph":
        # paypa1.com, amaz0n.com, etc.
        typo_brand = make_typo(brand)
        host = f"{typo_brand}-{random.choice(['secure','login','verify','support'])}.{tld}"

    elif pattern_type == "free_tld_brand":
        # brand-keyword.tk
        keyword = random.choice(["login", "verify", "secure", "account", "update", "support"])
        host = f"{brand}-{keyword}-{random_token(6)}.{tld}"

    elif pattern_type == "brand_typo":
        # Typo-squat on a LEGIT TLD: youtuube.com, faceboook.com, amazom.com
        # These are dangerous because they use .com and have no other red flags.
        legit_tld = random.choice(["com", "net", "org", "co"])
        typo = _make_brand_typo(brand)
        # Mostly HTTPS (these are sophisticated attacks)
        scheme = "https" if random.random() < 0.6 else "http"
        host = f"{typo}.{legit_tld}"
        # Often a clean/short path
        path = random.choice(["/", "/login", "/account", "/signin", "/home"])
        return f"{scheme}://{host}{path}"

    elif pattern_type == "brand_homograph":
        # Homograph attack: amaz0n.com, g00gle.com, paypa1.com on legit TLDs
        legit_tld = random.choice(["com", "net", "org"])
        homo = make_typo(brand)  # uses digit substitution (0,1,3,4,5)
        # Force at least one substitution
        if homo == brand:
            homo = brand.replace("o", "0", 1).replace("a", "4", 1).replace("i", "1", 1)
        scheme = "https" if random.random() < 0.6 else "http"
        host = f"{homo}.{legit_tld}"
        path = random.choice(["/", "/login", "/verify", "/account", "/signin"])
        return f"{scheme}://{host}{path}"

    return f"{scheme}://{host}{path}"


# ═══════════════════════════════════════════════════════════════════
# DATASET BUILDER
# ═══════════════════════════════════════════════════════════════════

def build_dataset(output_path="data/urls.csv", n_legitimate=10000, n_phishing=10000):
    """Build and save the dataset."""
    print("╔════════════════════════════════════════════════════════╗")
    print("║      BUILDING CLEAN PHISHING URL DATASET FROM SCRATCH  ║")
    print("╚════════════════════════════════════════════════════════╝\n")

    print(f"  Generating {n_legitimate:,} legitimate URLs...")
    legit_urls = set()
    while len(legit_urls) < n_legitimate:
        legit_urls.add(generate_legitimate_url())
    print(f"  ✅ {len(legit_urls):,} unique legitimate URLs created\n")

    print(f"  Generating {n_phishing:,} phishing URLs...")
    phishing_urls = set()
    while len(phishing_urls) < n_phishing:
        phishing_urls.add(generate_phishing_url())
    print(f"  ✅ {len(phishing_urls):,} unique phishing URLs created\n")

    # Combine and shuffle
    rows = []
    for u in legit_urls:
        rows.append({"url": u, "label": "legitimate"})
    for u in phishing_urls:
        rows.append({"url": u, "label": "phishing"})
    random.shuffle(rows)

    # Save
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["url", "label"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"  💾 Saved to: {output_path}")
    print(f"     Total URLs:  {len(rows):,}")
    print(f"     Legitimate:  {n_legitimate:,} ({100*n_legitimate/len(rows):.1f}%)")
    print(f"     Phishing:    {n_phishing:,} ({100*n_phishing/len(rows):.1f}%)")
    print()

    # Show samples
    print("  📋 Sample LEGITIMATE URLs:")
    legit_samples = [r for r in rows if r["label"] == "legitimate"][:5]
    for r in legit_samples:
        print(f"     • {r['url']}")
    print()
    print("  📋 Sample PHISHING URLs:")
    phish_samples = [r for r in rows if r["label"] == "phishing"][:5]
    for r in phish_samples:
        print(f"     • {r['url']}")
    print()

    print("  ✨ Dataset ready! Now run:")
    print("     python main.py --mode train")


if __name__ == "__main__":
    build_dataset()
