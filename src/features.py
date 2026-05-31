"""
src/features.py
---------------
Lexical feature extraction for phishing URL detection.

Each function extracts one signal from the raw URL string.
No external HTTP requests — everything is based on the URL text alone.
This is intentional: lexical features are instant (< 1ms) and work offline.
"""

import re
import math
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Suspicious keywords commonly found in phishing URLs
# ---------------------------------------------------------------------------
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "verification", "update", "confirm",
    "secure", "account", "banking", "paypal", "password", "credential",
    "alert", "suspend", "limited", "unusual", "webscr", "ebayisapi",
    "click", "billing", "support", "invoice", "auth", "authenticate",
    "wallet", "crypto", "free", "winner", "prize", "urgent", "validate",
]

# TLDs frequently abused in phishing campaigns
SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq",    # Free Freenom TLDs
    ".xyz", ".top", ".club", ".online",    # Cheap registrar TLDs
    ".info", ".biz",                       # Historically abused
]

# ---------------------------------------------------------------------------
# Popular brands frequently impersonated in phishing / typo-squatting attacks.
# We measure how "close" a domain is to one of these — a domain that is ALMOST
# (but not exactly) a known brand is highly suspicious (e.g. youtuube, amaz0n).
# ---------------------------------------------------------------------------
KNOWN_BRANDS = [
    "google", "youtube", "facebook", "instagram", "twitter", "linkedin",
    "amazon", "apple", "microsoft", "netflix", "spotify", "paypal",
    "ebay", "dropbox", "github", "reddit", "wikipedia", "yahoo",
    "whatsapp", "telegram", "snapchat", "tiktok", "pinterest", "tumblr",
    "wellsfargo", "chase", "bankofamerica", "citibank", "hsbc", "visa",
    "mastercard", "americanexpress", "discover", "binance", "coinbase",
    "fedex", "ups", "dhl", "usps", "outlook", "gmail", "icloud", "adobe",
    "office365", "docusign", "steam", "discord", "twitch", "roblox",
]

# Non-ASCII characters that visually mimic ASCII letters (homograph attacks).
# Their presence in a domain is a strong phishing signal.
HOMOGRAPH_CHARS = set(
    "àáâãäåèéêëìíîïòóôõöùúûüýÿñçčšžеаорхсукіїабвгдабсԁеѕхуіјо"  # Cyrillic/accented look-alikes
)


# ---------------------------------------------------------------------------
# Individual feature extraction helpers
# ---------------------------------------------------------------------------

def get_url_length(url: str) -> int:
    """Raw character length of the full URL."""
    return len(url)


def get_num_dots(url: str) -> int:
    """Count of dots — many dots often indicate subdomain abuse."""
    return url.count(".")


def get_num_hyphens(url: str) -> int:
    """Hyphens in domains are a classic phishing trick (paypa1-secure.com)."""
    return url.count("-")


def get_num_at(url: str) -> int:
    """'@' in URL redirects browser to the part after '@'. Always suspicious."""
    return 1 if "@" in url else 0


def get_num_slash(url: str) -> int:
    """Count of forward slashes (excluding the protocol ones)."""
    return url.count("/")


def get_num_subdomains(url: str) -> int:
    """
    Number of subdomain levels.
    e.g., secure.paypal.phishing.com → 2 subdomains before the real domain.
    We count dots in the netloc minus 1 (for the TLD dot).
    """
    try:
        netloc = urlparse(url).netloc
        # Strip port if present
        netloc = netloc.split(":")[0]
        parts = netloc.split(".")
        # subdomain count = total parts - 2 (domain + TLD)
        return max(0, len(parts) - 2)
    except Exception:
        return 0


def has_ip_address(url: str) -> int:
    """
    Detect if the URL uses a raw IP instead of a domain name.
    Legitimate sites almost never use IP addresses directly.
    Supports IPv4 only (IPv6 is extremely rare in phishing).
    """
    # Remove protocol prefix first
    stripped = re.sub(r"https?://", "", url)
    # IPv4 pattern at start of host
    ipv4_pattern = r"^(\d{1,3}\.){3}\d{1,3}"
    return 1 if re.match(ipv4_pattern, stripped) else 0


def has_https(url: str) -> int:
    """
    Returns 1 if URL uses HTTPS, 0 otherwise.
    Note: phishing sites increasingly use HTTPS — absence is suspicious,
    but presence alone does NOT mean safe.
    """
    return 1 if url.lower().startswith("https") else 0


def has_suspicious_keyword(url: str) -> int:
    """Returns 1 if any suspicious keyword appears in the URL (case-insensitive)."""
    url_lower = url.lower()
    return 1 if any(kw in url_lower for kw in SUSPICIOUS_KEYWORDS) else 0


def count_suspicious_keywords(url: str) -> int:
    """Count how many suspicious keywords appear (more = more suspicious)."""
    url_lower = url.lower()
    return sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)


def get_num_special_chars(url: str) -> int:
    """
    Count non-alphanumeric, non-standard URL characters.
    Encoded or obfuscated URLs often have many special chars.
    """
    return len(re.findall(r"[^a-zA-Z0-9/:._\-?=&%#@]", url))


def get_domain_length(url: str) -> int:
    """Length of the domain/netloc portion only."""
    try:
        return len(urlparse(url).netloc)
    except Exception:
        return 0


def get_path_length(url: str) -> int:
    """Length of the URL path (after the domain)."""
    try:
        return len(urlparse(url).path)
    except Exception:
        return 0


def has_port(url: str) -> int:
    """
    Returns 1 if a non-standard port is specified.
    Legitimate sites use 80/443; phishing often uses weird ports.
    """
    try:
        port = urlparse(url).port
        if port and port not in (80, 443):
            return 1
        return 0
    except Exception:
        return 0


def get_digit_ratio(url: str) -> float:
    """
    Ratio of digit characters in the URL.
    High digit ratios (e.g. 'a8b3c9x2.tk') are suspicious.
    """
    if not url:
        return 0.0
    return sum(c.isdigit() for c in url) / len(url)


def get_letter_ratio(url: str) -> float:
    """Ratio of letter characters. Complement to digit_ratio."""
    if not url:
        return 0.0
    return sum(c.isalpha() for c in url) / len(url)


def has_suspicious_tld(url: str) -> int:
    """Returns 1 if the URL uses a TLD commonly associated with phishing."""
    url_lower = url.lower()
    return 1 if any(tld in url_lower for tld in SUSPICIOUS_TLDS) else 0


def get_query_length(url: str) -> int:
    """Length of query string — long query strings can hide malicious params."""
    try:
        return len(urlparse(url).query)
    except Exception:
        return 0


def count_query_params(url: str) -> int:
    """Number of query parameters."""
    try:
        query = urlparse(url).query
        if not query:
            return 0
        return len(query.split("&"))
    except Exception:
        return 0


def has_double_slash_redirect(url: str) -> int:
    """
    Detect '//' in the path (not the protocol), which can indicate redirect abuse.
    e.g., https://real-bank.com//evil.com/
    """
    try:
        path = urlparse(url).path
        return 1 if "//" in path else 0
    except Exception:
        return 0


# ---------------------------------------------------------------------------
# Brand-similarity & homograph detection (NEW — catches typo-squatting)
# ---------------------------------------------------------------------------

def _levenshtein(a: str, b: str) -> int:
    """
    Compute the Levenshtein (edit) distance between two strings.
    This is the minimum number of single-character insertions, deletions,
    or substitutions to turn one string into the other.

    Pure Python, no external libraries needed.
    Example: distance("youtube", "youtuube") == 1
    """
    if a == b:
        return 0
    if len(a) == 0:
        return len(b)
    if len(b) == 0:
        return len(a)

    # Dynamic programming row
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        current = [i + 1]
        for j, cb in enumerate(b):
            insert  = previous[j + 1] + 1
            delete  = current[j] + 1
            replace = previous[j] + (ca != cb)
            current.append(min(insert, delete, replace))
        previous = current
    return previous[-1]


def _get_core_domain(url: str) -> str:
    """
    Extract the 'core' brand part of a domain.
    e.g. https://www.youtuube.com/watch → 'youtuube'
         http://secure-paypal.tk        → 'secure-paypal' → 'paypal' part checked separately
    Returns the second-level domain (the part before the TLD), lowercased.
    """
    try:
        netloc = urlparse(url).netloc.split(":")[0]  # strip port
        if not netloc:
            return ""
        parts = netloc.split(".")
        if len(parts) >= 2:
            # second-level domain (e.g. 'youtuube' from 'www.youtuube.com')
            return parts[-2].lower()
        return parts[0].lower()
    except Exception:
        return ""


def get_brand_similarity(url: str) -> int:
    """
    Returns 1 if the domain is SUSPICIOUSLY CLOSE to a known brand
    (but not an exact match) — i.e. likely typo-squatting.

    Logic:
      - distance == 0  → exact brand match → NOT suspicious (it's the real brand)
      - distance 1–2   → very close to a brand → SUSPICIOUS (typo-squat)
      - distance >= 3  → not related → not flagged by this feature

    Catches: youtuube (1), amaz0n (1), g00gle (2), paypa1 (1), faceboook (1)
    Ignores: youtube (0, exact), random words (far from all brands)
    """
    core = _get_core_domain(url)
    if not core:
        return 0

    # Also check the domain with hyphens removed (secure-paypal → securepaypal)
    # and individual hyphen-separated tokens
    candidates = [core] + core.split("-")

    for candidate in candidates:
        if len(candidate) < 4:
            continue
        for brand in KNOWN_BRANDS:
            dist = _levenshtein(candidate, brand)
            if dist == 0:
                # Exact match somewhere — but keep checking other candidates.
                # If the FULL core is an exact brand, it's legit; return 0 now.
                if candidate == core:
                    return 0
            elif 1 <= dist <= 2 and abs(len(candidate) - len(brand)) <= 2:
                # Close but not exact → typo-squat signal
                return 1
    return 0


def get_min_brand_distance(url: str) -> int:
    """
    Returns the minimum edit distance from the core domain to ANY known brand.
    Capped at 10 (anything further is irrelevant).

    A small non-zero value (1-2) is a strong typo-squat signal.
    0 means exact brand match (legit). Large value means unrelated domain.
    """
    core = _get_core_domain(url)
    if not core:
        return 10

    min_dist = 10
    candidates = [core] + core.split("-")
    for candidate in candidates:
        if len(candidate) < 4:
            continue
        for brand in KNOWN_BRANDS:
            dist = _levenshtein(candidate, brand)
            min_dist = min(min_dist, dist)
            if min_dist == 0:
                return 0
    return min_dist


def has_homograph_chars(url: str) -> int:
    """
    Returns 1 if the URL contains non-ASCII look-alike characters
    (homograph / IDN attack), e.g. youtubé.com, gøøgle.com, аpple.com (Cyrillic 'а').
    """
    # Check only the domain portion
    try:
        netloc = urlparse(url).netloc
    except Exception:
        netloc = url
    return 1 if any(ch in HOMOGRAPH_CHARS for ch in netloc) else 0


def has_non_ascii(url: str) -> int:
    """
    Returns 1 if the domain contains ANY non-ASCII character.
    Broader than homograph detection — any non-ASCII in a domain is unusual.
    """
    try:
        netloc = urlparse(url).netloc
    except Exception:
        netloc = url
    return 1 if any(ord(ch) > 127 for ch in netloc) else 0


# ---------------------------------------------------------------------------
# Master feature extraction function
# ---------------------------------------------------------------------------

def extract_features(url: str) -> dict:
    """
    Extract all lexical features from a single URL string.

    Parameters
    ----------
    url : str
        The raw URL to analyze.

    Returns
    -------
    dict
        A flat dictionary of feature_name → numeric value.
        All values are int or float (ready for sklearn).
    """
    return {
        "url_length":              get_url_length(url),
        "num_dots":                get_num_dots(url),
        "num_hyphens":             get_num_hyphens(url),
        "num_at":                  get_num_at(url),
        "num_slash":               get_num_slash(url),
        "num_subdomains":          get_num_subdomains(url),
        "has_ip":                  has_ip_address(url),
        "has_https":               has_https(url),
        "has_suspicious_keyword":  has_suspicious_keyword(url),
        "num_suspicious_keywords": count_suspicious_keywords(url),
        "num_special_chars":       get_num_special_chars(url),
        "domain_length":           get_domain_length(url),
        "path_length":             get_path_length(url),
        "has_port":                has_port(url),
        "digit_ratio":             get_digit_ratio(url),
        "letter_ratio":            get_letter_ratio(url),
        "has_suspicious_tld":      has_suspicious_tld(url),
        "query_length":            get_query_length(url),
        "num_query_params":        count_query_params(url),
        "has_double_slash":        has_double_slash_redirect(url),
        # ── NEW: typo-squatting & homograph detection ──
        "brand_similarity":        get_brand_similarity(url),
        "min_brand_distance":      get_min_brand_distance(url),
        "has_homograph":           has_homograph_chars(url),
        "has_non_ascii":           has_non_ascii(url),
    }


def extract_features_batch(urls: list) -> list:
    """
    Extract features for a list of URLs.

    Parameters
    ----------
    urls : list of str

    Returns
    -------
    list of dict  (one dict per URL)
    """
    return [extract_features(url) for url in urls]


# ---------------------------------------------------------------------------
# Feature names (useful for model inspection / feature importance)
# ---------------------------------------------------------------------------
FEATURE_NAMES = list(extract_features("http://example.com").keys())


if __name__ == "__main__":
    # Quick sanity check
    test_urls = [
        "https://www.google.com",
        "http://paypal-secure-login.verify-account.tk/update?user=victim@email.com",
        "http://192.168.1.1/admin/login.php",
    ]
    for u in test_urls:
        print(f"\nURL: {u}")
        feats = extract_features(u)
        for k, v in feats.items():
            print(f"  {k:30s} = {v}")
