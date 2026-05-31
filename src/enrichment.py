"""
src/enrichment.py
-----------------
Step 2 — Live domain enrichment (WHOIS + DNS).

WHAT THIS IS (mentor note):
  Step 1 only reads the TEXT of a URL — instant, offline, never touches the
  network. This module adds the *opposite* kind of signal: it ASKS THE INTERNET
  about the domain. Two questions, both strong phishing tells:

    1. WHOIS  → "How old is this domain?"  Banks own domains for years.
                 Phishing domains are often registered days ago. This is one
                 of the single strongest phishing signals that exists.
    2. DNS    → "Does this domain actually resolve to a real server?"
                 A link asking you to 'verify your account' whose domain
                 doesn't even resolve is a major red flag.

HOW IT'S USED:
  This runs AFTER the ML model. It never changes the model. It produces a
  small "risk boost" and human-readable reasons that get combined with the
  model's verdict in predict.py. This keeps Step 1 fast & offline by default,
  and makes the network cost OPT-IN.

DESIGN CHOICES worth understanding:
  - DNS uses the OPERATING SYSTEM resolver (socket.gethostbyname_ex), the same
    machinery your browser uses. It's fast, reliable everywhere, and needs no
    extra library — more robust than a third-party DNS client.
  - WHOIS has no built-in timeout, so we run it in a worker thread and abandon
    it if a slow WHOIS server takes too long. Network calls must never hang
    the API.
  - Results are CACHED in memory (domains repeat across requests).
  - A FAILED lookup is never treated as 'guilty'. Missing data = no penalty.
"""

import time
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout

import whois
import tldextract

# ---------------------------------------------------------------------------
# Tunables
# ---------------------------------------------------------------------------
WHOIS_TIMEOUT_SEC = 5.0       # hard cap on the WHOIS lookup
DNS_TIMEOUT_SEC = 3.0         # hard cap on the DNS resolution
CACHE_TTL_SEC = 3600          # remember a domain's result for 1 hour
_CACHE: dict = {}             # domain -> (timestamp, result_dict)


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def _extract_domain(url: str) -> str:
    """Pull the full hostname (e.g. 'www.paypal.com') out of a URL — used for DNS."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    host = urlparse(url).hostname or ""
    return host.lower()


def _registrable_domain(host: str) -> str:
    """
    Reduce a hostname to the domain you'd actually query WHOIS for.

    WHOIS is registered at the 'registrable domain' level — the apex you can
    buy — NOT at subdomains. So:
        www.github.com            -> github.com
        accounts.google.com       -> google.com
        login.example.co.uk       -> example.co.uk   (handles multi-part TLDs)

    Querying WHOIS for 'www.github.com' returns nothing, which is exactly the
    bug this prevents. tldextract uses the Public Suffix List to get this right.
    """
    ext = tldextract.extract(host)
    # Newer tldextract renamed this property; support both versions.
    return getattr(ext, "top_domain_under_public_suffix", None) or ext.registered_domain


def _run_with_timeout(fn, timeout, *args):
    """
    Run a blocking function but give up after `timeout` seconds.

    Why a thread: the whois library has no timeout option, and a slow WHOIS
    server could otherwise freeze the whole API. We run it in a worker thread
    and abandon it if it's too slow. Returns None on timeout or any error.
    """
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(fn, *args)
        try:
            return future.result(timeout=timeout)
        except (FuturesTimeout, Exception):
            return None


def _earliest_date(value):
    """
    WHOIS creation_date can be a datetime, a list of datetimes, or junk.
    Normalize to a single timezone-aware datetime (the earliest), or None.
    """
    if value is None:
        return None
    if isinstance(value, list):
        dates = [d for d in value if isinstance(d, datetime)]
        if not dates:
            return None
        value = min(dates)
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:                       # make tz-aware (UTC)
        value = value.replace(tzinfo=timezone.utc)
    return value


# ---------------------------------------------------------------------------
# The two raw lookups
# ---------------------------------------------------------------------------
def _whois_lookup(domain: str) -> dict:
    """Return {domain_age_days, creation_date, registrar}; values None on failure."""
    info = {"domain_age_days": None, "creation_date": None, "registrar": None}

    data = _run_with_timeout(lambda: whois.whois(domain), WHOIS_TIMEOUT_SEC)
    if data is None:
        return info

    created = _earliest_date(getattr(data, "creation_date", None))
    if created:
        age_days = (datetime.now(timezone.utc) - created).days
        info["domain_age_days"] = max(age_days, 0)
        info["creation_date"] = created.strftime("%Y-%m-%d")

    registrar = getattr(data, "registrar", None)
    if isinstance(registrar, list):
        registrar = registrar[0] if registrar else None
    info["registrar"] = registrar
    return info


def _dns_lookup(domain: str) -> dict:
    """
    Return {resolves, num_ip_addresses} using the OS resolver.

    resolves=None means 'we couldn't tell' (timeout/error) — distinct from
    resolves=False which means the OS actively said this host is unknown.
    We only penalize a confident False, never an unknown None.
    """
    info = {"resolves": None, "num_ip_addresses": 0}

    def _resolve():
        # gethostbyname_ex → (hostname, aliaslist, ip_list). Same lookup the
        # browser does. Raises socket.gaierror if the host genuinely doesn't
        # resolve.
        return socket.gethostbyname_ex(domain)[2]

    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(DNS_TIMEOUT_SEC)
    try:
        ips = _resolve()
        info["resolves"] = True
        info["num_ip_addresses"] = len(ips)
    except socket.gaierror:
        info["resolves"] = False          # confident: host does not resolve
    except Exception:
        info["resolves"] = None           # unknown: timeout / transient error
    finally:
        socket.setdefaulttimeout(old_timeout)

    return info


# ---------------------------------------------------------------------------
# Risk scoring from the enrichment signals
# ---------------------------------------------------------------------------
def _score_signals(info: dict) -> tuple:
    """
    Turn raw WHOIS/DNS facts into (risk_boost, reasons).

    risk_boost is added to the model's 0-100 risk score. Positive = more
    suspicious. A small NEGATIVE boost rewards very old domains (trust bonus).
    Everything here is conservative and fully explainable.
    """
    boost = 0
    reasons = []

    age = info.get("domain_age_days")
    if age is not None:
        if age < 7:
            boost += 30
            reasons.append(f"Domain registered only {age} day(s) ago — extremely new (top phishing signal)")
        elif age < 30:
            boost += 20
            reasons.append(f"Domain registered {age} days ago — very recently created")
        elif age < 90:
            boost += 8
            reasons.append(f"Domain is fairly new ({age} days old)")
        elif age > 730:
            boost -= 5  # 2+ years old → small trust bonus
            reasons.append(f"Domain is well-established ({age // 365} year(s) old)")

    # Only penalize a CONFIDENT non-resolution (resolves is False, not None).
    if info.get("resolves") is False:
        boost += 15
        reasons.append("Domain does not resolve to any IP address (may be dead or newly thrown up)")

    return boost, reasons


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------
def enrich_url(url: str) -> dict:
    """
    Look up live WHOIS + DNS facts for a URL's domain.

    Returns a dict:
        {
          "performed":        bool,         # did we run lookups (vs cache)?
          "domain":           str,
          "domain_age_days":  int | None,
          "creation_date":    str | None,   # "YYYY-MM-DD"
          "registrar":        str | None,
          "resolves":         bool | None,  # None = couldn't determine
          "num_ip_addresses": int,
          "risk_boost":       int,          # add this to the ML risk score
          "reasons":          list[str],
          "lookup_ms":        float,
          "cached":           bool,
        }

    Never raises. On failure it returns neutral values (risk_boost=0). A
    failed lookup must never make a URL look guilty.
    """
    start = time.perf_counter()
    domain = _extract_domain(url)

    # Cache hit? Return a copy so callers can't mutate our cache.
    now = time.time()
    cached = _CACHE.get(domain)
    if cached and (now - cached[0]) < CACHE_TTL_SEC:
        result = dict(cached[1])
        result["cached"] = True
        result["lookup_ms"] = round((time.perf_counter() - start) * 1000, 2)
        return result

    info = {
        "performed": True,
        "domain": domain,
        "registrable_domain": domain,
        "domain_age_days": None,
        "creation_date": None,
        "registrar": None,
        "resolves": None,
        "num_ip_addresses": 0,
        "risk_boost": 0,
        "reasons": [],
        "cached": False,
    }

    if domain:
        # WHOIS → registrable domain (apex). DNS → full hostname (what the
        # browser actually connects to, e.g. www.github.com).
        info["registrable_domain"] = _registrable_domain(domain)
        info.update(_whois_lookup(info["registrable_domain"]))
        info.update(_dns_lookup(domain))
        boost, reasons = _score_signals(info)
        info["risk_boost"] = boost
        info["reasons"] = reasons

    info["lookup_ms"] = round((time.perf_counter() - start) * 1000, 2)

    _CACHE[domain] = (now, dict(info))   # cache without per-call flags mutated
    return info


# ---------------------------------------------------------------------------
# Quick manual test:  python -m src.enrichment
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    for d in ["https://www.google.com", "https://github.com", "http://this-domain-almost-surely-does-not-exist-9281.tk"]:
        print(f"\n{d}")
        for k, v in enrich_url(d).items():
            print(f"   {k:18}: {v}")
