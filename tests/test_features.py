"""
tests/test_features.py
-----------------------
Unit tests for every feature extraction function.

Run with:
    python -m pytest tests/ -v
or:
    python tests/test_features.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import unittest
from src.features import (
    get_url_length,
    get_num_dots,
    get_num_hyphens,
    get_num_at,
    get_num_subdomains,
    has_ip_address,
    has_https,
    has_suspicious_keyword,
    count_suspicious_keywords,
    get_num_special_chars,
    get_domain_length,
    get_path_length,
    has_port,
    get_digit_ratio,
    has_suspicious_tld,
    get_query_length,
    count_query_params,
    has_double_slash_redirect,
    extract_features,
    FEATURE_NAMES,
)


class TestURLLength(unittest.TestCase):
    def test_basic(self):
        self.assertEqual(get_url_length("http://a.com"), 12)

    def test_empty(self):
        self.assertEqual(get_url_length(""), 0)

    def test_long(self):
        url = "http://" + "a" * 200 + ".com"
        self.assertEqual(get_url_length(url), 211)


class TestDots(unittest.TestCase):
    def test_simple(self):
        self.assertEqual(get_num_dots("http://www.google.com"), 2)

    def test_many_dots(self):
        self.assertEqual(get_num_dots("a.b.c.d.e.f"), 5)


class TestHyphens(unittest.TestCase):
    def test_phishing_domain(self):
        self.assertEqual(get_num_hyphens("http://paypal-secure-login.com"), 2)

    def test_no_hyphens(self):
        self.assertEqual(get_num_hyphens("https://google.com"), 0)


class TestAtSign(unittest.TestCase):
    def test_at_present(self):
        self.assertEqual(get_num_at("http://user@evil.com"), 1)

    def test_no_at(self):
        self.assertEqual(get_num_at("http://google.com"), 0)


class TestSubdomains(unittest.TestCase):
    def test_www(self):
        self.assertEqual(get_num_subdomains("https://www.google.com"), 1)

    def test_deep_subdomain(self):
        # secure.paypal.phishing.attacker.com → 3 subdomains
        self.assertEqual(
            get_num_subdomains("http://secure.paypal.phishing.attacker.com"), 3
        )

    def test_no_subdomain(self):
        self.assertEqual(get_num_subdomains("https://github.com"), 0)


class TestIPAddress(unittest.TestCase):
    def test_ipv4_url(self):
        self.assertEqual(has_ip_address("http://192.168.0.1/admin"), 1)

    def test_normal_domain(self):
        self.assertEqual(has_ip_address("https://google.com"), 0)

    def test_ip_with_path(self):
        self.assertEqual(has_ip_address("http://10.0.0.1:8080/login.php"), 1)


class TestHTTPS(unittest.TestCase):
    def test_https(self):
        self.assertEqual(has_https("https://bank.com"), 1)

    def test_http(self):
        self.assertEqual(has_https("http://bank.com"), 0)

    def test_uppercase(self):
        self.assertEqual(has_https("HTTPS://bank.com"), 1)


class TestSuspiciousKeywords(unittest.TestCase):
    def test_login(self):
        self.assertEqual(has_suspicious_keyword("http://evil.com/login.php"), 1)

    def test_multiple(self):
        self.assertGreater(
            count_suspicious_keywords("http://paypal-secure-verify-login.com"), 2
        )

    def test_clean(self):
        self.assertEqual(has_suspicious_keyword("https://github.com/openai"), 0)


class TestSpecialChars(unittest.TestCase):
    def test_clean_url(self):
        self.assertEqual(get_num_special_chars("https://google.com/search"), 0)

    def test_with_special(self):
        count = get_num_special_chars("http://evil.com/path!{}|")
        self.assertGreater(count, 0)


class TestDomainLength(unittest.TestCase):
    def test_normal(self):
        self.assertEqual(get_domain_length("https://google.com"), len("google.com"))

    def test_long(self):
        url = "https://" + "a" * 50 + ".com"
        self.assertEqual(get_domain_length(url), 54)


class TestPort(unittest.TestCase):
    def test_standard_ports(self):
        self.assertEqual(has_port("https://google.com:443"), 0)
        self.assertEqual(has_port("http://google.com:80"), 0)

    def test_weird_port(self):
        self.assertEqual(has_port("http://evil.com:8888/admin"), 1)

    def test_no_port(self):
        self.assertEqual(has_port("https://google.com"), 0)


class TestDigitRatio(unittest.TestCase):
    def test_high_ratio(self):
        ratio = get_digit_ratio("http://1234567890abc.tk")
        self.assertGreater(ratio, 0.3)

    def test_low_ratio(self):
        ratio = get_digit_ratio("https://github.com/openai")
        self.assertLess(ratio, 0.1)


class TestSuspiciousTLD(unittest.TestCase):
    def test_freenom(self):
        self.assertEqual(has_suspicious_tld("http://evil.tk"), 1)
        self.assertEqual(has_suspicious_tld("http://phish.ml"), 1)

    def test_legit_tld(self):
        self.assertEqual(has_suspicious_tld("https://google.com"), 0)


class TestDoubleSlash(unittest.TestCase):
    def test_redirect(self):
        self.assertEqual(has_double_slash_redirect("https://legit.com//evil.com"), 1)

    def test_normal(self):
        self.assertEqual(has_double_slash_redirect("https://google.com/search"), 0)


class TestExtractFeatures(unittest.TestCase):
    def test_returns_correct_keys(self):
        feats = extract_features("https://www.google.com")
        self.assertEqual(set(feats.keys()), set(FEATURE_NAMES))

    def test_all_numeric(self):
        feats = extract_features("http://paypal-login.verify.tk/update?user=x")
        for k, v in feats.items():
            self.assertIsInstance(v, (int, float), f"Feature '{k}' is not numeric: {type(v)}")

    def test_phishing_vs_safe(self):
        """Phishing URL should score higher on multiple risk features."""
        safe_f     = extract_features("https://www.google.com")
        phishing_f = extract_features("http://paypal-secure-verify-login.account-suspended.tk/update")

        # Phishing URL should be longer
        self.assertGreater(phishing_f["url_length"], safe_f["url_length"])
        # Phishing URL should have suspicious TLD
        self.assertEqual(phishing_f["has_suspicious_tld"], 1)
        # Phishing URL should have suspicious keywords
        self.assertGreater(phishing_f["num_suspicious_keywords"], 0)
        # Safe URL should have HTTPS
        self.assertEqual(safe_f["has_https"], 1)


if __name__ == "__main__":
    # Run tests with verbose output
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(unittest.TestLoader().loadTestsFromModule(
        __import__(__name__)
    ))
    sys.exit(0 if result.wasSuccessful() else 1)
