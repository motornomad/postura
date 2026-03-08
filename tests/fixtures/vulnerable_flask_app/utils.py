"""Utility functions — INTENTIONALLY VULNERABLE."""
import urllib.request


def fetch_url(url):
    """CWE-918: SSRF — takes user-supplied URL without validation."""
    response = urllib.request.urlopen(url)
    return response.read().decode("utf-8")


def sanitize_input(text):
    """Minimal sanitization — does not protect against SQL injection."""
    return text.strip()
