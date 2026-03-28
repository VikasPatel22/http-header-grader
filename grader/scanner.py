"""
HTTP scanner: fetches headers from a URL, following redirects.
"""
import urllib.request
import urllib.error
import urllib.parse
import ssl
from typing import Tuple, Dict, Optional


def fetch_headers(url: str, timeout: int = 10) -> Tuple[Dict[str, str], int, str]:
    """
    Fetch HTTP response headers from a URL.

    Returns:
        (headers_dict, status_code, final_url)

    headers_dict keys are lowercase.
    """
    # Ensure scheme
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "http-header-grader/1.0 (security scanner; +https://github.com/VikasPatel22/http-header-grader)"
        },
    )

    # Allow self-signed certs for scanning purposes
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
            headers = dict(response.headers)
            # Normalize to lowercase keys
            headers_lower = {k.lower(): v for k, v in headers.items()}
            return headers_lower, response.status, response.url
    except urllib.error.HTTPError as e:
        # Still return headers even on error responses
        headers_lower = {k.lower(): v for k, v in dict(e.headers).items()}
        return headers_lower, e.code, url
    except urllib.error.URLError as e:
        raise ConnectionError(f"Cannot reach {url}: {e.reason}")


def check_https_redirect(url: str) -> bool:
    """Check if HTTP redirects to HTTPS."""
    http_url = url.replace("https://", "http://")
    try:
        req = urllib.request.Request(http_url, headers={"User-Agent": "http-header-grader/1.0"})
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
            return resp.url.startswith("https://")
    except Exception:
        return False
