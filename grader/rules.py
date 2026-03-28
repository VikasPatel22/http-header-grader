"""
Scoring rules for HTTP security headers.
Each rule defines what to look for and how to score it.
"""
from typing import Optional

HEADER_RULES = [
    {
        "header": "Strict-Transport-Security",
        "name": "HSTS",
        "weight": 15,
        "description": "Forces HTTPS for future visits, preventing SSL stripping attacks.",
        "check": lambda v: v is not None and "max-age" in v,
        "bonus": lambda v: v and "includeSubDomains" in v and "preload" in v,
        "fix": 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
        "docs": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
    },
    {
        "header": "Content-Security-Policy",
        "name": "CSP",
        "weight": 20,
        "description": "Controls which resources the browser can load — prevents XSS.",
        "check": lambda v: v is not None and len(v) > 10,
        "bonus": lambda v: v and "default-src" in v and "unsafe-inline" not in v,
        "fix": "Add: Content-Security-Policy: default-src 'self'; script-src 'self'",
        "docs": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
    },
    {
        "header": "X-Frame-Options",
        "name": "X-Frame-Options",
        "weight": 10,
        "description": "Prevents your page from being embedded in iframes (clickjacking).",
        "check": lambda v: v and v.upper() in ("DENY", "SAMEORIGIN"),
        "bonus": lambda _: False,
        "fix": "Add: X-Frame-Options: DENY",
        "docs": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
    },
    {
        "header": "X-Content-Type-Options",
        "name": "X-Content-Type-Options",
        "weight": 10,
        "description": "Prevents MIME-type sniffing attacks.",
        "check": lambda v: v and v.lower() == "nosniff",
        "bonus": lambda _: False,
        "fix": "Add: X-Content-Type-Options: nosniff",
        "docs": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
    },
    {
        "header": "Referrer-Policy",
        "name": "Referrer-Policy",
        "weight": 8,
        "description": "Controls how much referrer info is included with requests.",
        "check": lambda v: v and v in (
            "no-referrer", "no-referrer-when-downgrade",
            "strict-origin", "strict-origin-when-cross-origin",
        ),
        "bonus": lambda _: False,
        "fix": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "docs": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
    },
    {
        "header": "Permissions-Policy",
        "name": "Permissions-Policy",
        "weight": 10,
        "description": "Restricts browser features (camera, mic, geolocation) for your page.",
        "check": lambda v: v is not None,
        "bonus": lambda v: v and "camera=()" in v and "microphone=()" in v,
        "fix": "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
        "docs": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
    },
    {
        "header": "X-XSS-Protection",
        "name": "X-XSS-Protection",
        "weight": 5,
        "description": "Legacy XSS filter for older browsers (deprecated but still checked).",
        "check": lambda v: v and v.startswith("1"),
        "bonus": lambda _: False,
        "fix": "Add: X-XSS-Protection: 1; mode=block",
        "docs": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection",
    },
    {
        "header": "Cache-Control",
        "name": "Cache-Control",
        "weight": 7,
        "description": "Controls caching of sensitive pages. Private data should not be cached.",
        "check": lambda v: v and ("no-store" in v or "private" in v),
        "bonus": lambda _: False,
        "fix": "For sensitive pages: Cache-Control: no-store, no-cache, must-revalidate",
        "docs": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control",
    },
    {
        "header": "Cross-Origin-Opener-Policy",
        "name": "COOP",
        "weight": 5,
        "description": "Isolates your page from cross-origin popups (Spectre mitigations).",
        "check": lambda v: v and v in ("same-origin", "same-origin-allow-popups"),
        "bonus": lambda _: False,
        "fix": "Add: Cross-Origin-Opener-Policy: same-origin",
        "docs": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy",
    },
    {
        "header": "Cross-Origin-Resource-Policy",
        "name": "CORP",
        "weight": 5,
        "description": "Controls which origins can embed your resources.",
        "check": lambda v: v and v in ("same-origin", "same-site", "cross-origin"),
        "bonus": lambda _: False,
        "fix": "Add: Cross-Origin-Resource-Policy: same-origin",
        "docs": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy",
    },
]


def evaluate_header(rule: dict, headers: dict) -> dict:
    """Evaluate one header rule against the response headers."""
    value = headers.get(rule["header"].lower())
    passed = bool(rule["check"](value))
    has_bonus = passed and bool(rule["bonus"](value))

    score = 0
    if passed:
        score = rule["weight"]
        if has_bonus:
            score = int(score * 1.1)  # 10% bonus for best-practice config

    return {
        "header": rule["header"],
        "name": rule["name"],
        "present": value is not None,
        "value": value or "— not set —",
        "passed": passed,
        "best_practice": has_bonus,
        "score": score,
        "max_score": rule["weight"],
        "description": rule["description"],
        "fix": rule["fix"],
        "docs": rule["docs"],
    }
