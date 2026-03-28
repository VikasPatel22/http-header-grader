# http-header-grader

> **Scan any website and get an A–F security grade based on its HTTP headers. Zero dependencies — pure Python stdlib.**

Checks 10 critical security headers (CSP, HSTS, X-Frame-Options, and more), explains what each does, and tells you exactly how to fix what's missing.

---

## Install

```bash
pip install http-header-grader
# or
git clone https://github.com/VikasPatel22/http-header-grader && pip install -e .
```

---

## Usage

```bash
http-header-grader https://example.com
http-header-grader https://example.com --json
http-header-grader https://example.com --no-color   # for CI
```

---

## Example Output

```
──────────────────────────────────────────────────────────
  HTTP SECURITY REPORT
──────────────────────────────────────────────────────────
  URL     : https://example.com
  Status  : 200
  HTTPS ↩ : Yes ✓
  Grade   : B   Score: 62/95 (65.3%)
──────────────────────────────────────────────────────────

  ✓ PASSING (4)
    ✓ HSTS  [best practice]
        max-age=31536000; includeSubDomains; preload
    ✓ X-Content-Type-Options
        nosniff

  ✗ MISSING / MISCONFIGURED (6)

    ✗ CSP (not set) — -20pts
       Controls which resources the browser can load — prevents XSS.
       → Fix: Content-Security-Policy: default-src 'self'; script-src 'self'
       Docs: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP

    ✗ Permissions-Policy (not set) — -10pts
       ...
```

---

## Headers Checked

| Header | Weight | What it prevents |
|--------|--------|-----------------|
| `Content-Security-Policy` | 20pts | XSS attacks |
| `Strict-Transport-Security` | 15pts | SSL stripping |
| `X-Frame-Options` | 10pts | Clickjacking |
| `X-Content-Type-Options` | 10pts | MIME sniffing |
| `Permissions-Policy` | 10pts | Feature abuse |
| `Referrer-Policy` | 8pts | Referrer leakage |
| `Cache-Control` | 7pts | Sensitive data caching |
| `X-XSS-Protection` | 5pts | Legacy XSS filter |
| `COOP` | 5pts | Cross-origin isolation |
| `CORP` | 5pts | Resource embedding |

---

## Grading Scale

| Score | Grade |
|-------|-------|
| ≥ 90% | A |
| ≥ 75% | B |
| ≥ 60% | C |
| ≥ 40% | D |
| < 40% | F |

Exit code `0` for A/B, `1` for C/D/F — CI/CD friendly.

---

## File Structure

```
http-header-grader/
├── grader/
│   ├── scanner.py         # Fetch headers, HTTPS redirect check
│   ├── rules.py           # Per-header scoring rules
│   └── cli.py             # CLI entry + color report renderer
├── tests/
│   └── test_rules.py
└── pyproject.toml
```

---

## License

MIT © Vikas Patel
