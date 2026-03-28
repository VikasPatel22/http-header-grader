#!/usr/bin/env python3
"""
HTTP Header Security Grader — CLI entry point.
Scans a URL and outputs a color-coded A–F security report.
"""
import argparse
import json
import sys

from .scanner import fetch_headers, check_https_redirect
from .rules import HEADER_RULES, evaluate_header

COLORS = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "red": "\033[91m", "yellow": "\033[93m", "green": "\033[92m",
    "cyan": "\033[96m", "magenta": "\033[95m", "white": "\033[97m",
}

GRADE_COLORS = {
    "A": "\033[92m", "B": "\033[96m", "C": "\033[93m",
    "D": "\033[91m", "F": "\033[91m\033[1m",
}

def c(color, text, no_color=False):
    if no_color:
        return text
    return f"{COLORS.get(color, '')}{text}{COLORS['reset']}"


def compute_grade(score: int, max_score: int) -> str:
    pct = (score / max_score) * 100 if max_score else 0
    if pct >= 90: return "A"
    if pct >= 75: return "B"
    if pct >= 60: return "C"
    if pct >= 40: return "D"
    return "F"


def run_scan(url: str) -> dict:
    headers, status_code, final_url = fetch_headers(url)
    https_redirect = check_https_redirect(url)

    results = [evaluate_header(rule, headers) for rule in HEADER_RULES]
    total_score = sum(r["score"] for r in results)
    max_score = sum(r["max_score"] for r in results)
    grade = compute_grade(total_score, max_score)

    return {
        "url": final_url,
        "status_code": status_code,
        "https_redirect": https_redirect,
        "grade": grade,
        "score": total_score,
        "max_score": max_score,
        "percentage": round((total_score / max_score) * 100, 1) if max_score else 0,
        "results": results,
        "missing": [r for r in results if not r["passed"]],
        "passed": [r for r in results if r["passed"]],
    }


def print_report(scan: dict, no_color: bool = False):
    grade = scan["grade"]
    grade_str = f"{GRADE_COLORS.get(grade, '')}{grade}{COLORS['reset']}" if not no_color else grade

    print(f"\n{'─'*58}")
    print(f"  HTTP SECURITY REPORT")
    print(f"{'─'*58}")
    print(f"  URL     : {scan['url']}")
    print(f"  Status  : {scan['status_code']}")
    print(f"  HTTPS ↩ : {'Yes ✓' if scan['https_redirect'] else 'No ✗'}")
    print(f"  Grade   : {grade_str}   Score: {scan['score']}/{scan['max_score']} ({scan['percentage']}%)")
    print(f"{'─'*58}\n")

    # Passed headers
    if scan["passed"]:
        print(c("green", f"  ✓ PASSING ({len(scan['passed'])})", no_color))
        for r in scan["passed"]:
            bp = c("dim", " [best practice]", no_color) if r["best_practice"] else ""
            print(f"    {c('green', '✓', no_color)} {r['name']}{bp}")
            print(c("dim", f"        {r['value'][:80]}", no_color))
        print()

    # Missing / failed headers
    if scan["missing"]:
        print(c("red", f"  ✗ MISSING / MISCONFIGURED ({len(scan['missing'])})", no_color))
        for r in scan["missing"]:
            status = "not set" if not r["present"] else "misconfigured"
            print(f"\n    {c('red', '✗', no_color)} {c('bold', r['name'], no_color)} ({status}) — -{r['max_score']}pts")
            print(c("dim", f"       {r['description']}", no_color))
            print(f"       {c('cyan', '→ Fix: ', no_color)}{r['fix']}")
            print(c("dim", f"       Docs: {r['docs']}", no_color))

    print(f"\n{'─'*58}\n")


def main():
    parser = argparse.ArgumentParser(
        prog="http-header-grader",
        description="Grade the HTTP security headers of any website.",
    )
    parser.add_argument("url", help="URL to scan (e.g. https://example.com)")
    parser.add_argument("--json", "-j", action="store_true", help="Output JSON")
    parser.add_argument("--no-color", action="store_true")
    args = parser.parse_args()

    print(f"Scanning {args.url}...")
    try:
        scan = run_scan(args.url)
    except ConnectionError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if args.json:
        print(json.dumps(scan, indent=2))
    else:
        print_report(scan, no_color=args.no_color)

    sys.exit(0 if scan["grade"] in ("A", "B") else 1)


if __name__ == "__main__":
    main()
