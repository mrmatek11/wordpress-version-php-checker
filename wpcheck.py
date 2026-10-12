#!/usr/bin/env python3
"""
wpcheck - detect the WordPress version and PHP version of a site by URL.

Zero dependencies (Python 3.8+ standard library only).

Usage:
    python3 wpcheck.py example.com
    python3 wpcheck.py https://a.com https://b.com --json
    python3 wpcheck.py -f sites.txt -w 10
"""

import argparse
import concurrent.futures
import json
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter

__version__ = "1.0.0"

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"
)
MAX_BODY = 2 * 1024 * 1024  # read at most 2 MB per response

# Minimum PHP version required by WordPress core, by WP release.
# (first WP version with that requirement, minimum PHP)
WP_MIN_PHP = [
    ((6, 6), "7.2.24"),
    ((6, 3), "7.0.0"),
    ((5, 2), "5.6.20"),
    ((3, 2), "5.2.4"),
]

VERSION_RE = r"(\d+\.\d+(?:\.\d+)?)"
PHP_RE = re.compile(r"PHP/?\s*(\d+\.\d+(?:\.\d+)?)", re.I)


class Fetcher:
    def __init__(self, timeout, user_agent, insecure):
        self.timeout = timeout
        self.user_agent = user_agent
        self.ctx = ssl.create_default_context()
        if insecure:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE

    def get(self, url):
        """Return (status, headers, body_text, final_url) or None on network error."""
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": self.user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            },
        )
        try:
            resp = urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx)
        except urllib.error.HTTPError as e:
            resp = e  # 4xx/5xx still carry headers (and often X-Powered-By)
        except (urllib.error.URLError, OSError, ValueError):
            return None
        try:
            raw = resp.read(MAX_BODY)
        except Exception:
            raw = b""
        charset = resp.headers.get_content_charset() or "utf-8"
        body = raw.decode(charset, errors="replace")
        return resp.status if hasattr(resp, "status") else resp.code, resp.headers, body, resp.geturl()


def normalize_url(url):
    url = url.strip()
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    parts = urllib.parse.urlsplit(url)
    path = parts.path if parts.path.endswith("/") else parts.path + "/"
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, path, "", ""))


def vtuple(v):
    return tuple(int(x) for x in v.split("."))


def min_php_for(wp_version):
    try:
        v = vtuple(wp_version)[:2]
    except ValueError:
        return None
    for since, php in WP_MIN_PHP:
        if v >= since:
            return php
    return None


def php_from_headers(headers):
    found = []
    for name in ("X-Powered-By", "Server", "X-PHP-Version"):
        for value in headers.get_all(name) or []:
            m = PHP_RE.search(value) or (
                name == "X-PHP-Version" and re.search(VERSION_RE, value)
            )
            if m:
                found.append((m.group(1), f"header {name}: {value.strip()}"))
    return found


def wp_from_html(html):
    """Version hints in an HTML page. Returns list of (version, source, weight)."""
    hits = []
    m = re.search(
        r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s+' + VERSION_RE,
        html, re.I,
    ) or re.search(
        r'<meta[^>]+content=["\']WordPress\s+' + VERSION_RE + r'[^>]+name=["\']generator["\']',
        html, re.I,
    )
    if m:
        hits.append((m.group(1), "meta generator tag", 3))
    # ?ver= on core assets only (plugins/themes use their own versions)
    for m in re.finditer(r'/wp-includes/([^"\'\s>]+?)\?ver=' + VERSION_RE, html, re.I):
        if "jquery" in m.group(1).lower():
            continue  # bundled jQuery carries its own version
        hits.append((m.group(2), "wp-includes asset ?ver=", 1))
    for m in re.finditer(r'/wp-admin/[^"\'\s>]+?\?ver=' + VERSION_RE, html, re.I):
        hits.append((m.group(1), "wp-admin asset ?ver=", 1))
    m = re.search(r'wp-emoji-release\.min\.js\?ver=' + VERSION_RE, html, re.I)
    if m:
        hits.append((m.group(1), "wp-emoji script ?ver=", 1))
    return hits


def looks_like_wp(status, headers, body):
    link = " ".join(headers.get_all("Link") or [])
    if "api.w.org" in link:
        return True
    return bool(re.search(r"/wp-(content|includes)/", body or ""))


def check_site(url, fetcher):
    base = normalize_url(url)
    result = {
        "url": base,
        "reachable": False,
        "is_wordpress": False,
        "wordpress_version": None,
        "wordpress_sources": [],
        "php_version": None,
        "php_sources": [],
        "php_min_required_by_wp": None,
        "error": None,
    }

    home = fetcher.get(base)
    if home is None and base.startswith("https://"):
        base = "http://" + base[len("https://"):]
        home = fetcher.get(base)
        result["url"] = base
    if home is None:
        result["error"] = "connection failed"
        return result

    result["reachable"] = True
    status, headers, body, final = home
    if final:
        base = normalize_url(final)
        result["url"] = base

    wp_hits = []
    php_hits = []
    is_wp = looks_like_wp(status, headers, body)

    php_hits += php_from_headers(headers)
    wp_hits += wp_from_html(body)

    # Extra endpoints. Each returns (path, kind).
    probes = [
        ("feed/", "feed"),
        ("wp-login.php", "html"),
        ("wp-links-opml.php", "opml"),
        ("readme.html", "readme"),
        ("xmlrpc.php", "headers"),
        ("wp-json/", "json"),
    ]
    for path, kind in probes:
        resp = fetcher.get(urllib.parse.urljoin(base, path))
        if resp is None:
            continue
        st, hd, bd, _ = resp
        php_hits += php_from_headers(hd)
        if st >= 400:
            continue
        if kind == "feed":
            m = re.search(r"<generator>https?://wordpress\.org/\?v=" + VERSION_RE, bd, re.I)
            if m:
                is_wp = True
                wp_hits.append((m.group(1), "RSS feed <generator>", 3))
        elif kind == "html":
            if "wp-login" in bd or "wp-submit" in bd:
                is_wp = True
            wp_hits += wp_from_html(bd)
        elif kind == "opml":
            m = re.search(r'generator=["\']WordPress/' + VERSION_RE, bd, re.I)
            if m:
                is_wp = True
                wp_hits.append((m.group(1), "wp-links-opml.php generator", 3))
        elif kind == "readme":
            m = re.search(r"<br\s*/?>\s*(?:Version|wersja)\s+" + VERSION_RE, bd, re.I)
            if m and "WordPress" in bd:
                is_wp = True
                wp_hits.append((m.group(1), "readme.html", 2))
        elif kind == "headers":
            if "XML-RPC server accepts POST requests only" in bd:
                is_wp = True
        elif kind == "json":
            if '"namespaces"' in bd and "wp/v2" in bd:
                is_wp = True

    result["is_wordpress"] = is_wp or bool(wp_hits)

    if wp_hits:
        score = Counter()
        sources = {}
        for v, src, w in wp_hits:
            score[v] += w
            sources.setdefault(v, [])
            if src not in sources[v]:
                sources[v].append(src)
        best = max(score, key=lambda v: (score[v], vtuple(v)))
        result["wordpress_version"] = best
        result["wordpress_sources"] = sources[best]
        result["php_min_required_by_wp"] = min_php_for(best)

    if php_hits:
        counts = Counter(v for v, _ in php_hits)
        best = max(counts, key=lambda v: (counts[v], len(v)))
        result["php_version"] = best
        seen = []
        for v, src in php_hits:
            if v == best and src not in seen:
                seen.append(src)
        result["php_sources"] = seen

    return result


def color(s, code, enabled):
    return f"\033[{code}m{s}\033[0m" if enabled else s


def print_human(r, use_color, verbose):
    g = lambda s: color(s, "32", use_color)
    y = lambda s: color(s, "33", use_color)
    red = lambda s: color(s, "31", use_color)
    b = lambda s: color(s, "1", use_color)

    print(b(r["url"]))
    if not r["reachable"]:
        print("  " + red(f"error: {r['error']}"))
        print()
        return
    print("  WordPress : " + (g("yes") if r["is_wordpress"] else y("not detected")))
    wp = r["wordpress_version"]
    print("  WP version: " + (g(wp) if wp else y("unknown (hidden)")))
    if verbose and r["wordpress_sources"]:
        print("              via " + ", ".join(r["wordpress_sources"]))
    php = r["php_version"]
    print("  PHP       : " + (g(php) if php else y("unknown (hidden)")))
    if verbose and r["php_sources"]:
        for s in r["php_sources"]:
            print("              via " + s)
    if not php and r["php_min_required_by_wp"]:
        print("              " + f"(WP {wp} requires PHP >= {r['php_min_required_by_wp']})")
    print()


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="wpcheck",
        description="Detect WordPress version and PHP version of websites.",
    )
    p.add_argument("urls", nargs="*", help="site URL(s) or domain(s)")
    p.add_argument("-f", "--file", help="file with one URL per line ('-' for stdin)")
    p.add_argument("-j", "--json", action="store_true", help="output JSON")
    p.add_argument("-v", "--verbose", action="store_true", help="show where each version was found")
    p.add_argument("-t", "--timeout", type=float, default=10, help="request timeout in seconds (default 10)")
    p.add_argument("-w", "--workers", type=int, default=5, help="sites checked in parallel (default 5)")
    p.add_argument("-k", "--insecure", action="store_true", help="don't verify TLS certificates")
    p.add_argument("--user-agent", default=DEFAULT_UA, help="custom User-Agent")
    p.add_argument("--no-color", action="store_true", help="disable colored output")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = p.parse_args(argv)

    urls = list(args.urls)
    if args.file:
        fh = sys.stdin if args.file == "-" else open(args.file, encoding="utf-8")
        with fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    urls.append(line)
    if not urls:
        p.print_help()
        return 2

    fetcher = Fetcher(args.timeout, args.user_agent, args.insecure)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
        results = list(ex.map(lambda u: check_site(u, fetcher), urls))

    if args.json:
        print(json.dumps(results if len(results) > 1 else results[0], indent=2))
    else:
        use_color = sys.stdout.isatty() and not args.no_color
        for r in results:
            print_human(r, use_color, args.verbose)

    return 0 if all(r["reachable"] for r in results) else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
