#!/usr/bin/env python3
"""
wpaudit - defensive WordPress security audit by URL.

READ-ONLY. It sends ordinary GET requests, the same ones a browser makes.
It does NOT log in, guess passwords, brute-force, exploit, or change
anything on the target. It only reads publicly available information and
reports what it finds. Use it only on sites you own or are explicitly
authorized to test.

It builds on wpcheck.py (WordPress + PHP version detection) and adds:
  * plugin and theme enumeration, with versions
  * common misconfiguration / information-exposure checks
  * matching of detected versions against a local vulnerability database
    (optionally refreshed from a public API)
  * text, JSON and HTML reports

Usage:
    python3 wpaudit.py example.com
    python3 wpaudit.py example.com --html report.html
    python3 wpaudit.py -f sites.txt --json > audit.json
"""

import argparse
import html as html_mod
import json
import os
import re
import sys
import urllib.parse

import wpcheck
import vulnfeed

__version__ = "1.1.0"

DATA_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "vulnerabilities.json")

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# ---------------------------------------------------------------------------
# version helpers
# ---------------------------------------------------------------------------

def parse_version(v):
    """'1.2.3' -> (1,2,3). Non-numeric parts are dropped; returns None if empty."""
    if not v:
        return None
    nums = re.findall(r"\d+", v)
    return tuple(int(n) for n in nums) if nums else None


def vcmp(a, b):
    """Compare two version strings. -1 / 0 / 1. Unparseable sorts lowest."""
    pa, pb = parse_version(a), parse_version(b)
    if pa is None and pb is None:
        return 0
    if pa is None:
        return -1
    if pb is None:
        return 1
    n = max(len(pa), len(pb))
    pa += (0,) * (n - len(pa))
    pb += (0,) * (n - len(pb))
    return (pa > pb) - (pa < pb)


# ---------------------------------------------------------------------------
# enumeration
# ---------------------------------------------------------------------------

PLUGIN_PATH_RE = re.compile(r"/wp-content/plugins/([a-z0-9][a-z0-9._-]*)/", re.I)
THEME_PATH_RE = re.compile(r"/wp-content/themes/([a-z0-9][a-z0-9._-]*)/", re.I)
STABLE_TAG_RE = re.compile(r"^\s*Stable tag:\s*([^\s]+)\s*$", re.I | re.M)
README_VERSION_RE = re.compile(r"^\s*Version:\s*([^\s]+)\s*$", re.I | re.M)
STYLE_VERSION_RE = re.compile(r"^\s*Version:\s*(.+?)\s*$", re.I | re.M)


def _collect_slugs(regex, *texts):
    seen = []
    for t in texts:
        if not t:
            continue
        for m in regex.finditer(t):
            slug = m.group(1).lower()
            if slug not in seen and slug not in ("", "index.php"):
                seen.append(slug)
    return seen


def _plugin_readme(base, fetcher, slug):
    """Return (version, source, present) by reading the plugin's readme.txt."""
    for fname in ("readme.txt", "README.txt", "Readme.txt"):
        resp = fetcher.get(urllib.parse.urljoin(base, f"wp-content/plugins/{slug}/{fname}"))
        if resp is None:
            continue
        st, _, body, _ = resp
        if st >= 400 or not body:
            continue
        # a genuine plugin readme contains a header section
        present = ("stable tag" in body.lower() or "=== " in body or "== description ==" in body.lower())
        m = STABLE_TAG_RE.search(body) or README_VERSION_RE.search(body)
        version = m.group(1) if (m and m.group(1).lower() != "trunk") else None
        return version, f"{fname} Stable tag" if version else f"{fname}", present
    return None, "referenced in page", False


def _theme_style(base, fetcher, slug):
    resp = fetcher.get(urllib.parse.urljoin(base, f"wp-content/themes/{slug}/style.css"))
    if resp is None:
        return None, "referenced in page", False
    st, _, body, _ = resp
    if st >= 400 or not body:
        return None, "referenced in page", False
    present = "theme name:" in body[:4000].lower()
    m = STYLE_VERSION_RE.search(body[:4000])
    version = m.group(1).strip() if m else None
    return version, "style.css Version" if version else "style.css", present


def enumerate_plugins(base, fetcher, html_texts, wordlist=None):
    referenced = _collect_slugs(PLUGIN_PATH_RE, *html_texts)
    plugins = []
    for slug in referenced:
        version, source, _ = _plugin_readme(base, fetcher, slug)
        plugins.append({"slug": slug, "version": version, "source": source, "detection": "passive"})
    if wordlist:
        known = {p["slug"] for p in plugins}
        for slug in wordlist:
            if slug in known:
                continue
            version, source, present = _plugin_readme(base, fetcher, slug)
            if present:  # only report wordlist hits we can actually confirm
                plugins.append({"slug": slug, "version": version, "source": source, "detection": "aggressive"})
    return plugins


def enumerate_themes(base, fetcher, html_texts, wordlist=None):
    referenced = _collect_slugs(THEME_PATH_RE, *html_texts)
    themes = []
    for slug in referenced:
        version, source, _ = _theme_style(base, fetcher, slug)
        themes.append({"slug": slug, "version": version, "source": source, "detection": "passive"})
    if wordlist:
        known = {t["slug"] for t in themes}
        for slug in wordlist:
            if slug in known:
                continue
            version, source, present = _theme_style(base, fetcher, slug)
            if present:
                themes.append({"slug": slug, "version": version, "source": source, "detection": "aggressive"})
    return themes


# ---------------------------------------------------------------------------
# misconfiguration / information-exposure checks (read-only)
# ---------------------------------------------------------------------------

EXPOSED_FILES = [
    ("wp-config.php.bak", "critical", "Backup of wp-config.php may expose DB credentials"),
    ("wp-config.php.save", "critical", "Backup of wp-config.php may expose DB credentials"),
    ("wp-config.php~", "critical", "Editor backup of wp-config.php may expose DB credentials"),
    ("wp-config.php.old", "critical", "Backup of wp-config.php may expose DB credentials"),
    (".env", "critical", "Environment file may expose secrets and credentials"),
    (".git/config", "high", "Exposed .git directory can leak full source code"),
    ("debug.log", "medium", "Debug log may expose paths and errors"),
    ("wp-content/debug.log", "medium", "WordPress debug log may expose paths and errors"),
    ("readme.html", "low", "readme.html reveals the exact WordPress version"),
    ("wp-content/uploads/", "low", "Uploads directory listing may be enabled"),
]


def check_misconfig(base, fetcher):
    findings = []

    for path, severity, desc in EXPOSED_FILES:
        resp = fetcher.get(urllib.parse.urljoin(base, path))
        if resp is None:
            continue
        st, _, body, _ = resp
        if st != 200 or not body:
            continue
        if path.endswith("/"):
            if re.search(r"<title>\s*Index of", body, re.I) or "Parent Directory" in body:
                findings.append(_f("directory-listing", severity,
                                   f"Directory listing enabled: /{path}", desc, path))
            continue
        # avoid counting a soft-404 HTML page as a hit
        low = body.lower()
        if path == "readme.html" and "wordpress" not in low:
            continue
        if path == ".git/config" and "[core]" not in low:
            continue
        if path == ".env" and "<html" in low[:200]:
            continue
        findings.append(_f("exposed-file", severity,
                           f"Accessible file: /{path}", desc, path))

    # user enumeration via REST API
    resp = fetcher.get(urllib.parse.urljoin(base, "wp-json/wp/v2/users"))
    if resp is not None:
        st, _, body, _ = resp
        if st == 200 and body.strip().startswith("["):
            try:
                users = json.loads(body)
            except ValueError:
                users = []
            names = [u.get("slug") or u.get("name") for u in users if isinstance(u, dict)]
            names = [n for n in names if n]
            if names:
                findings.append(_f("user-enumeration", "medium",
                                   "User enumeration possible via REST API",
                                   "Login names are exposed at /wp-json/wp/v2/users: "
                                   + ", ".join(names[:10]) + ("..." if len(names) > 10 else ""),
                                   "wp-json/wp/v2/users"))

    # XML-RPC enabled
    resp = fetcher.get(urllib.parse.urljoin(base, "xmlrpc.php"))
    if resp is not None:
        st, _, body, _ = resp
        if "XML-RPC server accepts POST requests only" in (body or ""):
            findings.append(_f("xmlrpc-enabled", "low",
                               "XML-RPC endpoint is enabled",
                               "xmlrpc.php is reachable. If unused, disabling it reduces the "
                               "attack surface (login amplification, pingback abuse).",
                               "xmlrpc.php"))

    # missing security headers (checked on the home page)
    home = fetcher.get(base)
    if home is not None:
        _, headers, _, _ = home
        present = {k.lower() for k in headers.keys()}
        wanted = {
            "content-security-policy": "Content-Security-Policy",
            "strict-transport-security": "Strict-Transport-Security (HSTS)",
            "x-frame-options": "X-Frame-Options",
            "x-content-type-options": "X-Content-Type-Options",
            "referrer-policy": "Referrer-Policy",
        }
        missing = [label for key, label in wanted.items() if key not in present]
        if missing:
            findings.append(_f("missing-headers", "info",
                               "Missing recommended security headers",
                               "Not set: " + ", ".join(missing), base))

    return findings


def _f(check, severity, title, detail, where):
    return {"check": check, "severity": severity, "title": title,
            "detail": detail, "location": where}


# ---------------------------------------------------------------------------
# vulnerability matching
# ---------------------------------------------------------------------------

def load_vuln_db(path):
    if not path or not os.path.exists(path):
        return {"core": [], "plugins": {}, "themes": {}, "_meta": {}}
    with open(path, encoding="utf-8") as fh:
        db = json.load(fh)
    db.setdefault("core", [])
    db.setdefault("plugins", {})
    db.setdefault("themes", {})
    return db


def _is_affected(version, entry):
    """True if `version` falls in the vulnerable range described by `entry`.

    Model: affected when  introduced <= version < fixed_in  (fixed_in exclusive).
    Missing introduced means "any earlier version". Missing fixed_in means
    "not fixed yet" -> affected for any version at/below max_affected (or always,
    if neither bound given).
    """
    if version is None:
        return False
    intro = entry.get("introduced")
    fixed = entry.get("fixed_in")
    maxaff = entry.get("max_affected")
    if intro and vcmp(version, intro) < 0:
        return False
    if fixed:
        return vcmp(version, fixed) < 0
    if maxaff:
        return vcmp(version, maxaff) <= 0
    return True


def match_vulns(db, wp_version, plugins, themes):
    vulns = []

    def add(entries, version, kind, name):
        for e in entries or []:
            if _is_affected(version, e):
                vulns.append({
                    "component": kind,
                    "name": name,
                    "installed_version": version,
                    "id": e.get("id", ""),
                    "title": e.get("title", ""),
                    "severity": (e.get("severity") or "medium").lower(),
                    "fixed_in": e.get("fixed_in"),
                    "references": e.get("references", []),
                })

    if wp_version:
        add(db.get("core"), wp_version, "core", "WordPress core")
    for p in plugins:
        if p.get("version"):
            add(db.get("plugins", {}).get(p["slug"]), p["version"], "plugin", p["slug"])
    for t in themes:
        if t.get("version"):
            add(db.get("themes", {}).get(t["slug"]), t["version"], "theme", t["slug"])

    vulns.sort(key=lambda v: SEVERITY_ORDER.get(v["severity"], 2), reverse=True)
    return vulns


# ---------------------------------------------------------------------------
# audit driver
# ---------------------------------------------------------------------------

def audit_site(url, fetcher, db, do_config=True, plugin_wordlist=None, theme_wordlist=None):
    base = wpcheck.normalize_url(url)
    report = {
        "url": base,
        "reachable": False,
        "is_wordpress": False,
        "wordpress_version": None,
        "php_version": None,
        "php_min_required_by_wp": None,
        "plugins": [],
        "themes": [],
        "misconfigurations": [],
        "vulnerabilities": [],
        "error": None,
    }

    core = wpcheck.check_site(base, fetcher)
    report["url"] = core["url"]
    report["reachable"] = core["reachable"]
    report["error"] = core["error"]
    if not core["reachable"]:
        return report

    base = core["url"]
    report["is_wordpress"] = core["is_wordpress"]
    report["wordpress_version"] = core["wordpress_version"]
    report["php_version"] = core["php_version"]
    report["php_min_required_by_wp"] = core["php_min_required_by_wp"]

    home = fetcher.get(base)
    login = fetcher.get(urllib.parse.urljoin(base, "wp-login.php"))
    html_texts = [home[2] if home else "", login[2] if login else ""]

    report["plugins"] = enumerate_plugins(base, fetcher, html_texts, plugin_wordlist)
    report["themes"] = enumerate_themes(base, fetcher, html_texts, theme_wordlist)
    if do_config:
        report["misconfigurations"] = check_misconfig(base, fetcher)
    report["vulnerabilities"] = match_vulns(
        db, report["wordpress_version"], report["plugins"], report["themes"])

    return report


def rematch(report, db):
    report["vulnerabilities"] = match_vulns(
        db, report["wordpress_version"], report["plugins"], report["themes"])


def enrich_db_online(db, source, reports, cache_path=None):
    """Query an online source for every component seen across reports and merge
    the results into `db` (deduped by id). Returns number of entries added."""
    added = 0

    def merge(bucket, entries):
        nonlocal added
        existing = {e.get("id") for e in bucket if e.get("id")}
        for e in entries or []:
            if e.get("id") and e["id"] in existing:
                continue
            bucket.append(e)
            existing.add(e.get("id"))
            added += 1

    cores, plugins, themes = set(), set(), set()
    for r in reports:
        if r.get("wordpress_version"):
            cores.add(r["wordpress_version"])
        for p in r.get("plugins", []):
            if p.get("version"):
                plugins.add(p["slug"])
        for t in r.get("themes", []):
            if t.get("version"):
                themes.add(t["slug"])

    for v in sorted(cores):
        merge(db["core"], source.lookup_core(v))
    for slug in sorted(plugins):
        merge(db["plugins"].setdefault(slug, []), source.lookup_plugin(slug))
    for slug in sorted(themes):
        merge(db["themes"].setdefault(slug, []), source.lookup_theme(slug))

    if cache_path:
        try:
            db.setdefault("_meta", {})["source"] = source.name
            with open(cache_path, "w", encoding="utf-8") as fh:
                json.dump(db, fh, indent=2)
        except OSError:
            pass
    return added


# ---------------------------------------------------------------------------
# output
# ---------------------------------------------------------------------------

def _c(s, code, on):
    return f"\033[{code}m{s}\033[0m" if on else s


SEV_COLOR = {"critical": "1;31", "high": "31", "medium": "33", "low": "36", "info": "37"}


def print_text(r, on):
    b = lambda s: _c(s, "1", on)
    print(b(r["url"]))
    if not r["reachable"]:
        print("  " + _c(f"error: {r['error']}", "31", on) + "\n")
        return
    print("  WordPress : " + ("yes" if r["is_wordpress"] else "not detected"))
    print("  WP version: " + (r["wordpress_version"] or "unknown (hidden)"))
    php = r["php_version"] or "unknown (hidden)"
    print("  PHP       : " + php)
    if not r["php_version"] and r["php_min_required_by_wp"]:
        print(f"              (WP requires PHP >= {r['php_min_required_by_wp']})")

    def _mark(x):
        return " *" if x.get("detection") == "aggressive" else ""

    if r["plugins"]:
        print(b("  Plugins:"))
        for p in r["plugins"]:
            print(f"    - {p['slug']} {p['version'] or '(version unknown)'}{_mark(p)}")
    if r["themes"]:
        print(b("  Themes:"))
        for t in r["themes"]:
            print(f"    - {t['slug']} {t['version'] or '(version unknown)'}{_mark(t)}")

    if r["misconfigurations"]:
        print(b("  Misconfigurations:"))
        for m in r["misconfigurations"]:
            tag = _c(f"[{m['severity'].upper()}]", SEV_COLOR.get(m["severity"], "37"), on)
            print(f"    {tag} {m['title']}")
            print(f"           {m['detail']}")

    if r["vulnerabilities"]:
        print(b("  Known vulnerabilities (version-based, verify manually):"))
        for v in r["vulnerabilities"]:
            tag = _c(f"[{v['severity'].upper()}]", SEV_COLOR.get(v["severity"], "37"), on)
            fixed = f" (fixed in {v['fixed_in']})" if v.get("fixed_in") else ""
            ident = f" {v['id']}" if v["id"] else ""
            print(f"    {tag} {v['name']} {v['installed_version']}:{ident} {v['title']}{fixed}")
    elif r["is_wordpress"]:
        print("  No known vulnerabilities matched the local database.")
    print()


def render_html(reports, db_meta):
    esc = html_mod.escape
    rows = []
    for r in reports:
        if not r["reachable"]:
            rows.append(f'<section class="site"><h2>{esc(r["url"])}</h2>'
                        f'<p class="err">Not reachable: {esc(r["error"] or "")}</p></section>')
            continue
        parts = [f'<section class="site"><h2>{esc(r["url"])}</h2>']
        parts.append('<table class="meta"><tbody>')
        parts.append(f'<tr><th>WordPress</th><td>{"yes" if r["is_wordpress"] else "not detected"}</td></tr>')
        parts.append(f'<tr><th>WP version</th><td>{esc(r["wordpress_version"] or "unknown")}</td></tr>')
        parts.append(f'<tr><th>PHP version</th><td>{esc(r["php_version"] or "unknown")}</td></tr>')
        parts.append('</tbody></table>')

        def listing(title, items, vkey):
            if not items:
                return ""
            lis = "".join(
                f"<li>{esc(i['slug'])} <span class='ver'>{esc(i[vkey] or 'version unknown')}</span></li>"
                for i in items)
            return f"<h3>{title} ({len(items)})</h3><ul class='comp'>{lis}</ul>"

        parts.append(listing("Plugins", r["plugins"], "version"))
        parts.append(listing("Themes", r["themes"], "version"))

        if r["misconfigurations"]:
            parts.append("<h3>Misconfigurations</h3>")
            for m in r["misconfigurations"]:
                parts.append(
                    f'<div class="finding sev-{esc(m["severity"])}">'
                    f'<span class="badge">{esc(m["severity"].upper())}</span> '
                    f'<strong>{esc(m["title"])}</strong>'
                    f'<p>{esc(m["detail"])}</p></div>')
        if r["vulnerabilities"]:
            parts.append("<h3>Known vulnerabilities <small>(version-based — verify manually)</small></h3>")
            for v in r["vulnerabilities"]:
                refs = "".join(f'<a href="{esc(u)}">ref</a> ' for u in v.get("references", []))
                fixed = f' &middot; fixed in {esc(v["fixed_in"])}' if v.get("fixed_in") else ""
                parts.append(
                    f'<div class="finding sev-{esc(v["severity"])}">'
                    f'<span class="badge">{esc(v["severity"].upper())}</span> '
                    f'<strong>{esc(v["name"])} {esc(v["installed_version"])}</strong> '
                    f'{esc(v["id"])} {esc(v["title"])}{fixed} {refs}</div>')
        elif r["is_wordpress"]:
            parts.append("<p class='ok'>No known vulnerabilities matched the local database.</p>")
        parts.append("</section>")
        rows.append("".join(parts))

    meta_note = ""
    if db_meta.get("updated"):
        meta_note = f"Vulnerability data: {esc(str(db_meta.get('updated')))}"

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WordPress audit report</title>
<style>
:root{{--bg:#0f1115;--card:#171a21;--line:#262b36;--txt:#e6e8ee;--mut:#9aa3b2;
--crit:#ff5370;--high:#ff8a5c;--med:#ffc14d;--low:#5cc6e0;--info:#8b93a4;--ok:#5cd38a;}}
*{{box-sizing:border-box}}
body{{margin:0;padding:24px;background:var(--bg);color:var(--txt);
font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}}
h1{{font-size:22px;margin:0 0 4px}} .sub{{color:var(--mut);margin:0 0 24px}}
.site{{background:var(--card);border:1px solid var(--line);border-radius:12px;
padding:20px;margin:0 auto 20px;max-width:900px}}
h2{{font-size:18px;margin:0 0 12px;word-break:break-all}}
h3{{font-size:14px;text-transform:uppercase;letter-spacing:.04em;color:var(--mut);
margin:20px 0 8px}} h3 small{{text-transform:none;letter-spacing:0}}
table.meta{{border-collapse:collapse;width:100%;max-width:360px}}
table.meta th{{text-align:left;color:var(--mut);font-weight:500;padding:2px 12px 2px 0}}
ul.comp{{list-style:none;padding:0;margin:0;display:grid;
grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:4px}}
ul.comp li{{background:#11141a;border:1px solid var(--line);border-radius:6px;padding:6px 10px}}
.ver{{color:var(--mut)}}
.finding{{border-left:3px solid var(--info);background:#11141a;border-radius:0 8px 8px 0;
padding:10px 14px;margin:6px 0}}
.finding p{{margin:4px 0 0;color:var(--mut);font-size:13px}}
.badge{{font-size:11px;font-weight:700;padding:1px 7px;border-radius:999px;
background:#000;margin-right:6px;vertical-align:1px}}
.sev-critical{{border-color:var(--crit)}} .sev-critical .badge{{background:var(--crit);color:#2a0008}}
.sev-high{{border-color:var(--high)}} .sev-high .badge{{background:var(--high);color:#2a1000}}
.sev-medium{{border-color:var(--med)}} .sev-medium .badge{{background:var(--med);color:#2a2000}}
.sev-low{{border-color:var(--low)}} .sev-low .badge{{background:var(--low);color:#002029}}
.sev-info{{border-color:var(--info)}} .sev-info .badge{{background:var(--info);color:#111}}
.finding a{{color:var(--low);margin-left:6px;font-size:12px}}
.ok{{color:var(--ok)}} .err{{color:var(--crit)}}
.disc{{max-width:900px;margin:24px auto 0;color:var(--mut);font-size:12px}}
</style></head><body>
<h1>WordPress security audit</h1>
<p class="sub">Read-only, version-based report. {meta_note}</p>
{''.join(rows)}
<p class="disc">This report is based on publicly readable information and a local
vulnerability database. Version matches are indicative, not proof of exploitability
&mdash; confirm each finding manually. Run only against systems you are authorized to test.</p>
</body></html>"""


# ---------------------------------------------------------------------------
# cli
# ---------------------------------------------------------------------------

def _load_wordlist(path):
    slugs = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                slugs.append(line.lower())
    return slugs


def highest_severity(reports):
    worst = -1
    for r in reports:
        for item in r.get("vulnerabilities", []) + r.get("misconfigurations", []):
            worst = max(worst, SEVERITY_ORDER.get(item.get("severity"), 0))
    return worst


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="wpaudit",
        description="Read-only WordPress security audit by URL. "
                    "Use only on sites you are authorized to test.")
    p.add_argument("urls", nargs="*", help="site URL(s) or domain(s)")
    p.add_argument("-f", "--file", help="file with one URL per line ('-' for stdin)")
    p.add_argument("-j", "--json", action="store_true", help="output JSON")
    p.add_argument("--html", metavar="FILE", help="write an HTML report to FILE")
    p.add_argument("--db", default=DATA_FILE, help="vulnerability database JSON (default: data/vulnerabilities.json)")
    p.add_argument("--no-config", action="store_true", help="skip misconfiguration checks")

    enum = p.add_argument_group("enumeration")
    enum.add_argument("-e", "--enumerate", action="store_true",
                      help="aggressively probe bundled lists of popular plugins/themes "
                           "(finds components not referenced in the page)")
    enum.add_argument("--plugin-wordlist", metavar="FILE",
                      help="custom plugin slug list (implies --enumerate for plugins)")
    enum.add_argument("--theme-wordlist", metavar="FILE",
                      help="custom theme slug list (implies --enumerate for themes)")

    online = p.add_argument_group("online vulnerability data")
    online.add_argument("--online", action="store_true",
                        help="look up detected versions against a live vulnerability source")
    online.add_argument("--source", choices=sorted(vulnfeed.SOURCES), default="wpscan",
                        help="online source (default: wpscan)")
    online.add_argument("--api-key", default=os.environ.get("WPSCAN_API_KEY"),
                        help="API key for the source (or WPSCAN_API_KEY env var)")
    online.add_argument("--update-db", action="store_true",
                        help="with --online, write fetched data back into the local --db file")

    p.add_argument("--fail-on", choices=sorted(SEVERITY_ORDER), metavar="SEVERITY",
                   help="exit 2 if any finding is at least this severe (for CI)")
    p.add_argument("-t", "--timeout", type=float, default=10, help="request timeout (default 10)")
    p.add_argument("-w", "--workers", type=int, default=5, help="sites in parallel (default 5)")
    p.add_argument("-k", "--insecure", action="store_true", help="don't verify TLS certificates")
    p.add_argument("--user-agent", default=wpcheck.DEFAULT_UA, help="custom User-Agent")
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

    data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
    plugin_wl = theme_wl = None
    if args.enumerate or args.plugin_wordlist:
        plugin_wl = _load_wordlist(args.plugin_wordlist or os.path.join(data_dir, "plugins_popular.txt"))
    if args.enumerate or args.theme_wordlist:
        theme_wl = _load_wordlist(args.theme_wordlist or os.path.join(data_dir, "themes_popular.txt"))

    db = load_vuln_db(args.db)
    fetcher = wpcheck.Fetcher(args.timeout, args.user_agent, args.insecure)

    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
        reports = list(ex.map(
            lambda u: audit_site(u, fetcher, db, do_config=not args.no_config,
                                 plugin_wordlist=plugin_wl, theme_wordlist=theme_wl), urls))

    if args.online:
        try:
            source = vulnfeed.make_source(args.source, fetcher, args.api_key)
            added = enrich_db_online(db, source, reports,
                                     cache_path=args.db if args.update_db else None)
            for r in reports:
                rematch(r, db)
            print(f"online source '{args.source}': merged {added} vulnerability entr"
                  f"{'y' if added == 1 else 'ies'}", file=sys.stderr)
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2

    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(render_html(reports, db.get("_meta", {})))
        print(f"HTML report written to {args.html}", file=sys.stderr)

    if args.json:
        print(json.dumps(reports if len(reports) > 1 else reports[0], indent=2))
    elif not args.html:
        on = sys.stdout.isatty() and not args.no_color
        for r in reports:
            print_text(r, on)

    if args.fail_on is not None and highest_severity(reports) >= SEVERITY_ORDER[args.fail_on]:
        return 2
    return 0 if all(r["reachable"] for r in reports) else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
