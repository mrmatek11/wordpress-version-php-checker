#!/usr/bin/env python3
"""
vulnfeed - pluggable online vulnerability data sources for wpaudit.

Fetching and parsing are kept separate so the parsers can be unit-tested
without network access. Each source returns entries in wpaudit's normalized
local-DB shape:

    {"id", "title", "severity", "fixed_in", "max_affected",
     "introduced", "references": [url, ...]}

Supported sources:
  * wpscan        - WPScan API v3 (needs a free API key; stable, documented)
  * wpvulnerability - wpvulnerability.net (keyless; best-effort parsing)
"""

import json
import urllib.error
import urllib.request

SEVERITIES = ("critical", "high", "medium", "low", "info")


def _severity_from_cvss(score):
    try:
        s = float(score)
    except (TypeError, ValueError):
        return None
    if s >= 9.0:
        return "critical"
    if s >= 7.0:
        return "high"
    if s >= 4.0:
        return "medium"
    if s > 0:
        return "low"
    return "info"


def _norm_severity(value, cvss=None):
    if isinstance(value, str) and value.lower() in SEVERITIES:
        return value.lower()
    s = _severity_from_cvss(cvss)
    return s or "medium"


# ---------------------------------------------------------------------------
# WPScan API v3  (https://wpscan.com/api)
# ---------------------------------------------------------------------------

def parse_wpscan_component(payload):
    """payload: the dict returned for one plugin/theme/core slug.

    WPScan wraps data under the slug/version key, e.g.
    {"contact-form-7": {"vulnerabilities": [ ... ]}}. Accepts either the
    wrapper dict or the inner object directly.
    """
    if not isinstance(payload, dict):
        return []
    # unwrap single-key wrapper
    if "vulnerabilities" not in payload and len(payload) == 1:
        payload = next(iter(payload.values()))
    if not isinstance(payload, dict):
        return []

    out = []
    for v in payload.get("vulnerabilities", []) or []:
        if not isinstance(v, dict):
            continue
        refs = []
        rdict = v.get("references") or {}
        if isinstance(rdict, dict):
            for u in rdict.get("url", []) or []:
                refs.append(u)
            for cve in rdict.get("cve", []) or []:
                refs.append(f"https://nvd.nist.gov/vuln/detail/CVE-{cve}")
        cvss = (v.get("cvss") or {})
        cvss_score = cvss.get("score") if isinstance(cvss, dict) else None
        cvss_sev = cvss.get("severity") if isinstance(cvss, dict) else None
        ident = ""
        if isinstance(rdict, dict) and rdict.get("cve"):
            ident = "CVE-" + str(rdict["cve"][0])
        out.append({
            "id": ident or str(v.get("id", "")),
            "title": v.get("title", ""),
            "severity": _norm_severity(cvss_sev, cvss_score),
            "fixed_in": v.get("fixed_in"),
            "max_affected": None,
            "introduced": None,
            "references": refs,
        })
    return out


class WPScanSource:
    name = "wpscan"
    BASE = "https://wpscan.com/api/v3"

    def __init__(self, fetcher, api_key):
        self.fetcher = fetcher
        self.api_key = api_key

    def _get_json(self, url):
        req = urllib.request.Request(
            url, headers={
                "Authorization": f"Token token={self.api_key}",
                "User-Agent": self.fetcher.user_agent,
            })
        try:
            resp = urllib.request.urlopen(req, timeout=self.fetcher.timeout, context=self.fetcher.ctx)
            return json.loads(resp.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {}            # unknown component = no vulns
            raise
        except (urllib.error.URLError, OSError, ValueError):
            return None              # network/parse failure

    def lookup_plugin(self, slug):
        return parse_wpscan_component(self._get_json(f"{self.BASE}/plugins/{slug}"))

    def lookup_theme(self, slug):
        return parse_wpscan_component(self._get_json(f"{self.BASE}/themes/{slug}"))

    def lookup_core(self, version):
        key = version.replace(".", "")
        return parse_wpscan_component(self._get_json(f"{self.BASE}/wordpresses/{key}"))


# ---------------------------------------------------------------------------
# wpvulnerability.net  (keyless, best-effort)
# ---------------------------------------------------------------------------

def parse_wpvulnerability(payload):
    """Best-effort parser for wpvulnerability.net responses.

    The schema varies; we probe for a list of vulnerability objects and pull
    the fields we recognize, tolerating anything missing.
    """
    if not isinstance(payload, dict):
        return []
    vulns = None
    data = payload.get("data", payload)
    if isinstance(data, dict):
        for key in ("vulnerability", "vulnerabilities"):
            if isinstance(data.get(key), list):
                vulns = data[key]
                break
    if vulns is None and isinstance(payload.get("vulnerability"), list):
        vulns = payload["vulnerability"]
    if not vulns:
        return []

    out = []
    for v in vulns:
        if not isinstance(v, dict):
            continue
        refs = []
        src = v.get("source") or []
        if isinstance(src, list):
            for s in src:
                if isinstance(s, dict) and s.get("link"):
                    refs.append(s["link"])
        ident = ""
        cve = None
        if isinstance(src, list):
            for s in src:
                if isinstance(s, dict) and str(s.get("id", "")).upper().startswith("CVE"):
                    cve = s["id"]
                    break
        if cve:
            ident = cve if str(cve).upper().startswith("CVE") else f"CVE-{cve}"

        impact = v.get("impact") or {}
        score = None
        sev = None
        if isinstance(impact, dict):
            cv = impact.get("cvss") or {}
            if isinstance(cv, dict):
                score = cv.get("score")
                sev = cv.get("severity")

        fixed_in = None
        max_aff = None
        op = v.get("operator") or {}
        if isinstance(op, dict):
            fixed_in = op.get("fixed") or op.get("min_fixed")
            max_aff = op.get("max_version") or op.get("max")

        out.append({
            "id": ident,
            "title": v.get("name") or v.get("title") or "",
            "severity": _norm_severity(sev, score),
            "fixed_in": fixed_in,
            "max_affected": max_aff,
            "introduced": None,
            "references": refs,
        })
    return out


class WPVulnerabilitySource:
    name = "wpvulnerability"
    BASE = "https://www.wpvulnerability.net"

    def __init__(self, fetcher, api_key=None):
        self.fetcher = fetcher

    def _get_json(self, url):
        req = urllib.request.Request(url, headers={"User-Agent": self.fetcher.user_agent})
        try:
            resp = urllib.request.urlopen(req, timeout=self.fetcher.timeout, context=self.fetcher.ctx)
            return json.loads(resp.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {}
            return None
        except (urllib.error.URLError, OSError, ValueError):
            return None

    def lookup_plugin(self, slug):
        return parse_wpvulnerability(self._get_json(f"{self.BASE}/plugin/{slug}/"))

    def lookup_theme(self, slug):
        return parse_wpvulnerability(self._get_json(f"{self.BASE}/theme/{slug}/"))

    def lookup_core(self, version):
        return parse_wpvulnerability(self._get_json(f"{self.BASE}/core/{version}/"))


SOURCES = {"wpscan": WPScanSource, "wpvulnerability": WPVulnerabilitySource}


def make_source(name, fetcher, api_key=None):
    cls = SOURCES.get(name)
    if cls is None:
        raise ValueError(f"unknown source: {name} (choose from {', '.join(SOURCES)})")
    if cls is WPScanSource and not api_key:
        raise ValueError("the 'wpscan' source needs an API key (--api-key or WPSCAN_API_KEY)")
    return cls(fetcher, api_key)
