# wordpress-version-php-checker

A small command-line tool that detects the **WordPress version** and the **PHP version** of a website from its URL.

It needs only Python 3.8+ and nothing else: one file, no `pip install`.

```
$ python3 wpcheck.py -v example-blog.com

https://example-blog.com/
  WordPress : yes
  WP version: 6.5.3
              via meta generator tag, RSS feed <generator>
  PHP       : 8.1.27
              via header X-Powered-By: PHP/8.1.27
```

## Installation

```bash
git clone https://github.com/mrmatek11/wordpress-version-php-checker.git
cd wordpress-version-php-checker
python3 wpcheck.py example.com
```

Or download just the script:

```bash
curl -O https://raw.githubusercontent.com/mrmatek11/wordpress-version-php-checker/main/wpcheck.py
python3 wpcheck.py example.com
```

## Usage

```bash
# one site (https:// is added if you leave it out)
python3 wpcheck.py example.com

# several sites at once
python3 wpcheck.py site1.com https://site2.pl http://site3.net

# list of sites from a file, one per line (lines starting with # are skipped)
python3 wpcheck.py -f sites.txt

# show where each version was found
python3 wpcheck.py -v example.com

# JSON output (for scripts and spreadsheets)
python3 wpcheck.py --json -f sites.txt > results.json
```

### Options

| Option | Description |
|---|---|
| `-f, --file FILE` | Read URLs from a file (`-` = stdin) |
| `-j, --json` | Print the results as JSON |
| `-v, --verbose` | Show the source of each detected version |
| `-t, --timeout SEC` | Timeout for each request (default 10) |
| `-w, --workers N` | Number of sites checked in parallel (default 5) |
| `-k, --insecure` | Skip TLS certificate checks |
| `--user-agent UA` | Use your own User-Agent |
| `--no-color` | Turn off colors |

Exit code: `0` when every site responded, `1` when at least one could not be reached.

## How it works

The tool sends a handful of ordinary GET requests, the same ones a browser would. It does not log in, brute-force anything or use any exploits.

**WordPress version** comes from these sources, each with a weight. The version with the most evidence wins.

| Source | Weight |
|---|---|
| `<meta name="generator" content="WordPress X.Y">` on the home page | high |
| `<generator>` in the RSS feed (`/feed/`) | high |
| `generator` in `/wp-links-opml.php` | high |
| `Version X.Y` in `/readme.html` (older installs) | medium |
| `?ver=X.Y` on core files in `/wp-includes/` and `/wp-admin/` (home page and `wp-login.php`) | low |

**PHP version** comes from HTTP headers such as `X-Powered-By: PHP/8.1.27`, `Server` and `X-PHP-Version`. The tool checks the home page, `wp-login.php`, `xmlrpc.php` and other endpoints. Those PHP endpoints usually skip the page cache, so they reveal the header more often than the home page does.

If the PHP version is hidden but the WordPress version is known, the tool shows the **minimum PHP version that WordPress release requires**. In JSON this is the `php_min_required_by_wp` field. It is a lower bound, not the actual version.

**Is it WordPress at all?** The tool looks for `wp-content` / `wp-includes` paths, the `api.w.org` header, the `wp/v2` REST API, the login form and the XML-RPC response.

## Limitations

- Many sites hide their versions on purpose, with security plugins, removed `generator` tags, `expose_php = Off` or a CDN/WAF such as Cloudflare. The tool then reports `unknown (hidden)`, which is expected and not a bug.
- `?ver=` values can be changed by optimization plugins, so they carry the lowest weight.
- PHP can only be detected when the server sends it in a header.

## Example JSON

```json
{
  "url": "https://example-blog.com/",
  "reachable": true,
  "is_wordpress": true,
  "wordpress_version": "6.7.1",
  "wordpress_sources": ["wp-includes asset ?ver=", "wp-admin asset ?ver="],
  "php_version": "7.4.33",
  "php_sources": ["header X-Powered-By: PHP/7.4.33"],
  "php_min_required_by_wp": "7.2.24",
  "error": null
}
```


## wpaudit — security audit (read-only)

`wpaudit.py` extends the version checker into a small, **read-only** WordPress security auditor, in the spirit of WPScan's detection side. It only sends ordinary GET requests (the same a browser makes). It does **not** log in, guess passwords, brute-force, exploit, or change anything — it reads publicly available information and reports it. Use it only on sites you own or are authorized to test.

```bash
# text report
python3 wpaudit.py example.com

# nice HTML report you can hand to a client
python3 wpaudit.py example.com --html report.html

# audit a whole list and save JSON
python3 wpaudit.py -f sites.txt --json > audit.json
```

What it does:

- **Version detection** — WordPress + PHP, reusing `wpcheck.py`.
- **Plugin & theme enumeration** — finds slugs referenced in the page, then reads each plugin's `readme.txt` (`Stable tag:`) and each theme's `style.css` (`Version:`) for the installed version. With `-e / --enumerate` it also probes bundled lists of popular plugins/themes, so it finds components that aren't referenced anywhere in the HTML (aggressive hits are marked `*`). Most real-world WordPress vulnerabilities live in plugins, so this is the big one.
- **Misconfiguration / exposure checks** — accessible `wp-config.php` backups, `.env`, exposed `.git`, `debug.log`, directory listing on `/wp-content/uploads/`, user enumeration via `/wp-json/wp/v2/users`, XML-RPC enabled, `readme.html`, and missing security headers (CSP, HSTS, X-Frame-Options, …).
- **Vulnerability matching** — compares each detected version against a database and lists matching CVEs with severity and the version they were fixed in. Works offline against `data/vulnerabilities.json`, or against a **live source** with `--online`.

### Aggressive enumeration

```bash
# probe ~140 popular plugins and ~45 popular themes, not just what's in the HTML
python3 wpaudit.py example.com -e

# use your own slug lists
python3 wpaudit.py example.com --plugin-wordlist my-plugins.txt --theme-wordlist my-themes.txt
```

A wordlist hit is only reported when its `readme.txt` / `style.css` actually confirms the component is installed, so you don't get false positives.

### Live vulnerability data (closing the gap to WPScan)

The detection logic here is comparable to WPScan's; WPScan's real edge is its continuously-updated vulnerability feed. `--online` lets wpaudit query a live source for exactly the components it found:

```bash
# WPScan API (free key, ~25 lookups/day): https://wpscan.com/api
export WPSCAN_API_KEY=xxxxxxxx
python3 wpaudit.py example.com -e --online

# keyless, best-effort source
python3 wpaudit.py example.com -e --online --source wpvulnerability

# cache the fetched data into the local DB for later offline runs
python3 wpaudit.py example.com -e --online --update-db
```

Only the detected components are looked up (one request each), so a free WPScan key goes a long way. Fetched entries are merged into the in-memory database (and written back with `--update-db`), then matched like any local entry.

### CI usage

```bash
# non-zero exit (2) if anything high or worse is found — fails the pipeline
python3 wpaudit.py example.com -e --online --fail-on high --json > audit.json
```

### The vulnerability database

Matching is only as good as the data behind it. `data/vulnerabilities.json` ships with a **small sample** (a few real historical issues) just to show the format — it is **not** a complete or current feed. Keep it up to date yourself, or regenerate it from a public source such as the WPScan API or wpvulnerability.net.

Format:

```json
{
  "core": [
    { "id": "CVE-2023-2745", "title": "…", "severity": "medium", "fixed_in": "6.2.1" }
  ],
  "plugins": {
    "contact-form-7": [
      { "id": "CVE-2020-35489", "title": "…", "severity": "critical", "fixed_in": "5.3.2" }
    ]
  },
  "themes": {}
}
```

A component at version `V` is reported when `introduced <= V < fixed_in`. You can use `max_affected` (inclusive) instead of `fixed_in`. Severity is one of `critical`, `high`, `medium`, `low`, `info`.

> **Note on results:** a version match is *indicative*, not proof. A plugin may be patched by a backport, protected by a WAF, or not actually running the vulnerable code path. Always confirm findings manually.

### Scope and ethics

This tool is for defensive auditing of your own or authorized sites. It intentionally does **not** include exploitation, password attacks, WAF evasion, or mass-scanning of arbitrary targets — it detects and reports, it does not break in.

## Legal

Use the tool only on your own sites, client sites, or sites you are allowed to check. It reads only publicly available information, but you are responsible for how you use it.

## License

MIT, see [LICENSE](LICENSE).
