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

## Legal

Use the tool only on your own sites, client sites, or sites you are allowed to check. It reads only publicly available information, but you are responsible for how you use it.

## License

MIT, see [LICENSE](LICENSE).
