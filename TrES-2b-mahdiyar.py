#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# tres2b - quick poc runner for cors / idor / race / jwt
# written for authorized bounty work. no warranty.
#
# usage:
#   ./tres2b.py                      # interactive
#   ./tres2b.py --cors https://x/y   # cli
#
# notes to self:
#  - python 3.11+ needed for asyncio.Barrier
#  - don't crank --race-count above ~30 without a proxy, you'll get 429'd
#  - ssl verify is off by default, turn it on with --verify if you care
# -----------------------------------------------------------------------------

import argparse
import asyncio
import base64
import json
import random
import sys
from datetime import datetime, timezone

try:
    import aiohttp
except ImportError:
    sys.exit("aiohttp missing: pip install aiohttp")

try:
    from colorama import Fore, Style, init as _cinit
    _cinit(autoreset=True)
except ImportError:
    # minimal shim, we don't need much
    class _F:
        RED = GREEN = YELLOW = CYAN = MAGENTA = BLUE = RESET = ""
    class _S:
        BRIGHT = RESET_ALL = ""
    Fore, Style = _F, _S


# --- misc helpers -----------------------------------------------------------

_UA_POOL = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
)

_TAG_COLOR = {
    "INFO": Fore.CYAN,
    "OK": Fore.GREEN,
    "WARN": Fore.YELLOW,
    "VULN": Fore.RED,
    "DBG": Fore.MAGENTA,
}


def say(tag, msg):
    print(f"{_TAG_COLOR.get(tag, '')}[{tag}]{Style.RESET_ALL} {msg}")


def ua():
    return random.choice(_UA_POOL)


def prompt(label, default=""):
    suffix = f" [{default}]" if default else ""
    try:
        v = input(f"{Fore.CYAN}?{Style.RESET_ALL} {label}{suffix}: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(130)
    return v or default


def _b64pad(s):
    return s + "=" * (-len(s) % 4)


# --- findings ---------------------------------------------------------------

def finding(kind, sev, **kw):
    d = {"type": kind, "severity": sev}
    d.update(kw)
    return d


# --- tests ------------------------------------------------------------------

async def test_cors(session, url, origin="https://evil.example"):
    say("INFO", f"cors {url}")
    try:
        async with session.get(
            url, headers={"Origin": origin, "User-Agent": ua()},
            ssl=session._ssl_ctx is not False,
        ) as r:
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()
    except Exception as e:
        say("DBG", f"cors fail {url}: {e!r}")
        return None

    # reflected origin + creds = the money shot
    if acao == origin and acac == "true":
        return finding("CORS_REFLECT_CREDS", "HIGH", url=url,
                       detail=f"ACAO={acao} ACAC={acac}")
    if acao == "*" and acac == "true":
        return finding("CORS_WILDCARD_CREDS", "HIGH", url=url,
                       detail="ACAO=* ACAC=true")
    if acao == origin:
        return finding("CORS_REFLECT", "MEDIUM", url=url,
                       detail=f"ACAO={acao}")
    return None


async def test_idor(session, endpoint, token_a, resource_b):
    if "{id}" not in endpoint:
        say("WARN", "idor endpoint needs {id} placeholder, skipping")
        return None
    url = endpoint.replace("{id}", str(resource_b))
    say("INFO", f"idor {url}")
    hdr = {"Authorization": f"Bearer {token_a}", "User-Agent": ua()}
    try:
        async with session.get(url, headers=hdr,
                               ssl=session._ssl_ctx is not False) as r:
            body = await r.text()
    except Exception as e:
        say("DBG", f"idor fail {url}: {e!r}")
        return None

    # 200 + non-trivial body from *another* account's id is the signal.
    # small bodies are usually error pages that return 200, so ignore them.
    if r.status == 200 and len(body) > 50:
        return finding("IDOR", "CRITICAL", url=url,
                       detail=f"200, {len(body)}b from acct-B id")
    return None


async def _race_worker(session, url, method, body, hdr, barrier, i, verify):
    await barrier.wait()
    try:
        async with session.request(method, url, json=body, headers=hdr,
                                   ssl=verify) as r:
            txt = await r.text()
            return i, r.status, txt
    except Exception as e:
        return i, -1, repr(e)


async def test_race(session, url, method, body, token, count, verify):
    if count < 2:
        say("WARN", "race needs count>=2")
        return None
    say("INFO", f"race {url} x{count}")
    hdr = {"Authorization": f"Bearer {token}",
           "User-Agent": ua(),
           "Content-Type": "application/json"}
    barrier = asyncio.Barrier(count)
    results = await asyncio.gather(*(
        _race_worker(session, url, method, body, hdr, barrier, i, verify)
        for i in range(count)
    ))
    ok = [(i, s, t) for i, s, t in results if s in (200, 201, 202)]
    say("DBG", f"race {len(ok)}/{count} ok")
    if len(ok) > 1:
        return finding(
            "RACE", "CRITICAL", url=url,
            detail=f"{len(ok)}/{count} succeeded (expected <=1)",
            sample=[{"i": i, "status": s, "body": t[:120]} for i, s, t in ok[:3]],
        )
    return None


def analyze_jwt(tok):
    say("INFO", "jwt analyzing")
    parts = tok.split(".")
    if len(parts) != 3:
        return None
    try:
        hdr = json.loads(base64.urlsafe_b64decode(_b64pad(parts[0])))
        payload = json.loads(base64.urlsafe_b64decode(_b64pad(parts[1])))
    except Exception as e:
        say("DBG", f"jwt decode fail: {e!r}")
        return None

    out = []
    alg = (hdr.get("alg") or "").lower()
    if alg == "none":
        out.append(finding("JWT_ALG_NONE", "CRITICAL",
                           detail="alg=none; server may accept unsigned tokens"))
    if alg.startswith("hs"):
        out.append(finding("JWT_HMAC", "INFO",
                           detail=f"alg={alg}; try weak-key or kid-injection"))
    if alg.startswith("rs") or alg.startswith("es"):
        out.append(finding("JWT_ASYM", "INFO",
                           detail=f"alg={alg}; try alg-confusion (rs->hs)"))
    if "exp" not in payload:
        out.append(finding("JWT_NO_EXP", "MEDIUM",
                           detail="no exp claim"))
    else:
        exp = payload.get("exp")
        if isinstance(exp, (int, float)) and exp < datetime.now(timezone.utc).timestamp():
            out.append(finding("JWT_EXPIRED", "INFO",
                               detail="token already expired"))
    return out or None


# --- orchestration ----------------------------------------------------------

class Runner:
    """Owns one aiohttp session for the whole run. Avoids the session-holder
    hack that plagued the earlier draft."""

    def __init__(self, verify=True, concurrency=30, timeout=25):
        self.verify = verify
        self._limit = concurrency
        self._timeout = timeout
        self._session = None

    async def __aenter__(self):
        conn = aiohttp.TCPConnector(ssl=self.verify, limit=self._limit)
        tmo = aiohttp.ClientTimeout(total=self._timeout)
        self._session = aiohttp.ClientSession(connector=conn, timeout=tmo)
        return self

    async def __aexit__(self, *exc):
        if self._session:
            await self._session.close()

    async def cors(self, url):
        return await test_cors(self._session, url)

    async def idor(self, endpoint, token_a, resource_b):
        return await test_idor(self._session, endpoint, token_a, resource_b)

    async def race(self, url, method, body, token, count):
        return await test_race(self._session, url, method, body, token,
                               count, self.verify)


async def run_jobs(runner, jobs):
    raw = await asyncio.gather(*(j(runner) for j in jobs))
    flat = []
    for r in raw:
        if not r:
            continue
        flat.extend(r) if isinstance(r, list) else flat.append(r)
    return flat


def write_report(vulns, path):
    payload = {
        "tool": "tres2b",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "count": len(vulns),
        "findings": vulns,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    say("INFO", f"report written -> {path}")


def show(vulns):
    print()
    if not vulns:
        say("OK", "clean. try harder next time.")
        return
    say("VULN", f"{len(vulns)} finding(s):")
    for v in vulns:
        c = Fore.RED if v.get("severity") == "CRITICAL" else Fore.YELLOW
        print(f"  {c}[{v['severity']}]{Style.RESET_ALL} "
              f"{v['type']} -> {v.get('url', 'token')}")


def confirm_scope(skip):
    if skip:
        return
    print(f"{Fore.YELLOW}{'=' * 64}")
    print(" authorized use only. you must have written permission.")
    print(" unauthorized testing is illegal. you own the consequences.")
    print(f"{'=' * 64}{Style.RESET_ALL}")
    if prompt("continue? (yes/no)", "no").lower() != "yes":
        say("WARN", "aborted")
        sys.exit(0)


# --- interactive ------------------------------------------------------------

def interactive():
    confirm_scope(False)
    print()
    print(f"{Fore.CYAN}tests:{Style.RESET_ALL}")
    print("  1) cors")
    print("  2) idor")
    print("  3) race")
    print("  4) jwt")
    print("  5) all")
    choice = prompt("pick", "1")

    cors_urls, idor_args, race_args, jwt_tok = [], None, None, None

    if choice in ("1", "5"):
        raw = prompt("cors urls (comma-separated)", "")
        cors_urls = [u.strip() for u in raw.split(",") if u.strip()]

    if choice in ("2", "5"):
        ep = prompt("idor endpoint ({id} placeholder)", "")
        ta = prompt("token A", "")
        rb = prompt("account B resource id", "")
        if ep and ta and rb:
            idor_args = (ep, ta, rb)

    if choice in ("3", "5"):
        ru = prompt("race url", "")
        rm = prompt("method", "POST").upper()
        rbody = prompt("json body", "{}")
        rt = prompt("token", "")
        rc = prompt("count", "10")
        try:
            rc = int(rc)
            rbody = json.loads(rbody) if rbody else {}
        except ValueError:
            say("WARN", "bad count or body, skipping race")
        else:
            if ru and rt:
                race_args = (ru, rm, rbody, rt, rc)

    if choice in ("4", "5"):
        jwt_tok = prompt("jwt token", "")

    verify = prompt("verify tls? (y/n)", "n").lower() == "y"

    async def _go():
        vulns = []
        async with Runner(verify=verify) as r:
            jobs = []
            for u in cors_urls:
                jobs.append(lambda r=r, u=u: r.cors(u))
            if idor_args:
                jobs.append(lambda r=r, a=idor_args: r.idor(*a))
            if race_args:
                jobs.append(lambda r=r, a=race_args: r.race(*a))
            if jobs:
                vulns.extend(await run_jobs(r, jobs))
        if jwt_tok:
            found = analyze_jwt(jwt_tok)
            if found:
                vulns.extend(found)
        return vulns

    vulns = asyncio.run(_go())
    show(vulns)
    write_report(vulns, prompt("report path", "report.json"))


# --- cli --------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(description="tres2b poc runner")
    p.add_argument("--cors", nargs="*", metavar="URL")
    p.add_argument("--idor-endpoint")
    p.add_argument("--token-a")
    p.add_argument("--resource-b")
    p.add_argument("--race-url")
    p.add_argument("--race-method", default="POST")
    p.add_argument("--race-body", default="{}")
    p.add_argument("--race-count", type=int, default=10)
    p.add_argument("--jwt")
    p.add_argument("--output", default="report.json")
    p.add_argument("--verify", action="store_true",
                   help="verify TLS (default: off)")
    p.add_argument("--yes", action="store_true", help="skip scope warning")
    return p


def cli(argv):
    args = build_parser().parse_args(argv)
    confirm_scope(args.yes)

    async def _go():
        vulns = []
        async with Runner(verify=args.verify) as r:
            jobs = [lambda r=r, u=u: r.cors(u) for u in (args.cors or [])]
            if args.idor_endpoint and args.token_a and args.resource_b:
                jobs.append(lambda r=r: r.idor(
                    args.idor_endpoint, args.token_a, args.resource_b))
            if args.race_url and args.token_a:
                try:
                    body = json.loads(args.race_body) if args.race_body else {}
                except json.JSONDecodeError as e:
                    sys.exit(f"bad --race-body json: {e}")
                jobs.append(lambda r=r: r.race(
                    args.race_url, args.race_method, body,
                    args.token_a, args.race_count))
            if jobs:
                vulns.extend(await run_jobs(r, jobs))
        if args.jwt:
            found = analyze_jwt(args.jwt)
            if found:
                vulns.extend(found)
        return vulns

    vulns = asyncio.run(_go())
    show(vulns)
    write_report(vulns, args.output)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        interactive()
    else:
        cli(argv)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        say("WARN", "interrupted")
        sys.exit(130)
