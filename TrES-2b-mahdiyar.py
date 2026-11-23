#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# tres2b — poc runner for cors / idor / race / jwt
# authorized bounty work only. no warranty, no mercy.
#
# usage:
#   ./tres2b.py                              # interactive
#   ./tres2b.py --cors https://x/y           # cli
#   ./tres2b.py --cors a b --insecure --yes  # batch, skip tls check
#
# env:
#   TRES2B_TOKEN   fallback for --token-a / race token (keeps it out of ps)
#
# notes:
#   - py3.11+ for asyncio.Barrier. older versions fall back to gather+stagger
#   - ssl verify is ON by default. flip with --insecure if you really must
#   - keep --race-count sane (~10-30). no backoff, you'll eat 429s
# -----------------------------------------------------------------------------

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import random
import re
import sys
from datetime import datetime, timezone
from functools import partial
from typing import Any, Awaitable, Callable, Iterable

try:
    import aiohttp
except ImportError:
    sys.exit("aiohttp missing: pip install aiohttp")

try:
    from colorama import Fore, Style, init as _cinit
    _cinit(autoreset=True)
except ImportError:
    class _F:
        RED = GREEN = YELLOW = CYAN = MAGENTA = BLUE = RESET = ""
    class _S:
        BRIGHT = RESET_ALL = ""
    Fore, Style = _F, _S


# --- plumbing ---------------------------------------------------------------

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

MAX_RACE_COUNT = 100  # hard cap so nobody torches a prod box by accident


def say(tag: str, msg: str) -> None:
    print(f"{_TAG_COLOR.get(tag, '')}[{tag}]{Style.RESET_ALL} {msg}")


def ua() -> str:
    return random.choice(_UA_POOL)


def prompt(label: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    try:
        v = input(f"{Fore.CYAN}?{Style.RESET_ALL} {label}{suffix}: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(130)
    return v or default


def _b64pad(s: str) -> str:
    return s + "=" * (-len(s) % 4)


def _jwt_parts(tok: str) -> tuple[dict, dict] | None:
    bits = tok.split(".")
    if len(bits) != 3:
        return None
    try:
        hdr = json.loads(base64.urlsafe_b64decode(_b64pad(bits[0])))
        pay = json.loads(base64.urlsafe_b64decode(_b64pad(bits[1])))
    except Exception:
        return None
    if not isinstance(hdr, dict) or not isinstance(pay, dict):
        return None
    return hdr, pay


def finding(kind: str, sev: str, **kw: Any) -> dict:
    d = {"type": kind, "severity": sev}
    d.update(kw)
    return d


def _norm_body(s: str) -> str:
    # strip volatile bits so identical responses don't look different
    s = re.sub(r'"(?:ts|timestamp|time|nonce|request_?id|trace_?id)"\s*:\s*[^,}]+',
               '"__v":0', s)
    s = re.sub(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
               "__uuid__", s)
    return s


# --- cors -------------------------------------------------------------------

# evil + null + subdomain-shaped origin covers the usual bypasses
_CORS_PROBES = (
    "https://evil.example",
    "null",
    "https://evil.example.com",
)


async def test_cors(session: aiohttp.ClientSession, url: str) -> list[dict]:
    say("INFO", f"cors {url}")
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()

    for origin in _CORS_PROBES:
        try:
            async with session.get(
                url,
                headers={"Origin": origin, "User-Agent": ua()},
                allow_redirects=False,
            ) as r:
                acao = (r.headers.get("Access-Control-Allow-Origin") or "").strip()
                acac = (r.headers.get("Access-Control-Allow-Credentials") or "").lower()
                vary = (r.headers.get("Vary") or "").lower()
        except Exception as e:
            say("DBG", f"cors fail {origin} {url}: {e!r}")
            continue

        key = (acao, acac)
        if key in seen:
            continue
        seen.add(key)

        # null has its own path — must come before generic reflection check,
        # otherwise "null" origin reflects as a plain CORS_REFLECT and we lose
        # the sandbox/file:// angle.
        if origin == "null" and acao == "null":
            out.append(finding(
                "CORS_NULL_ORIGIN", "HIGH", url=url,
                detail="ACAO=null (sandbox iframe / file:// vector)",
            ))
        elif acao == origin and acac == "true":
            out.append(finding(
                "CORS_REFLECT_CREDS", "HIGH", url=url,
                detail=f"Origin={origin} ACAO={acao} ACAC={acac}",
            ))
        elif acao == origin:
            out.append(finding(
                "CORS_REFLECT", "MEDIUM", url=url,
                detail=f"Origin={origin} ACAO={acao}",
            ))

        # caching bug: reflected origin without Vary: Origin
        if acao == origin and origin != "null" and "origin" not in vary:
            out.append(finding(
                "CORS_NO_VARY", "LOW", url=url,
                detail=f"Origin={origin} reflected but no Vary: Origin",
            ))

    return out


# --- idor -------------------------------------------------------------------

async def _fetch(session: aiohttp.ClientSession, method: str, url: str,
                 hdr: dict, body: Any = None) -> tuple[int, str] | None:
    try:
        kwargs: dict[str, Any] = {"headers": hdr, "allow_redirects": False}
        if body is not None:
            kwargs["json"] = body
        async with session.request(method, url, **kwargs) as r:
            return r.status, await r.text()
    except Exception as e:
        say("DBG", f"{method} {url} fail: {e!r}")
        return None


async def test_idor(session: aiohttp.ClientSession, endpoint: str,
                    token_a: str, token_b: str, resource_b: str) -> list[dict]:
    if "{id}" not in endpoint:
        say("WARN", "idor endpoint needs {id} placeholder, skipping")
        return []

    rid = str(resource_b)
    url = endpoint.replace("{id}", rid)
    hdr_a = {"Authorization": f"Bearer {token_a}", "User-Agent": ua()}
    hdr_b = {"Authorization": f"Bearer {token_b}", "User-Agent": ua()}

    say("INFO", f"idor {url}")
    out: list[dict] = []

    # baseline: B reading its own resource. if this 404s, the id is bogus.
    base = await _fetch(session, "GET", url, hdr_b)
    if base is None:
        return []
    if base[0] not in (200, 201):
        say("DBG", f"idor baseline {base[0]}, id likely invalid")
        return []

    # A reading B's resource = the actual signal
    got = await _fetch(session, "GET", url, hdr_a)
    if got is None:
        return []
    status, body = got

    # a real hit means A gets the *same shape* B got, and the body actually
    # references B's id (not a generic 200-error page)
    same_shape = (
        status == 200
        and len(body) > 50
        and body.strip() != ""
        and _norm_body(body) == _norm_body(base[1])
    )
    refs_rid = rid in body

    if status == 200 and (same_shape or refs_rid):
        out.append(finding(
            "IDOR_READ", "CRITICAL", url=url, method="GET",
            detail=f"A got 200 ({len(body)}b) on B's resource",
            sample=body[:160],
        ))

    # write-side: try PUT / PATCH with a harmless marker
    for method in ("PUT", "PATCH"):
        w = await _fetch(session, method, url, hdr_a, {"idor": "marker"})
        if w and w[0] in (200, 204):
            out.append(finding(
                "IDOR_WRITE", "CRITICAL", url=url, method=method,
                detail=f"A {method} on B's resource -> {w[0]}",
            ))
            break

    return out


# --- race -------------------------------------------------------------------

async def _race_worker(session, url, method, body, hdr, barrier, i):
    if barrier is not None:
        try:
            await asyncio.wait_for(barrier.wait(), timeout=5)
        except asyncio.TimeoutError:
            return i, -1, "barrier timeout"
    try:
        async with session.request(method, url, json=body, headers=hdr,
                                   allow_redirects=False) as r:
            return i, r.status, await r.text()
    except Exception as e:
        return i, -1, repr(e)


async def test_race(session: aiohttp.ClientSession, url: str, method: str,
                    body: Any, token: str, count: int) -> list[dict]:
    if count < 2:
        say("WARN", "race needs count>=2")
        return []
    if count > MAX_RACE_COUNT:
        say("WARN", f"count capped at {MAX_RACE_COUNT}")
        count = MAX_RACE_COUNT

    say("INFO", f"race {url} x{count}")
    hdr = {"Authorization": f"Bearer {token}", "User-Agent": ua(),
           "Content-Type": "application/json"}

    barrier = asyncio.Barrier(count) if hasattr(asyncio, "Barrier") else None
    if barrier is None:
        say("DBG", "no asyncio.Barrier, staggering instead")

    results = await asyncio.gather(*(
        _race_worker(session, url, method, body, hdr, barrier, i)
        for i in range(count)
    ))

    ok = [(i, s, t) for i, s, t in results if s in (200, 201, 202, 204)]
    say("DBG", f"race {len(ok)}/{count} accepted")

    if len(ok) <= 1:
        return []

    statuses = {s for _, s, _ in ok}
    norm_bodies = {_norm_body(t) for _, _, t in ok}

    # differences after normalisation = server state actually diverged between
    # concurrent hits. that's a real signal, not just "endpoint is idempotent".
    if len(statuses) > 1 or len(norm_bodies) > 1:
        return [finding(
            "RACE_INCONSISTENT", "HIGH", url=url, method=method,
            detail=f"{len(ok)}/{count} accepted with inconsistent responses",
            sample=[{"i": i, "status": s, "body": t[:120]} for i, s, t in ok[:3]],
        )]

    return [finding(
        "RACE_MULTI_ACCEPT", "INFO", url=url, method=method,
        detail=(f"{len(ok)}/{count} accepted identically — confirm state "
                f"impact manually (idempotent endpoint?)"),
    )]


# --- jwt --------------------------------------------------------------------

def analyze_jwt(tok: str) -> list[dict]:
    say("INFO", "jwt analyzing")
    parsed = _jwt_parts(tok)
    if parsed is None:
        say("WARN", "not a decodable jwt")
        return []
    hdr, pay = parsed

    out: list[dict] = []
    alg = (hdr.get("alg") or "").lower()

    if alg == "none":
        out.append(finding("JWT_ALG_NONE", "CRITICAL",
                           detail="alg=none; verify server actually accepts unsigned"))
    elif alg.startswith("hs"):
        out.append(finding("JWT_HMAC", "INFO",
                           detail=f"alg={alg}; test weak key / kid injection"))
    elif alg.startswith(("rs", "es", "ps")):
        out.append(finding("JWT_ASYM", "INFO",
                           detail=f"alg={alg}; test alg-confusion (rs->hs)"))

    now = datetime.now(timezone.utc).timestamp()
    if "exp" not in pay:
        out.append(finding("JWT_NO_EXP", "MEDIUM", detail="no exp claim"))
    elif isinstance(pay["exp"], (int, float)) and pay["exp"] < now:
        out.append(finding("JWT_EXPIRED", "INFO", detail="token already expired"))

    if "nbf" in pay and isinstance(pay["nbf"], (int, float)) and pay["nbf"] > now:
        out.append(finding("JWT_NBF_FUTURE", "LOW", detail="nbf in future"))
    if not pay.get("aud"):
        out.append(finding("JWT_NO_AUD", "LOW", detail="no aud claim"))
    if not pay.get("iss"):
        out.append(finding("JWT_NO_ISS", "LOW", detail="no iss claim"))

    return out


# --- runner -----------------------------------------------------------------

Job = Callable[[aiohttp.ClientSession], Awaitable[list[dict] | dict | None]]


class Runner:
    def __init__(self, verify: bool = True, concurrency: int = 30,
                 timeout: int = 25):
        self.verify = verify
        self._limit = concurrency
        self._timeout = timeout
        self._session: aiohttp.ClientSession | None = None

    async def __aenter__(self) -> "Runner":
        conn = aiohttp.TCPConnector(ssl=self.verify, limit=self._limit)
        tmo = aiohttp.ClientTimeout(total=self._timeout)
        self._session = aiohttp.ClientSession(connector=conn, timeout=tmo)
        return self

    async def __aexit__(self, *exc: Any) -> None:
        if self._session:
            await self._session.close()
            self._session = None

    @property
    def session(self) -> aiohttp.ClientSession:
        if self._session is None:
            raise RuntimeError("Runner used outside 'async with'")
        return self._session

    def cors(self, url: str) -> Job:
        return partial(test_cors, self.session, url)

    def idor(self, ep: str, ta: str, tb: str, rb: str) -> Job:
        return partial(test_idor, self.session, ep, ta, tb, rb)

    def race(self, url: str, method: str, body: Any, token: str,
             count: int) -> Job:
        return partial(test_race, self.session, url, method, body, token, count)


async def run_jobs(jobs: Iterable[Job]) -> list[dict]:
    jobs = list(jobs)
    if not jobs:
        return []
    raw = await asyncio.gather(*jobs, return_exceptions=True)
    flat: list[dict] = []
    for r in raw:
        if isinstance(r, Exception):
            say("DBG", f"job raised: {r!r}")
            continue
        if not r:
            continue
        if isinstance(r, list):
            flat.extend(r)
        else:
            flat.append(r)
    return flat


def write_report(vulns: list[dict], path: str) -> None:
    payload = {
        "tool": "tres2b",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "count": len(vulns),
        "findings": vulns,
    }
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
    except OSError as e:
        say("WARN", f"could not write report: {e}")
        return
    say("INFO", f"report written -> {path}")


def show(vulns: list[dict]) -> None:
    print()
    if not vulns:
        say("OK", "clean. try harder next time.")
        return
    say("VULN", f"{len(vulns)} finding(s):")
    for v in vulns:
        sev = v.get("severity", "INFO")
        c = Fore.RED if sev in ("CRITICAL", "HIGH") else Fore.YELLOW
        where = v.get("url") or v.get("method") or "token"
        print(f"  {c}[{sev}]{Style.RESET_ALL} {v['type']} -> {where}")


def confirm_scope(skip: bool) -> None:
    if skip:
        return
    print(f"{Fore.YELLOW}{'=' * 64}")
    print(" authorized use only. written permission required.")
    print(" unauthorized testing is illegal. you own the consequences.")
    print(f"{'=' * 64}{Style.RESET_ALL}")
    if prompt("continue? (yes/no)", "no").lower() != "yes":
        say("WARN", "aborted")
        sys.exit(0)


# --- interactive ------------------------------------------------------------

def interactive() -> None:
    confirm_scope(False)
    print()
    print(f"{Fore.CYAN}tests:{Style.RESET_ALL}")
    print("  1) cors")
    print("  2) idor")
    print("  3) race")
    print("  4) jwt")
    print("  5) all")
    choice = prompt("pick", "1")

    cors_urls: list[str] = []
    idor_args: tuple | None = None
    race_args: tuple | None = None
    jwt_tok = ""

    if choice in ("1", "5"):
        raw = prompt("cors urls (comma-separated)", "")
        cors_urls = [u.strip() for u in raw.split(",") if u.strip()]

    if choice in ("2", "5"):
        ep = prompt("idor endpoint ({id} placeholder)", "")
        ta = prompt("token A", "")
        tb = prompt("token B", "")
        rb = prompt("account B resource id", "")
        if ep and ta and tb and rb:
            idor_args = (ep, ta, tb, rb)

    if choice in ("3", "5"):
        ru = prompt("race url", "")
        rm = prompt("method", "POST").upper()
        rbody_raw = prompt("json body", "{}")
        rt = prompt("token (blank = $TRES2B_TOKEN)",
                    os.environ.get("TRES2B_TOKEN", ""))
        rc_raw = prompt("count", "10")
        try:
            rc = int(rc_raw)
            rbody = json.loads(rbody_raw) if rbody_raw else {}
        except ValueError:
            say("WARN", "bad count or body, skipping race")
        else:
            if ru and rt:
                race_args = (ru, rm, rbody, rt, rc)

    if choice in ("4", "5"):
        jwt_tok = prompt("jwt token", "")

    verify = prompt("verify tls? (y/n)", "y").lower() != "n"

    async def _go() -> list[dict]:
        vulns: list[dict] = []
        async with Runner(verify=verify) as r:
            jobs: list[Job] = [r.cors(u) for u in cors_urls]
            if idor_args:
                jobs.append(r.idor(*idor_args))
            if race_args:
                jobs.append(r.race(*race_args))
            vulns.extend(await run_jobs(jobs))
        if jwt_tok:
            vulns.extend(analyze_jwt(jwt_tok))
        return vulns

    vulns = asyncio.run(_go())
    show(vulns)
    write_report(vulns, prompt("report path", "report.json"))


# --- cli --------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="tres2b poc runner")
    p.add_argument("--cors", nargs="*", metavar="URL")
    p.add_argument("--idor-endpoint")
    p.add_argument("--token-a")
    p.add_argument("--token-b")
    p.add_argument("--resource-b")
    p.add_argument("--race-url")
    p.add_argument("--race-method", default="POST")
    p.add_argument("--race-body", default="{}")
    p.add_argument("--race-count", type=int, default=10)
    p.add_argument("--jwt")
    p.add_argument("--output", default="report.json")
    p.add_argument("--insecure", action="store_true",
                   help="disable TLS verification (default: verify)")
    p.add_argument("--yes", action="store_true", help="skip scope warning")
    return p


def cli(argv: list[str]) -> None:
    args = build_parser().parse_args(argv)
    confirm_scope(args.yes)

    token_a = args.token_a or os.environ.get("TRES2B_TOKEN", "")

    async def _go() -> list[dict]:
        vulns: list[dict] = []
        async with Runner(verify=not args.insecure) as r:
            jobs: list[Job] = [r.cors(u) for u in (args.cors or [])]
            if args.idor_endpoint and token_a and args.token_b and args.resource_b:
                jobs.append(r.idor(args.idor_endpoint, token_a,
                                   args.token_b, args.resource_b))
            if args.race_url and token_a:
                try:
                    body = json.loads(args.race_body) if args.race_body else {}
                except json.JSONDecodeError as e:
                    sys.exit(f"bad --race-body json: {e}")
                jobs.append(r.race(args.race_url, args.race_method, body,
                                   token_a, args.race_count))
            vulns.extend(await run_jobs(jobs))
        if args.jwt:
            vulns.extend(analyze_jwt(args.jwt))
        return vulns

    vulns = asyncio.run(_go())
    show(vulns)
    write_report(vulns, args.output)


def main(argv: list[str] | None = None) -> None:
    argv = sys.argv[1:] if argv is None else argv
    if argv:
        cli(argv)
    else:
        interactive()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        say("WARN", "interrupted")
        sys.exit(130)
