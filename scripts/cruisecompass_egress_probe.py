#!/usr/bin/env python3
"""Read-only CruiseCompass reachability probe. Run on the candidate external host.

No customer data or credentials are used. Only fixed HTTPS paths on the fixed host
are requested; redirects and HTML-provided URLs are never followed.
"""

from __future__ import annotations

import argparse
import http.client
import json
import re
import socket
import ssl
import sys
import time
from urllib.parse import quote

HOST = "suche.corecruises.de"
PORT = 443
MAX_BODY = 3 * 1024 * 1024
TIMEOUT = 10
ID_RE = re.compile(r"\A[A-Za-z0-9._:-]{1,128}\Z")
TOKEN_RE = re.compile(rb'var\s+t\s*=\s*"([A-Za-z0-9._~-]{16,768})"')
GATE_RE = re.compile(rb'stored\s*\?\s*"([A-Za-z0-9._~-]{16,768})"\s*:\s*"([A-Za-z0-9._~-]{16,768})"')


def step(name, fn):
    start = time.monotonic()
    try:
        detail = fn()
        return {"step": name, "ok": True, "ms": round((time.monotonic() - start) * 1000), **detail}
    except Exception as exc:
        # Exception type only; never print bodies, request URLs or provider text.
        return {"step": name, "ok": False, "ms": round((time.monotonic() - start) * 1000), "errorType": type(exc).__name__}


def dns():
    addresses = {row[4][0] for row in socket.getaddrinfo(HOST, PORT, type=socket.SOCK_STREAM)}
    if not addresses:
        raise OSError("DNS returned no address")
    return {"addressCount": len(addresses)}


def tcp():
    with socket.create_connection((HOST, PORT), timeout=TIMEOUT):
        return {}


def tls():
    with socket.create_connection((HOST, PORT), timeout=TIMEOUT) as raw:
        with ssl.create_default_context().wrap_socket(raw, server_hostname=HOST) as secure:
            return {"tlsVersion": secure.version()}


def request(method, path, cookie=None, referer=None):
    if not path.startswith("/") or "//" in path or "#" in path or "\n" in path or "\r" in path:
        raise ValueError("Invalid fixed path")
    connection = http.client.HTTPSConnection(HOST, PORT, timeout=TIMEOUT, context=ssl.create_default_context())
    headers = {"Accept": "text/html,application/xhtml+xml;q=0.9", "Accept-Language": "de-DE,de;q=0.9", "User-Agent": "CoreCruises-EgressProbe/1.0"}
    if cookie:
        headers["Cookie"] = cookie
    if referer:
        headers["Referer"] = "https://" + HOST + referer
    try:
        connection.request(method, path, headers=headers)
        response = connection.getresponse()
        body = response.read(MAX_BODY + 1)
        if len(body) > MAX_BODY:
            raise ValueError("Response exceeded size limit")
        return response.status, response.getheader("Content-Type", ""), body
    finally:
        connection.close()


def is_gate(body):
    return b"xtgate" in body and b"location.replace(" in body and b"Angebote werden geladen" in body


def fetch_with_gate(path):
    status, content_type, body = request("GET", path)
    hops = 1
    if status == 200 and is_gate(body):
        token = TOKEN_RE.search(body)
        gate = GATE_RE.search(body)
        if token and gate:
            cookie = "xtgate=" + token.group(1).decode("ascii")
            gate_path = path + ("&" if "?" in path else "?") + "_g=" + quote(gate.group(1).decode("ascii"), safe="")
            status, content_type, body = request("GET", gate_path, cookie, path)
            hops = 2
            if 300 <= status < 400:
                status, content_type, body = request("GET", path, cookie, gate_path)
                hops = 3
    if status != 200 or not content_type.lower().startswith(("text/html", "application/xhtml+xml")) or is_gate(body) or not body:
        raise ValueError("Provider did not return usable HTML")
    return {"httpStatus": status, "bytes": len(body), "gateHops": hops}


def main():
    parser = argparse.ArgumentParser(description="Fixed-host read-only external egress probe")
    parser.add_argument("--s-id", default="5-270214-14", help="known future t=S cruise_id")
    parser.add_argument("--ns-id", default="242-271211-3", help="known future t=NS cruise_id")
    args = parser.parse_args()
    if not ID_RE.fullmatch(args.s_id) or not ID_RE.fullmatch(args.ns_id):
        parser.error("Cruise IDs must match the observed opaque ID format")
    offer_s = "/offer?t=S&cruise_id=" + quote(args.s_id, safe="")
    offer_ns = "/offer?t=NS&cruise_id=" + quote(args.ns_id, safe="")
    checks = [
        step("dns", dns),
        step("tcp_443", tcp),
        step("tls", tls),
        step("https_head", lambda: http_check("HEAD", "/")),
        step("https_get", lambda: http_check("GET", "/")),
        step("search", lambda: fetch_with_gate("/search?t=K&red=1&region=8&dur=7-14&sort=pauf&page=1")),
        step("offer_s", lambda: fetch_with_gate(offer_s)),
        step("offer_ns", lambda: fetch_with_gate(offer_ns)),
    ]
    print(json.dumps({"target": HOST, "checks": checks, "allPassed": all(check["ok"] for check in checks)}, ensure_ascii=False, separators=(",", ":")))
    return 0 if all(check["ok"] for check in checks) else 1


def http_check(method, path):
    status, content_type, body = request(method, path)
    if not 200 <= status < 400:
        raise ValueError("Unexpected HTTP status")
    return {"httpStatus": status, "contentType": content_type.split(";", 1)[0], "bytes": len(body)}


if __name__ == "__main__":
    sys.exit(main())
