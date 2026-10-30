#!/usr/bin/env python3
"""Fetch public offer pages for IONOS. Never receives customer/account data."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import quote

from cruisecompass_egress_probe import GATE_RE, TOKEN_RE, is_gate, request

API = "https://api.corecruises.info"
ID_RE = re.compile(r"\A[A-Za-z0-9._:-]{1,128}\Z")
JOB_RE = re.compile(r"\A[a-f0-9]{64}\Z")
MAX_API_RESPONSE = 250_000


def api_post(path: str, data: dict, key: bytes) -> dict:
    body = json.dumps(data, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    timestamp = str(int(time.time()))
    nonce = secrets.token_hex(16)
    message = "\n".join(("v1", timestamp, nonce, "POST", path, hashlib.sha256(body).hexdigest())).encode()
    signature = hmac.new(key, message, hashlib.sha256).hexdigest()
    req = urllib.request.Request(
        API + path,
        data=body,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "CoreCruises-AlertEgress/1.0",
            "X-CC-Time": timestamp,
            "X-CC-Nonce": nonce,
            "X-CC-Signature": signature,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=25) as response:
            raw = response.read(MAX_API_RESPONSE + 1)
            response_signature = response.headers.get("X-CC-Response-Signature", "")
            if len(raw) > MAX_API_RESPONSE or not hmac.compare_digest(
                hmac.new(key, raw, hashlib.sha256).hexdigest(), response_signature
            ):
                raise ValueError("API response signature or size invalid")
            if response.status != 200:
                raise ValueError("API status invalid")
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise ValueError("API format invalid")
            return value
    except urllib.error.HTTPError as exc:
        # Never print API responses or signed headers.
        raise RuntimeError(f"API HTTP {exc.code}") from None


def fetch_offer(job: dict) -> bytes:
    kind, cruise_id, airport = job["type"], job["cruiseId"], job["airport"]
    if kind not in ("S", "NS") or not ID_RE.fullmatch(cruise_id) or not JOB_RE.fullmatch(job["jobId"]):
        raise ValueError("Invalid fixed offer job")
    if not isinstance(airport, str) or (airport and (kind != "S" or not re.fullmatch(r"[A-Z]{3}", airport))):
        raise ValueError("Invalid airport")
    path = "/offer?t=" + kind + "&cruise_id=" + quote(cruise_id, safe="")
    if airport:
        path += "&hmi=" + quote(airport, safe="")
    status, content_type, body = request("GET", path)
    if status == 200 and is_gate(body):
        token = TOKEN_RE.search(body)
        gate = GATE_RE.search(body)
        if not token or not gate:
            raise ValueError("Gate format invalid")
        cookie = "xtgate=" + token.group(1).decode("ascii")
        gate_path = path + "&_g=" + quote(gate.group(1).decode("ascii"), safe="")
        status, content_type, body = request("GET", gate_path, cookie, path)
        if 300 <= status < 400:
            status, content_type, body = request("GET", path, cookie, gate_path)
    if status != 200 or not content_type.lower().startswith(("text/html", "application/xhtml+xml")) or is_gate(body) or len(body) < 500:
        raise ValueError("Provider response unusable")
    if len(body) > 1_600_000:
        raise ValueError("Provider response too large")
    return body


def main() -> int:
    key_hex = os.environ.get("CC_ALERT_EGRESS_KEY", "")
    if not re.fullmatch(r"[a-f0-9]{64}", key_hex):
        print("Missing bridge secret")
        return 2
    key = bytes.fromhex(key_hex)
    jobs = api_post("/v1/internal/alert-egress/jobs", {}, key).get("jobs")
    if not isinstance(jobs, list) or len(jobs) > 500:
        print("Invalid job batch")
        return 2
    success = failed = 0
    for job in jobs:
        try:
            if not isinstance(job, dict):
                raise ValueError("Invalid job")
            html = fetch_offer(job)
            result = api_post(
                "/v1/internal/alert-egress/result",
                {"jobId": job["jobId"], "type": job["type"], "cruiseId": job["cruiseId"], "airport": job["airport"], "htmlBase64": base64.b64encode(html).decode("ascii")},
                key,
            )
            if result.get("ok") is not True or result.get("status") not in ("ok", "unavailable"):
                raise ValueError("Result rejected")
            success += 1
        except Exception as exc:
            failed += 1
            print("Job failed:", type(exc).__name__)
    print(json.dumps({"jobs": len(jobs), "successful": success, "failed": failed}, separators=(",", ":")))
    return 0 if failed == 0 and success == len(jobs) else 1


if __name__ == "__main__":
    sys.exit(main())
