#!/usr/bin/env python3
"""Passive multi-signal asset triage for CVE-2026-111497.

HTTP targets receive only bounded HEAD/GET requests. TCP targets are connected
and immediately closed without sending bytes. The exploit is never imported.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import http.client
import json
import re
import socket
import ssl
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import urlsplit

MAX_BODY = 64 * 1024
MAX_WORKERS = 32
USER_AGENT = "node2shell-lab-passive-scan/1.0"
NODE_RE = re.compile(r"\b(?:Node\.js|node)(?:/|\s+|/v)v?(\d+)\.(\d+)\.(\d+)\b", re.I)
FIXED = {(22,): (22, 23, 4), (24,): (24, 22, 1), (26,): (26, 12, 1)}


@dataclass(frozen=True)
class Result:
    asset: str
    status: str
    exposure: str
    observed: str
    signals: tuple[str, ...]
    detail: str
    elapsed_ms: int


def load_assets(path: Path) -> list[str]:
    seen: set[str] = set()
    assets: list[str] = []
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        value = raw.strip()
        if not value or value.startswith("#"):
            continue
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https", "tcp"} or not parsed.hostname:
            raise ValueError(f"{path}:{number}: expected an http://, https://, or tcp:// URI")
        if parsed.scheme == "tcp" and parsed.port is None:
            raise ValueError(f"{path}:{number}: tcp:// assets require an explicit port")
        if value not in seen:
            seen.add(value)
            assets.append(value)
    if not assets:
        raise ValueError(f"{path}: no assets found")
    return assets


def classify_version(version: tuple[int, int, int]) -> tuple[str, str]:
    boundary = FIXED.get((version[0],))
    if boundary is None:
        return "RUNTIME_DETECTED_VERSION_UNASSESSED", "version is outside the advisory's maintained release lines"
    if version < boundary:
        return "AFFECTED_VERSION_OBSERVED", f"below fixed release v{'.'.join(map(str, boundary))}"
    return "PATCHED_VERSION_OBSERVED", f"at or above fixed release v{'.'.join(map(str, boundary))}"


def scan_tcp(asset: str, timeout: float) -> Result:
    started = time.monotonic()
    parsed = urlsplit(asset)
    try:
        with socket.create_connection((parsed.hostname, parsed.port), timeout=timeout):
            pass
        status, exposure = "REACHABLE_VERSION_UNKNOWN", "TRANSPORT_ONLY"
        observed, signals = "TCP service", ("transport:tcp",)
        detail = "connected and sent zero bytes; runtime/version not disclosed"
    except OSError as exc:
        status, exposure, observed, signals = "UNREACHABLE", "NOT_ASSESSED", "none", ()
        detail = f"{type(exc).__name__}: {exc}"
    return Result(asset, status, exposure, observed, signals, detail, round((time.monotonic() - started) * 1000))


def inspect_http_signals(
    headers: list[tuple[str, str]], body: bytes
) -> tuple[tuple[int, int, int] | None, str | None, tuple[str, ...], str]:
    header_text = "\n".join(f"{key}: {value}" for key, value in headers)
    body_text = body.decode("latin-1", "replace")
    lower_headers, lower_body = header_text.lower(), body_text.lower()
    trusted_identity_headers = "\n".join(
        f"{key}: {value}"
        for key, value in headers
        if key.lower() in {"server", "x-powered-by", "x-node-version"}
    )
    match = NODE_RE.search(trusted_identity_headers)
    source = "header" if match else None
    if not match:
        match = re.search(r'["\'](?:node_version|nodeVersion)["\']\s*:\s*["\']v?(\d+)\.(\d+)\.(\d+)["\']', body_text)
        source = "body:diagnostic-json" if match else None
    if not match and re.search(r'["\']v8["\']\s*:', body_text, re.I):
        match = re.search(r'["\']node["\']\s*:\s*["\']v?(\d+)\.(\d+)\.(\d+)["\']', body_text, re.I)
        source = "body:process-versions" if match else None
    version = tuple(map(int, match.groups())) if match else None
    signals: list[str] = ["transport:http"]
    if version:
        signals.append(f"runtime:node/{'.'.join(map(str, version))}@{source}")
    framework_tokens = {
        "express": ("x-powered-by: express",),
        "nextjs": ("x-nextjs-", "__next_data__", "next.js"),
        "nestjs": ("nestjs",),
        "koa": ("x-powered-by: koa", "koa"),
    }
    combined = lower_headers + "\n" + lower_body
    for name, tokens in framework_tokens.items():
        if any(token in combined for token in tokens):
            signals.append(f"framework:{name}")
    if re.search(r"^server:\s*", header_text, re.I | re.M):
        signals.append("header:server")
    if re.search(r"^content-encoding:\s*br\s*$", header_text, re.I | re.M):
        signals.append("encoding:brotli-response")
    url_input = bool(
        re.search(r"<input\b[^>]*\bname\s*=\s*['\"]?(?:url|uri|endpoint|target)\b", body_text, re.I)
        or re.search(r'"(?:url|uri|endpoint|target)"\s*:', body_text, re.I)
    )
    if url_input:
        signals.append("surface:url-input")
    if url_input:
        exposure = "OUTBOUND_URL_INPUT_SIGNAL"
    elif any(signal.startswith(("runtime:", "framework:")) for signal in signals):
        exposure = "NODE_APPLICATION_SIGNAL"
    else:
        exposure = "HTTP_SERVICE_ONLY"
    priority = {"surface": 0, "encoding": 1, "framework": 2, "header": 3, "runtime": 4, "transport": 5}
    signals.sort(key=lambda value: (priority.get(value.split(":", 1)[0], 99), value))
    return version, source, tuple(signals), exposure


def scan_http(asset: str, timeout: float) -> Result:
    started = time.monotonic()
    parsed = urlsplit(asset)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    request_headers = {"User-Agent": USER_AGENT, "Accept": "text/html,application/json;q=0.8,*/*;q=0.1", "Connection": "close"}
    try:
        response_headers: list[tuple[str, str]] = []
        body = b""
        code = 0
        for method in ("HEAD", "GET"):
            connection_cls = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
            kwargs = {"timeout": timeout}
            if parsed.scheme == "https":
                kwargs["context"] = ssl.create_default_context()
            connection = connection_cls(parsed.hostname, port, **kwargs)
            try:
                connection.request(method, path, headers=request_headers)
                response = connection.getresponse()
                code = response.status
                response_headers.extend(response.getheaders())
                body = response.read(MAX_BODY + 1)[:MAX_BODY] if method == "GET" else b""
            finally:
                connection.close()
        version, _version_source, signals, exposure = inspect_http_signals(response_headers, body)
        if version:
            status, detail = classify_version(version)
            observed = "Node.js/v" + ".".join(map(str, version))
        elif any(signal.startswith("framework:") for signal in signals):
            status, observed, detail = "RUNTIME_DETECTED_VERSION_HIDDEN", "Node.js application signal", "Node.js version was not disclosed"
        else:
            status, observed, detail = "REACHABLE_VERSION_UNKNOWN", "HTTP service", "runtime/version not disclosed"
        detail = f"HTTP {code}; {detail}"
    except (OSError, ssl.SSLError, http.client.HTTPException, ValueError) as exc:
        # Some labs intentionally accept the connection and close it before an
        # HTTP response. Confirm transport reachability without sending bytes so
        # a protocol-level refusal is not reported as an unreachable asset.
        try:
            with socket.create_connection((parsed.hostname, port), timeout=timeout):
                pass
            status, exposure = "REACHABLE_VERSION_UNKNOWN", "TRANSPORT_ONLY"
            observed, signals = "TCP service", ("transport:tcp",)
            detail = f"TCP reachable; HTTP probe ended with {type(exc).__name__}"
        except OSError as transport_exc:
            status, exposure, observed, signals = "UNREACHABLE", "NOT_ASSESSED", "none", ()
            detail = f"{type(transport_exc).__name__}: {transport_exc}"
    return Result(asset, status, exposure, observed, signals, detail, round((time.monotonic() - started) * 1000))


def scan(asset: str, timeout: float) -> Result:
    try:
        return scan_tcp(asset, timeout) if urlsplit(asset).scheme == "tcp" else scan_http(asset, timeout)
    except Exception as exc:  # keep one malformed endpoint from aborting the asset set
        return Result(asset, "ERROR", "NOT_ASSESSED", "none", (), f"{type(exc).__name__}: {exc}", 0)


def print_table(results: list[Result]) -> None:
    columns = [
        ("ASSET", [r.asset for r in results]),
        ("STATUS", [r.status for r in results]),
        ("EXPOSURE", [r.exposure for r in results]),
        ("SIGNALS", [",".join(r.signals) for r in results]),
    ]
    widths = [min(max(len(title), *(len(v) for v in values)), cap) for (title, values), cap in zip(columns, (30, 31, 28, 64))]
    def row(values: list[str]) -> str:
        return "  ".join(value[:width].ljust(width) for value, width in zip(values, widths)).rstrip()
    print(row([title for title, _ in columns]))
    print(row(["-" * width for width in widths]))
    for result in results:
        print(row([result.asset, result.status, result.exposure, ",".join(result.signals)]))


def main() -> int:
    parser = argparse.ArgumentParser(description="Passive multi-signal asset triage; does not test exploitation")
    parser.add_argument("--assets", required=True, type=Path, help="newline-delimited http(s) or tcp URIs")
    parser.add_argument("--workers", type=int, default=4, help=f"concurrent workers (1-{MAX_WORKERS})")
    parser.add_argument("--timeout", type=float, default=5.0, help="per-request timeout in seconds")
    parser.add_argument("--format", choices=("table", "jsonl"), default="table")
    args = parser.parse_args()
    if not 1 <= args.workers <= MAX_WORKERS:
        parser.error(f"--workers must be between 1 and {MAX_WORKERS}")
    if not 0 < args.timeout <= 60:
        parser.error("--timeout must be greater than 0 and at most 60")
    try:
        assets = load_assets(args.assets)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    info_stream = sys.stderr if args.format == "jsonl" else sys.stdout
    print(f"[*] loaded {len(assets)} unique assets from {args.assets}", file=info_stream)
    print("[*] passive mode: bounded HEAD/GET or zero-byte TCP connect; no exploit or availability test", file=info_stream)
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(scan, asset, args.timeout): index for index, asset in enumerate(assets)}
        indexed = [(futures[future], future.result()) for future in concurrent.futures.as_completed(futures)]
    results = [result for _, result in sorted(indexed)]
    if args.format == "jsonl":
        for result in results:
            print(json.dumps(asdict(result), sort_keys=True))
    else:
        print_table(results)
    counts: dict[str, int] = {}
    for result in results:
        counts[result.status] = counts.get(result.status, 0) + 1
    print("[*] summary " + " ".join(f"{key}={counts[key]}" for key in sorted(counts)), file=info_stream)
    return 0


if __name__ == "__main__":
    sys.exit(main())
