"""Minimal MQTT 3.1.1 publisher (stdlib only). Used to push Home Assistant summaries."""

from __future__ import annotations

import os
import socket
import ssl
import struct
from urllib.parse import unquote, urlparse


class MqttError(Exception):
    """The broker could not be reached, or it refused the connection."""


def parse_mqtt_target(spec: str, username: str | None = None, password: str | None = None) -> dict:
    """Parse a host, host:port, mqtt:// or mqtts:// URL into connection settings."""
    raw = (spec or "").strip()
    if not raw:
        raise ValueError("MQTT target is empty")
    if "://" not in raw:
        raw = "mqtt://" + raw
    parsed = urlparse(raw)
    if parsed.scheme not in {"mqtt", "mqtts"}:
        raise ValueError(f"unsupported MQTT scheme: {parsed.scheme}")
    host = parsed.hostname
    if not host:
        raise ValueError("MQTT target is missing a host")
    use_tls = parsed.scheme == "mqtts"
    port = parsed.port or (8883 if use_tls else 1883)
    user = unquote(parsed.username) if parsed.username else username
    pwd = unquote(parsed.password) if parsed.password is not None else password
    if pwd is None:
        pwd = os.environ.get("IOTAUDIT_MQTT_PASSWORD")
    if user is None:
        user = os.environ.get("IOTAUDIT_MQTT_USER") or os.environ.get("IOTAUDIT_MQTT_USERNAME")
    return {
        "host": host,
        "port": int(port),
        "tls": use_tls,
        "username": user,
        "password": pwd,
    }


def _remaining_length(n: int) -> bytes:
    if n < 0 or n > 268435455:
        raise ValueError("MQTT packet is too large")
    out = bytearray()
    while True:
        byte = n % 128
        n //= 128
        if n:
            byte |= 0x80
        out.append(byte)
        if not n:
            break
    return bytes(out)


def _utf8(value: str) -> bytes:
    data = value.encode("utf-8")
    if len(data) > 65535:
        raise ValueError("MQTT string is too long")
    return struct.pack("!H", len(data)) + data


def connect_packet(
    client_id: str, username: str | None = None, password: str | None = None, keepalive: int = 60
) -> bytes:
    payload = _utf8(client_id)
    flags = 0x02  # clean session
    if username is not None:
        flags |= 0x80
        payload += _utf8(username)
        if password is not None:
            flags |= 0x40
            payload += _utf8(password)
    elif password is not None:
        raise ValueError("MQTT password requires a username")
    variable = _utf8("MQTT") + bytes([4, flags]) + struct.pack("!H", keepalive) + payload
    return bytes([0x10]) + _remaining_length(len(variable)) + variable


def publish_packet(topic: str, payload: bytes | str, retain: bool = False) -> bytes:
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    body = _utf8(topic) + payload
    flags = 0x30 | (0x01 if retain else 0x00)
    return bytes([flags]) + _remaining_length(len(body)) + body


def disconnect_packet() -> bytes:
    return b"\xe0\x00"


def _read_exact(sock: socket.socket, n: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < n:
        piece = sock.recv(n - len(chunks))
        if not piece:
            raise MqttError("the MQTT broker closed the connection")
        chunks.extend(piece)
    return bytes(chunks)


def _read_packet(sock: socket.socket) -> tuple[int, bytes]:
    header = _read_exact(sock, 1)[0]
    multiplier = 1
    length = 0
    while True:
        byte = _read_exact(sock, 1)[0]
        length += (byte & 0x7F) * multiplier
        if not (byte & 0x80):
            break
        multiplier *= 128
        if multiplier > 128 * 128 * 128:
            raise MqttError("the MQTT broker sent a bad packet length")
    body = _read_exact(sock, length) if length else b""
    return header, body


def publish_many(
    target: dict, messages: list[tuple[str, str | bytes, bool]], timeout: float = 8.0, client_id: str | None = None
) -> int:
    """Connect, publish each (topic, payload, retain) message, disconnect. Returns the count."""
    if not messages:
        return 0
    cid = client_id or f"iotaudit-{os.getpid()}"
    sock = socket.create_connection((target["host"], target["port"]), timeout=timeout)
    try:
        if target.get("tls"):
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=target["host"])
        sock.settimeout(timeout)
        sock.sendall(connect_packet(cid, target.get("username"), target.get("password")))
        header, body = _read_packet(sock)
        if (header & 0xF0) != 0x20 or len(body) < 2 or body[1] != 0:
            reason = body[1] if len(body) > 1 else -1
            raise MqttError(f"the MQTT broker refused the connection (code {reason})")
        for topic, payload, retain in messages:
            sock.sendall(publish_packet(topic, payload, retain=retain))
        sock.sendall(disconnect_packet())
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return len(messages)
