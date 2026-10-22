"""Opt-in default-credential check for a single device you own.

This is the one active login iotaudit makes. It only runs when the user types an explicit
confirmation for a specific IP, it tries only a short list of well-known vendor *default*
credentials (never a brute-force wordlist), it waits between attempts, and it stops at the first
accepted login. It reports only "a default login was accepted" or "not accepted". It never keeps
or acts on a working shell.

Design rules, enforced here:
- One target IP, which must be a private/loopback LAN address.
- At most MAX_ATTEMPTS logins per service, each separated by DELAY seconds (rate-limited).
- Fixed credential list; callers cannot inject an arbitrary wordlist.
- Connectors are injectable so the logic is testable without touching a real device.
"""

from __future__ import annotations

import ipaddress
import socket
import time
from dataclasses import dataclass

# (username, password, where this pair is a documented factory default)
TELNET_DEFAULTS = [
    ("root", "", "many BusyBox cameras/DVRs"),
    ("root", "root", "generic"),
    ("admin", "admin", "generic"),
    ("admin", "", "generic"),
    ("root", "xc3511", "XiongMai DVR/cameras"),
    ("root", "vizxv", "Dahua-family cameras"),
    ("root", "12345", "generic cameras"),
    ("admin", "12345", "generic cameras"),
    ("support", "support", "generic"),
]
HTTP_DEFAULTS = [
    ("admin", "admin", "generic"),
    ("admin", "", "generic"),
    ("admin", "password", "generic"),
    ("admin", "12345", "generic"),
    ("user", "user", "generic"),
]
FTP_DEFAULTS = [
    ("admin", "admin", "generic"),
    ("anonymous", "anonymous@", "anonymous FTP"),
]

MAX_ATTEMPTS = 10
DELAY = 1.0  # seconds between attempts, so this is never a fast brute force
CONNECT_TIMEOUT = 5.0

CONFIRM_TEMPLATE = "TEST DEFAULT LOGINS ON {ip}"


def is_lan_target(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_private or a.is_loopback or a.is_link_local


@dataclass
class CredResult:
    service: str
    port: int
    accepted: bool
    attempts: int
    username: str | None = None   # only set when accepted
    note: str | None = None       # vendor note for the accepted pair, or an error/skip reason
    error: str | None = None

    def as_finding(self) -> dict:
        if self.error:
            return {
                "category": "credential", "severity": "info", "confidence": "certain",
                "title": f"Default-credential check could not run on {self.service}",
                "detail": f"{self.service}/{self.port}: {self.error}",
                "evidence": {"service": self.service, "port": self.port},
            }
        if self.accepted:
            return {
                "category": "credential", "severity": "high", "confidence": "certain",
                "title": f"Default {self.service} login accepted",
                "detail": (f"The device accepted a well-known default {self.service} login "
                           f"(user \"{self.username}\"{', ' + self.note if self.note else ''}). "
                           "Anyone on the network can log in. Change this password now, and "
                           "disable the service if you don't use it."),
                "evidence": {"service": self.service, "port": self.port,
                             "username": self.username, "note": self.note},
            }
        return {
            "category": "credential", "severity": "info", "confidence": "certain",
            "title": f"No default {self.service} login accepted",
            "detail": (f"Tried {self.attempts} well-known default {self.service} credential(s); "
                       "none were accepted. This does not prove the password is strong."),
            "evidence": {"service": self.service, "port": self.port, "attempts": self.attempts},
        }


def _try_each(service: str, port: int, defaults, attempt_fn, delay: float) -> CredResult:
    """Run attempt_fn(user, pwd) -> bool over the default list, rate-limited, stop on success."""
    tried = 0
    for user, pwd, note in defaults[:MAX_ATTEMPTS]:
        if tried:
            time.sleep(delay)
        tried += 1
        try:
            ok = attempt_fn(user, pwd)
        except (OSError, EOFError) as e:
            return CredResult(service, port, False, tried, error=f"{type(e).__name__}: {e}")
        if ok:
            return CredResult(service, port, True, tried, username=user, note=note)
    return CredResult(service, port, False, tried)


# --- real connectors (thin; network I/O only) --------------------------------

def _telnet_attempt(host: str, port: int, timeout: float):
    def attempt(user: str, pwd: str) -> bool:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            buf = b""

            def read_until(markers, limit=4096):
                nonlocal buf
                end = time.time() + timeout
                while time.time() < end and len(buf) < limit:
                    if any(m in buf.lower() for m in markers):
                        break
                    try:
                        chunk = s.recv(256)
                    except TimeoutError:
                        break
                    if not chunk:
                        break
                    buf += chunk
                data, buf = buf, b""
                return data

            read_until([b"login:", b"username:"])
            s.sendall(user.encode() + b"\r\n")
            data = read_until([b"password:", b"login:", b"#", b"$", b">"])
            if b"password" in data.lower():
                s.sendall(pwd.encode() + b"\r\n")
                data = read_until([b"#", b"$", b">", b"incorrect", b"login:", b"fail"])
            low = data.lower()
            if any(b in low for b in (b"incorrect", b"fail", b"denied", b"login:")):
                return False
            return any(p in data for p in (b"#", b"$", b">"))
    return attempt


def _http_basic_attempt(host: str, port: int, timeout: float, scheme: str = "http"):
    import base64
    import http.client

    def attempt(user: str, pwd: str) -> bool:
        conn_cls = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
        conn = conn_cls(host, port, timeout=timeout)
        try:
            token = base64.b64encode(f"{user}:{pwd}".encode()).decode()
            conn.request("GET", "/", headers={"Authorization": f"Basic {token}"})
            r = conn.getresponse()
            r.read()
            # 401/403 => rejected. 200/30x with Basic realm requested => accepted.
            return r.status not in (401, 403)
        finally:
            conn.close()
    return attempt


def _ftp_attempt(host: str, port: int, timeout: float):
    from ftplib import FTP, error_perm

    def attempt(user: str, pwd: str) -> bool:
        ftp = FTP()
        ftp.connect(host, port, timeout=timeout)
        try:
            ftp.login(user, pwd)
            ftp.quit()
            return True
        except error_perm:
            try:
                ftp.close()
            except OSError:
                pass
            return False
    return attempt


SERVICES = {
    "telnet": (23, TELNET_DEFAULTS, _telnet_attempt),
    "http": (80, HTTP_DEFAULTS, _http_basic_attempt),
    "ftp": (21, FTP_DEFAULTS, _ftp_attempt),
}


def check_service(ip: str, service: str, port: int | None = None, *, timeout: float = CONNECT_TIMEOUT,
                  delay: float = DELAY, attempt_factory=None) -> CredResult:
    if service not in SERVICES:
        raise ValueError(f"unknown service {service!r}")
    default_port, defaults, factory = SERVICES[service]
    port = port or default_port
    if not is_lan_target(ip):
        return CredResult(service, port, False, 0, error="target is not a private/LAN address")
    attempt = (attempt_factory or factory)(ip, port, timeout)
    return _try_each(service, port, defaults, attempt, delay)


def check_device(ip: str, services, *, confirmed: bool, timeout: float = CONNECT_TIMEOUT,
                 delay: float = DELAY, attempt_factories=None) -> list[CredResult]:
    """Run the check for each requested service. Does nothing unless `confirmed` is True."""
    if not confirmed:
        raise PermissionError("default-credential check requires explicit per-IP confirmation")
    if not is_lan_target(ip):
        raise ValueError("default-credential check only runs against a private/LAN address")
    factories = attempt_factories or {}
    results = []
    for svc in services:
        results.append(check_service(ip, svc, timeout=timeout, delay=delay,
                                     attempt_factory=factories.get(svc)))
    return results
