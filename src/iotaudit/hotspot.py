"""Hotspot mode (recommended): turn this laptop into a Wi-Fi access point via NetworkManager,
join the IoT device to it, and capture passively. No ARP spoofing needed."""

from __future__ import annotations

import shutil
import subprocess

CON_NAME = "iotaudit-hotspot"


def _nmcli(*args: str) -> subprocess.CompletedProcess:
    if not shutil.which("nmcli"):
        raise RuntimeError("nmcli (NetworkManager) not found; hotspot mode needs it on Linux.")
    return subprocess.run(["nmcli", *args], capture_output=True, text=True, check=False)


def start(ifname: str, ssid: str = "iotaudit", password: str = "auditme123") -> str:
    """Start a hotspot; returns the interface to capture on."""
    if len(password) < 8:
        raise ValueError("Wi-Fi password must be at least 8 characters.")
    r = _nmcli("device", "wifi", "hotspot", "ifname", ifname, "con-name", CON_NAME,
               "ssid", ssid, "password", password)
    if r.returncode != 0:
        raise RuntimeError(f"Could not start hotspot: {r.stderr.strip() or r.stdout.strip()}")
    return ifname


def stop() -> None:
    _nmcli("connection", "down", CON_NAME)


def clients(ifname: str) -> dict[str, str]:
    """Return {ip: mac} for clients seen in the neighbour table on the hotspot interface."""
    r = subprocess.run(["ip", "neigh", "show", "dev", ifname], capture_output=True, text=True)
    out = {}
    for line in r.stdout.splitlines():
        parts = line.split()
        if "lladdr" in parts:
            out[parts[0]] = parts[parts.index("lladdr") + 1].lower()
    return out
