"""One-command audit: discover, check, capture passively, write the report.

`iotaudit auto` keeps the ownership phrase (or the existing `--i-own-this-network`
flag). It does not try default passwords. That stays on `iotaudit credcheck`,
which already has `--yes`.
"""

from __future__ import annotations

import ipaddress
import json
import os
import platform
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path

from .analyze import build_devices, to_dict
from .arp import resolve_iface
from .capture import Collector, from_pcap
from .consent import require_consent
from .diff import audit_from_devices, diff_audits, format_diff, load_audit
from .discover import arp_sweep, format_table
from .enrich import Geo
from .pdf import PdfExtraMissing, write_pdf
from .report import render_html

DEFAULT_DURATION = 60
MAX_DURATION = 3600
PROGRESS_EVERY = 10
MAX_BPF_HOSTS = 64
REQUIRED_TOOLS = ("nmap", "tcpdump")


def install_command(packages: list[str], system: str | None = None, which=shutil.which) -> str:
    """Exact install line for the missing capture tools on this OS."""
    names = " ".join(packages)
    system = system or platform.system()
    if system == "Darwin":
        return f"brew install {names}"
    if system == "Linux":
        if which("apt-get") or which("apt"):
            return f"sudo apt install {names}"
        if which("dnf"):
            return f"sudo dnf install {names}"
        if which("pacman"):
            return f"sudo pacman -S --needed {names}"
        if which("zypper"):
            return f"sudo zypper install {names}"
    return f"sudo apt install {names}"


def missing_tools(which=shutil.which) -> list[str]:
    return [name for name in REQUIRED_TOOLS if which(name) is None]


def format_missing_tools(missing: list[str], system: str | None = None, which=shutil.which) -> str:
    """Friendly stop message with one install command."""
    system = system or platform.system()
    if len(missing) == 1:
        head = f"{missing[0]} is not installed."
        already = "If it is already installed, sudo may not see Homebrew. Re-run:"
    else:
        head = f"{' and '.join(missing)} are not installed."
        already = "If they are already installed, sudo may not see Homebrew. Re-run:"
    lines = [
        head,
        f"Install {'it' if len(missing) == 1 else 'them'}, then re-run sudo iotaudit auto:",
        f"  {install_command(missing, system=system, which=which)}",
    ]
    if system == "Darwin":
        lines.append(already)
        lines.append('  sudo env PATH="$PATH" iotaudit auto')
    return "\n".join(lines)


def host_bpf(ips: list[str]) -> str | None:
    """tcpdump filter for the audited hosts, or None when the list is too long."""
    hosts: list[str] = []
    for ip in ips:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if addr.version != 4:
            continue
        hosts.append(str(addr))
    if not hosts or len(hosts) > MAX_BPF_HOSTS:
        return None
    return " or ".join(f"host {ip}" for ip in hosts)


def pcap_packet_count(path: str | Path) -> int | None:
    """Count packets in a classic pcap. None when the file is pcapng or unknown."""
    file = Path(path)
    try:
        data = file.read_bytes()
    except OSError:
        return 0
    if len(data) < 24:
        return 0
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        return None
    offset = 24
    count = 0
    while offset + 16 <= len(data):
        incl = struct.unpack_from(endian + "IIII", data, offset)[2]
        if incl > 1_000_000:
            return count
        nxt = offset + 16 + incl
        if nxt > len(data):
            break
        offset = nxt
        count += 1
    return count


def _audit_sort_key(path: Path) -> tuple:
    stem = path.stem
    main, sep, extra = stem.partition("-")
    try:
        n = int(extra) if sep else 0
    except ValueError:
        n = 0
    return (main, n, stem)


def latest_audit(folder: Path) -> Path | None:
    """Newest JSON audit already in this dated folder, if any."""
    files = [p for p in folder.glob("*.json") if p.is_file()]
    if not files:
        return None
    return max(files, key=_audit_sort_key)


def run_paths(out_dir: Path, when: datetime) -> tuple[Path, Path, Path, Path | None]:
    """Create `out_dir/YYYY-MM-DD/` and pick HTML and JSON paths that do not collide."""
    folder = out_dir / when.strftime("%Y-%m-%d")
    folder.mkdir(parents=True, exist_ok=True)
    previous = latest_audit(folder)
    stamp = when.strftime("%H%M%S")
    candidate = folder / stamp
    n = 2
    while candidate.with_suffix(".json").exists() or candidate.with_suffix(".html").exists():
        candidate = folder / f"{stamp}-{n}"
        n += 1
    return folder, candidate.with_suffix(".html"), candidate.with_suffix(".json"), previous


def _euid() -> int:
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:
        return 0
    return int(geteuid())


def _echo(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def _read_stderr(proc) -> str:
    stream = getattr(proc, "stderr", None)
    if stream is None:
        return ""
    try:
        data = stream.read()
    except Exception:  # noqa: BLE001
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", "replace")
    return str(data or "")


def _tcpdump_failure(iface: str, stderr: str) -> str:
    text = " ".join(stderr.split())
    low = text.lower()
    if "permission" in low or "not permitted" in low:
        return (
            f"tcpdump could not capture on {iface} (permission denied). "
            "Re-run with sudo: sudo iotaudit auto"
        )
    if not text:
        text = "tcpdump exited early"
    if len(text) > 300:
        text = text[:300]
    return f"tcpdump failed on {iface}: {text}"


def _progress_line(iface: str, elapsed: int, seconds: int, dest: Path) -> str:
    count = pcap_packet_count(dest) if dest.exists() else 0
    if count is None:
        return f"Passive capture on {iface}: {elapsed}s of {seconds}s"
    noun = "packet" if count == 1 else "packets"
    return f"Passive capture on {iface}: {elapsed}s of {seconds}s, {count} {noun}"


def capture_passive(
    iface: str,
    seconds: int,
    dest: str | Path,
    *,
    bpf: str | None = None,
    progress_every: int = PROGRESS_EVERY,
    popen=None,
    sleep=time.sleep,
    clock=time.monotonic,
    echo=None,
) -> int:
    """Sniff with tcpdump for up to `seconds`. Print a progress line. Return seconds ran."""
    echo = echo or _echo
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["tcpdump", "-i", iface, "-n", "-s", "0", "-U", "-w", str(dest)]
    if bpf:
        cmd.append(bpf)
    popen = popen or subprocess.Popen
    try:
        proc = popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    except FileNotFoundError as exc:
        raise RuntimeError(format_missing_tools(["tcpdump"])) from exc

    start = clock()
    every = max(int(progress_every), 1)
    next_mark = start + every
    failed: RuntimeError | None = None
    try:
        while True:
            now = clock()
            if now - start >= seconds:
                break
            code = proc.poll()
            if code not in (None, 0):
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
                failed = RuntimeError(_tcpdump_failure(iface, _read_stderr(proc)))
                break
            if code == 0:
                break
            wake = min(next_mark, start + seconds)
            delay = wake - clock()
            if delay > 0:
                seen = clock()
                sleep(delay)
                if clock() <= seen:
                    break
            now = clock()
            if now + 1e-6 < next_mark and now - start < seconds:
                continue
            elapsed = min(seconds, max(0, int(now - start)))
            echo(_progress_line(iface, elapsed, seconds, dest))
            while next_mark <= now:
                next_mark += every
    except KeyboardInterrupt:
        echo("Capture stopped early. Writing the report with what was recorded.")
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
    if failed is not None:
        raise failed
    elapsed = min(seconds, max(0, int(clock() - start)))
    final_count = pcap_packet_count(dest) if dest.exists() else 0
    if final_count is None:
        echo(f"Passive capture on {iface} finished: {elapsed}s.")
    else:
        noun = "packet" if final_count == 1 else "packets"
        echo(f"Passive capture on {iface} finished: {elapsed}s, {final_count} {noun}.")
    return elapsed


def _when(now) -> datetime:
    if now is None:
        return datetime.now()
    if isinstance(now, datetime):
        return now
    return now()


def _out_dir(args) -> Path:
    raw = getattr(args, "out_dir", None)
    if raw:
        return Path(raw).expanduser()
    return Path.home() / "iotaudit"


def _safe_iface(name: str) -> str:
    if not name or name.startswith("-") or any(ch.isspace() for ch in name):
        raise ValueError(f"invalid interface name {name!r}")
    return name


def _ip_key(device: dict) -> int:
    try:
        return int(ipaddress.ip_address(device.get("ip") or "0.0.0.0"))
    except ValueError:
        return 0


def _audited(devices: list[dict]) -> list[dict]:
    chosen: list[dict] = []
    seen: set[str] = set()
    for device in devices:
        if device.get("role") == "this-host":
            continue
        ip = device.get("ip")
        if not ip or ip in seen:
            continue
        seen.add(ip)
        chosen.append(device)
    chosen.sort(key=_ip_key)
    return chosen


def summary_line(device: dict) -> str:
    head = device.get("verdict") or f"grade {device.get('grade')}"
    hints = device.get("known_issue_hints") or []
    hint_note = f", {len(hints)} known-issue hint(s)" if hints else ""
    label = device.get("looks_like")
    prefix = f"{label}. " if label else ""
    destinations = device.get("destinations") or []
    findings = device.get("findings") or []
    return (
        f"{device['ip']:<16} {prefix}{head}  "
        f"({len(destinations)} destinations, {len(findings)} findings{hint_note})"
    )


def _upnp_line(upnp: dict) -> str:
    if not upnp.get("routers"):
        return "no UPnP IGD answered (UPnP off, or blocked)"
    errors = upnp.get("errors") or []
    line = f"{len(upnp['routers'])} UPnP router(s), {len(upnp.get('mappings') or [])} port forward(s) open"
    if errors:
        line += f"; errors: {'; '.join(errors)}"
    return line


def _write_pdf(html: str, pdf_path: Path) -> bool:
    try:
        write_pdf(html, pdf_path)
    except PdfExtraMissing as exc:
        print(str(exc), file=sys.stderr)
        return False
    except RuntimeError as exc:
        print(f"PDF skipped: {exc}", file=sys.stderr)
        return False
    return True


def _scan_one(scan, ip: str) -> list:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        print(f"Port scan skipped for {ip}: not an IP address.", file=sys.stderr)
        return []
    if not addr.is_private:
        print(f"Port scan skipped for {ip}: not a private address.", file=sys.stderr)
        return []
    print(f"Scanning {ip} with nmap...", file=sys.stderr)
    try:
        return list(scan(ip) or [])
    except (RuntimeError, ValueError, OSError) as exc:
        print(f"Port scan skipped for {ip}: {exc}", file=sys.stderr)
        return []


def run_auto(
    args,
    *,
    consent=None,
    which=shutil.which,
    euid=None,
    system: str | None = None,
    resolve=None,
    discover=None,
    scan=None,
    upnp_audit=None,
    capture=None,
    now=None,
) -> int:
    """Run the full local audit. Network calls are injected in tests."""
    consent = consent or require_consent
    euid = euid or _euid
    system = system or platform.system()
    resolve = resolve or resolve_iface
    discover = discover or arp_sweep
    capture = capture or capture_passive

    if not consent(bool(getattr(args, "i_own_this_network", False))):
        print("Consent not given; aborting.", file=sys.stderr)
        return 2
    if system not in ("Darwin", "Linux"):
        print("iotaudit auto supports macOS and Linux.", file=sys.stderr)
        return 1

    seconds = int(getattr(args, "duration", DEFAULT_DURATION))
    if seconds < 1 or seconds > MAX_DURATION:
        print(f"error: --duration must be between 1 and {MAX_DURATION} seconds.", file=sys.stderr)
        return 2

    missing = missing_tools(which)
    if missing:
        print(format_missing_tools(missing, system=system, which=which), file=sys.stderr)
        return 1
    if euid() != 0:
        print("Packet capture needs root. Re-run: sudo iotaudit auto", file=sys.stderr)
        return 1

    requested = getattr(args, "iface", None) or "auto"
    try:
        iface = _safe_iface(resolve(requested))
    except (RuntimeError, ValueError, OSError) as exc:
        print(
            f"error: could not pick an active interface ({exc}). "
            "Pass --iface en0 (or your Wi-Fi interface).",
            file=sys.stderr,
        )
        return 1
    print(f"Using interface {iface}.", file=sys.stderr)

    print("Scanning the LAN for devices...", file=sys.stderr)
    try:
        found = list(discover(iface=iface) or [])
    except Exception as exc:  # noqa: BLE001
        print(
            f"error: LAN discovery failed ({type(exc).__name__}: {exc}). "
            "Check that you are on the same Wi-Fi (2.4GHz, no client isolation).",
            file=sys.stderr,
        )
        return 1
    audited = _audited(found)
    if not audited:
        print(
            f"No other devices found on {iface}. "
            "Check that you are on the same Wi-Fi (2.4GHz, no client isolation).",
            file=sys.stderr,
        )
        return 1
    print(f"Found {len(audited)} device(s) on {iface}.", file=sys.stderr)
    print(format_table(audited), file=sys.stderr)

    if scan is None:
        from .scan import nmap_scan

        scan = nmap_scan
    scans = {device["ip"]: _scan_one(scan, device["ip"]) for device in audited}

    upnp = None
    if upnp_audit is None:
        from .upnp import audit as upnp_audit
    print("Listing UPnP port forwards on the router (read-only)...", file=sys.stderr)
    try:
        upnp = upnp_audit()
    except OSError as exc:
        print(f"UPnP check skipped: {exc}", file=sys.stderr)
        upnp = None

    when = _when(now)
    _folder, html_path, json_path, previous_path = run_paths(_out_dir(args), when)
    meta = {"source": f"auto:{iface}", "duration": seconds}
    if upnp is not None:
        meta["upnp"] = _upnp_line(upnp)

    try:
        with tempfile.TemporaryDirectory(prefix="iotaudit-") as tmp:
            pcap = Path(tmp) / "capture.pcap"
            elapsed = capture(iface, seconds, pcap, bpf=host_bpf([d["ip"] for d in audited]))
            if isinstance(elapsed, int) and elapsed >= 0:
                meta["duration"] = elapsed
            collector = from_pcap(str(pcap), Collector([d["ip"] for d in audited]))
    except (RuntimeError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    devices = [
        to_dict(device)
        for device in build_devices(
            collector,
            Geo(getattr(args, "geoip", None)),
            getattr(args, "profiles", None),
            scans,
            upnp=upnp,
            known_devices=audited,
        )
    ]
    json_path.write_text(json.dumps(devices, indent=2), encoding="utf-8")
    html = render_html(devices, meta)
    html_path.write_text(html, encoding="utf-8")

    for device in devices:
        print(summary_line(device))
    print(f"Report written to {html_path.resolve()}")
    print(f"JSON written to {json_path.resolve()}")
    pdf_path = html_path.with_suffix(".pdf")
    if _write_pdf(html, pdf_path):
        print(f"PDF written to {pdf_path.resolve()}")

    ha_path = getattr(args, "ha_json", None)
    if previous_path is None:
        print("No earlier audit in this folder. Nothing to compare.", file=sys.stderr)
        _write_ha(ha_path, devices, None, when)
        return 0
    try:
        previous = load_audit(previous_path)
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"error: --compare: {exc}", file=sys.stderr)
        return 2
    result = diff_audits(
        previous,
        audit_from_devices(devices),
        old_label=str(previous_path),
        new_label=str(json_path),
    )
    print()
    print(format_diff(result), end="")
    _write_ha(ha_path, devices, result, when)
    return 1 if result["security_relevant"] else 0


def _write_ha(path, devices: list[dict], diff: dict | None, when: datetime) -> None:
    if not path:
        return
    from .ha import ha_summary, write_ha_summary

    try:
        dest = write_ha_summary(path, ha_summary(devices, diff, now=when))
    except OSError as exc:
        print(f"Home Assistant summary skipped: {exc}", file=sys.stderr)
        return
    print(f"Home Assistant summary written to {dest.resolve()}")
