"""Command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from jinja2 import TemplateError

from . import __version__
from .analyze import build_devices, to_dict
from .capture import Collector, build_bpf, from_pcap, live
from .consent import require_consent
from .diff import audit_from_devices, diff_audits, diff_results, format_diff, load_audit
from .enrich import Geo
from .pdf import PdfExtraMissing, write_pdf
from .report import render_html
from .upnp import RISKY_PORTS as RISKY


def _finish(col, args, meta) -> int:
    scans = {}
    if getattr(args, "scan", False):
        from .scan import nmap_scan

        for ip in (args.device or []):
            print(f"Scanning {ip} with nmap...", file=sys.stderr)
            scans[ip] = nmap_scan(ip)
    upnp = None
    if getattr(args, "upnp", False):
        from .upnp import audit

        print("Listing UPnP port forwards on the router (read-only)...", file=sys.stderr)
        try:
            upnp = audit()
        except OSError as e:
            print(f"UPnP check skipped: {e}", file=sys.stderr)
        if upnp is not None:
            meta = {**meta, "upnp": _upnp_line(upnp)}
    peer_labels = getattr(args, "_peer_labels", None) or {}
    devices = [to_dict(d) for d in build_devices(
        col, Geo(args.geoip), args.profiles, scans, peer_labels=peer_labels, upnp=upnp)]
    compare = getattr(args, "compare", None)
    previous = None
    compare_error = None
    if compare:
        try:
            previous = load_audit(compare)
        except (OSError, UnicodeError, ValueError) as exc:
            compare_error = exc
    json_path = args.json or str(Path(args.out).with_suffix(".json"))
    Path(json_path).write_text(json.dumps(devices, indent=2))
    out = Path(args.out)
    html = render_html(devices, meta)
    out.write_text(html, encoding="utf-8")
    for d in devices:
        head = d.get("verdict") or f"grade {d['grade']}"
        hints = d.get("known_issue_hints") or []
        hint_note = f", {len(hints)} known-issue hint(s)" if hints else ""
        print(f"{d['ip']:<16} {head}  ({len(d['destinations'])} destinations, "
              f"{len(d['findings'])} findings{hint_note})")
    print(f"Report written to {out.resolve()}")
    print(f"JSON written to {Path(json_path).resolve()}")
    if getattr(args, "pdf", False):
        pdf_path = out.with_suffix(".pdf")
        if _emit_pdf(html, pdf_path):
            print(f"PDF written to {pdf_path.resolve()}")
    if compare_error is not None:
        print(f"error: --compare: {compare_error}", file=sys.stderr)
        return 2
    if previous is not None:
        result = diff_audits(
            previous, audit_from_devices(devices),
            old_label=str(compare), new_label=str(json_path),
        )
        print()
        print(format_diff(result), end="")
        return 1 if result["security_relevant"] else 0
    return 0


def _emit_pdf(html: str, pdf_path: Path) -> bool:
    """Write a PDF. On a missing extra, print one hint line and return False."""
    try:
        write_pdf(html, pdf_path)
    except PdfExtraMissing as exc:
        print(str(exc), file=sys.stderr)
        return False
    return True


def _html_for_report_input(path: Path) -> str:
    raw = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".html", ".htm"} or raw.lstrip().startswith("<"):
        return raw
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"not a JSON or HTML report: {path.name}") from exc
    meta: dict = {}
    if isinstance(data, dict) and isinstance(data.get("devices"), list):
        devices = data["devices"]
        if isinstance(data.get("meta"), dict):
            meta = data["meta"]
    elif isinstance(data, list):
        devices = data
    else:
        raise ValueError("report JSON must be a list of devices")
    try:
        return render_html(devices, meta)
    except TemplateError as exc:
        raise ValueError(f"could not render report JSON: {exc}") from exc


def cmd_report(args) -> int:
    src = Path(args.input)
    if not src.is_file():
        print(f"error: not a file: {src}", file=sys.stderr)
        return 2
    if not args.pdf:
        print("Pass --pdf to write a PDF. Example: iotaudit report --pdf report.html",
              file=sys.stderr)
        return 2
    dest = Path(args.out) if args.out else src.with_suffix(".pdf")
    if dest.resolve() == src.resolve():
        print("error: PDF output path is the same as the input.", file=sys.stderr)
        return 2
    try:
        html = _html_for_report_input(src)
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if not _emit_pdf(html, dest):
        return 1
    print(f"PDF written to {dest.resolve()}")
    return 0


def cmd_capture(args) -> int:
    if not require_consent(args.i_own_this_network):
        print("Consent not given; aborting.", file=sys.stderr)
        return 2
    iface = args.iface
    chosen = None
    lan_devices = []
    if not args.device and args.mode in ("arp", "iface"):
        from .discover import arp_sweep, pick

        print("Scanning the LAN for devices...", file=sys.stderr)
        try:
            lan_devices = arp_sweep(iface=None if args.iface == "auto" else args.iface)
        except Exception as e:  # noqa: BLE001
            print(f"error: LAN discovery failed ({type(e).__name__}: {e}). "
                  "Try naming the device with --device <ip>, or check you're on 2.4GHz Wi-Fi.",
                  file=sys.stderr)
            return 1
        chosen = pick(lan_devices)
        if not chosen:
            print("No device selected; aborting.", file=sys.stderr)
            return 2
        args.device = [chosen["ip"]]
        print(f"Auditing {chosen['ip']} "
              f"({chosen.get('looks_like') or chosen.get('vendor') or 'unknown'}).",
              file=sys.stderr)
    if args.mode == "hotspot":
        from . import hotspot

        hotspot.start(args.iface, args.ssid, args.password)
        print(f"Hotspot '{args.ssid}' up on {args.iface}. Join your device to it now.",
              file=sys.stderr)
    spoofer = None
    ndp_spoofer = None
    fwd = None
    bpf = None
    if args.mode == "arp":
        from . import arp

        if not args.device:
            print("ARP mode needs at least one --device (the IP to audit).", file=sys.stderr)
            return 2
        target_ip = args.device[0]
        # Reuse MACs from the LAN scan so sendp() never ARP-resolves L2 itself.
        if not lan_devices:
            from .discover import arp_sweep as _sweep
            try:
                lan_devices = _sweep(iface=None if args.iface == "auto" else args.iface)
            except Exception:  # noqa: BLE001
                lan_devices = []
        by_ip = {d["ip"]: d for d in lan_devices}
        target_mac = (chosen or by_ip.get(target_ip) or {}).get("mac")
        gw_ip = args.gateway or arp.default_gateway()
        gateway_mac = None
        if gw_ip and gw_ip in by_ip:
            gateway_mac = by_ip[gw_ip].get("mac")
        else:
            for d in lan_devices:
                if d.get("role") == "router":
                    gateway_mac = d.get("mac")
                    gw_ip = gw_ip or d.get("ip")
                    break
        iface = arp.resolve_iface(args.iface)
        fwd = arp.IPForwarding().__enter__()
        watch = args.watch_lan if args.watch_lan is not None else bool(chosen)
        extra_peers = []
        peer_labels = {}
        if watch:
            for d in lan_devices:
                ip, mac = d.get("ip"), d.get("mac")
                if not ip or not mac or ip in (target_ip, gw_ip):
                    continue
                if d.get("role") in ("router", "this-host"):
                    continue
                extra_peers.append((ip, mac))
                peer_labels[ip] = d.get("looks_like") or d.get("vendor") or ip
            print(f"Watch-LAN on: spoofing {len(extra_peers)} peer(s) so device↔phone "
                  f"unicast is visible.", file=sys.stderr)
        args._peer_labels = peer_labels
        spoofer = arp.start(target_ip, gw_ip, iface,
                            target_mac=target_mac, gateway_mac=gateway_mac,
                            extra_peers=extra_peers)
        bpf = build_bpf(target_ip, target_mac, ipv6=not args.no_ipv6)
        if args.ipv6_ndp and extra_peers and target_mac:
            pairs = [(target_mac, pmac) for (_pip, pmac) in extra_peers]
            ndp_spoofer = arp.NDPSpoofer(iface, arp.our_mac(iface), pairs=pairs).start()
    elif iface == "auto":
        try:
            from .arp import resolve_iface
            iface = resolve_iface("auto")
        except Exception:  # noqa: BLE001
            iface = None
    col = Collector(args.device)
    try:
        live(iface, args.duration, col, bpf_filter=bpf)
    except KeyboardInterrupt:
        pass
    finally:
        if args.mode == "hotspot" and not args.keep_hotspot:
            from . import hotspot

            hotspot.stop()
        if ndp_spoofer is not None:
            ndp_spoofer.stop()
        if spoofer is not None:
            print("Restoring ARP tables...", file=sys.stderr)
            spoofer.stop()
        if fwd is not None:
            fwd.__exit__(None, None, None)
    return _finish(col, args, {"source": f"{args.mode}:{iface}", "duration": args.duration})


def _upnp_line(u: dict) -> str:
    if not u["routers"]:
        return "no UPnP IGD answered (UPnP off, or blocked)"
    return (f"{len(u['routers'])} UPnP router(s), {len(u['mappings'])} port forward(s) open"
            + (f"; errors: {'; '.join(u['errors'])}" if u["errors"] else ""))


def cmd_credcheck(args) -> int:
    from .credcheck import CONFIRM_TEMPLATE, SERVICES, check_device, is_lan_target

    ip = args.ip
    if not is_lan_target(ip):
        print(f"{ip} is not a private/LAN address; refusing.", file=sys.stderr)
        return 2
    services = args.service or ["telnet"]
    for svc in services:
        if svc not in SERVICES:
            print(f"unknown service {svc!r} (choose from {', '.join(SERVICES)})", file=sys.stderr)
            return 2
    phrase = CONFIRM_TEMPLATE.format(ip=ip)
    confirmed = args.yes
    if not confirmed:
        print("This will attempt a short list of well-known DEFAULT logins against "
              f"{', '.join(services)} on {ip}.", file=sys.stderr)
        print("Only do this on a device you own. It is rate-limited and never brute-forces.",
              file=sys.stderr)
        print(f'Type exactly: {phrase}', file=sys.stderr)
        try:
            answer = sys.stdin.readline().strip()
        except (EOFError, KeyboardInterrupt):
            answer = ""
        confirmed = answer == phrase
    if not confirmed:
        print("Confirmation phrase not entered; aborting.", file=sys.stderr)
        return 2
    results = check_device(ip, services, confirmed=True)
    out = [r.as_finding() for r in results]
    if args.json:
        print(json.dumps(out, indent=2))
    else:
        for r in results:
            f = r.as_finding()
            print(f"[{f['severity']}] {f['title']} - {f['detail']}")
    return 1 if any(r.accepted for r in results) else 0


def cmd_upnp(args) -> int:
    from .upnp import audit

    u = audit(timeout=args.timeout)
    if args.json:
        print(json.dumps(u, indent=2))
        return 0
    if not u["routers"]:
        print("No UPnP Internet Gateway answered. Either UPnP is off on your router (good) "
              "or multicast is blocked on this network.")
    for r in u["routers"]:
        print(f"Router: {r.get('name') or '?'} {r.get('model') or ''} "
              f"(external IP {r.get('external_ip') or 'unknown'})")
    if u["routers"] and not u["mappings"]:
        print("UPnP is on, but no port forwards are open right now.")
    for m in u["mappings"]:
        flag = " <- risky" if m["internal_port"] in RISKY or m["external_port"] in RISKY else ""
        print(f"  {m['protocol']:<3} public :{m['external_port']:<5} -> "
              f"{m['internal_client']}:{m['internal_port']:<5} {m['description']!r}{flag}")
    for e in u["errors"]:
        print(f"error: {e}", file=sys.stderr)
    return 0


def cmd_analyze(args) -> int:
    col = from_pcap(args.pcap, Collector(args.device))
    return _finish(col, args, {"source": args.pcap})


def cmd_diff(args) -> int:
    try:
        result = diff_results(args.old, args.new)
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(format_diff(result), end="")
    return result["exit_code"]


def cmd_scan(args) -> int:
    if not require_consent(args.i_own_this_network):
        return 2
    from .scan import nmap_scan

    print(json.dumps(nmap_scan(args.ip), indent=2))
    return 0


def cmd_mcp(args) -> int:
    from .mcp_server import main as mcp_main

    mcp_main()
    return 0


def cmd_web(args) -> int:
    from .web import serve

    serve(port=args.port, lan=args.lan, token=args.token, reports_dir=args.reports_dir)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="iotaudit", description="Audit your own smart-home devices.")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("--device", action="append", help="device IP to focus on (repeatable)")
        sp.add_argument("--out", default="iotaudit-report.html")
        sp.add_argument("--json", help="also write JSON results here")
        sp.add_argument("--pdf", action="store_true",
                        help='also write a PDF next to the HTML (needs: pip install "iotaudit[pdf]")')
        sp.add_argument("--geoip", help="path to a GeoLite2/DB-IP country .mmdb")
        sp.add_argument("--profiles", help="extra directory of device profile YAML files")
        sp.add_argument("--scan", action=argparse.BooleanOptionalAction, default=True,
                       help="nmap-scan each --device after capture (default: on; --no-scan to skip)")
        sp.add_argument("--upnp", action=argparse.BooleanOptionalAction, default=False,
                        help="list router UPnP port forwards to the device (read-only; "
                             "default on for capture, off for analyze)")
        sp.add_argument("--compare", metavar="PREV.json",
                        help="after the report, diff it against this earlier JSON audit")

    c = sub.add_parser("capture", help="live capture (hotspot recommended)")
    c.add_argument("--mode", choices=["hotspot", "iface", "arp"], default="hotspot",
                   help="hotspot: start Wi-Fi AP; iface: sniff an existing interface")
    c.add_argument("--iface", default="auto", help="capture interface; 'auto' lets libpcap choose")
    c.add_argument("--gateway", help="ARP mode: router IP (auto-detected if omitted)")
    c.add_argument("--ssid", default="iotaudit")
    c.add_argument("--password", default="auditme123")
    c.add_argument("--duration", type=int, default=3600,
                   help="capture seconds; Ctrl+C stops early and still writes the report")
    c.add_argument("--keep-hotspot", action="store_true")
    c.add_argument("--watch-lan", action=argparse.BooleanOptionalAction, default=None,
                   help="ARP-spoof target<->LAN peers for phone P2P (default on with picker)")
    c.add_argument("--no-ipv6", action="store_true",
                   help="do not add IPv6/ICMPv6 (NDP) to the capture filter")
    c.add_argument("--ipv6-ndp", action="store_true",
                   help="experimental: also NDP-spoof IPv6 link-local so phone<->device "
                        "IPv6 unicast is visible (ARP-mode only)")
    c.add_argument("--i-own-this-network", action="store_true")
    common(c)
    c.set_defaults(func=cmd_capture, upnp=True)

    a = sub.add_parser("analyze", help="analyse an existing pcap")
    a.add_argument("pcap")
    common(a)
    a.set_defaults(func=cmd_analyze)

    d = sub.add_parser("diff", help="compare two JSON audits (exit 1 when new risk appeared)")
    d.add_argument("old", help="earlier JSON results")
    d.add_argument("new", help="later JSON results")
    d.add_argument("--json", action="store_true", help="print machine-readable JSON")
    d.set_defaults(func=cmd_diff)

    r = sub.add_parser("report", help="write a PDF from a saved JSON or HTML report")
    r.add_argument("input", help="saved device JSON, or an HTML report")
    r.add_argument("--pdf", action="store_true",
                   help='write a PDF next to the input (needs: pip install "iotaudit[pdf]")')
    r.add_argument("--out", help="PDF path (default: the input path with a .pdf suffix)")
    r.set_defaults(func=cmd_report)

    s = sub.add_parser("scan", help="nmap open-port scan of one device")
    s.add_argument("ip")
    s.add_argument("--i-own-this-network", action="store_true")
    s.set_defaults(func=cmd_scan)

    cc = sub.add_parser("credcheck",
                        help="opt-in default-password check on one device you own (active login)")
    cc.add_argument("ip")
    cc.add_argument("--service", action="append", choices=["telnet", "http", "ftp"],
                    help="service to test (repeatable; default: telnet)")
    cc.add_argument("--yes", action="store_true",
                    help="skip the typed confirmation prompt (scripted use; you still own it)")
    cc.add_argument("--json", action="store_true")
    cc.set_defaults(func=cmd_credcheck)

    u = sub.add_parser("upnp", help="list port forwards your router opened via UPnP (read-only)")
    u.add_argument("--timeout", type=float, default=3.0)
    u.add_argument("--json", action="store_true")
    u.set_defaults(func=cmd_upnp)

    w = sub.add_parser("web", help="local web UI: reports, scan/capture, pcap upload")
    w.add_argument("--port", type=int, default=8765)
    w.add_argument("--lan", action="store_true",
                   help="also listen on your LAN so a phone on the same Wi-Fi can connect "
                        "(token still required)")
    w.add_argument("--token", help="access token (default: random, printed at start)")
    w.add_argument("--reports-dir", default="iotaudit-reports")
    w.set_defaults(func=cmd_web)

    m = sub.add_parser("mcp", help="run the MCP server (stdio)")
    m.set_defaults(func=cmd_mcp)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (RuntimeError, ValueError, NotImplementedError, PermissionError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
