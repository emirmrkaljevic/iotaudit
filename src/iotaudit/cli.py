"""Command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .analyze import build_devices, to_dict
from .capture import Collector, build_bpf, from_pcap, live
from .consent import require_consent
from .enrich import Geo
from .report import render_html


def _finish(col, args, meta) -> int:
    scans = {}
    if getattr(args, "scan", False):
        from .scan import nmap_scan

        for ip in (args.device or []):
            print(f"Scanning {ip} with nmap...", file=sys.stderr)
            scans[ip] = nmap_scan(ip)
    peer_labels = getattr(args, "_peer_labels", None) or {}
    devices = [to_dict(d) for d in build_devices(
        col, Geo(args.geoip), args.profiles, scans, peer_labels=peer_labels)]
    json_path = args.json or str(Path(args.out).with_suffix(".json"))
    Path(json_path).write_text(json.dumps(devices, indent=2))
    out = Path(args.out)
    out.write_text(render_html(devices, meta), encoding="utf-8")
    for d in devices:
        print(f"{d['ip']:<16} grade {d['grade']}  ({len(d['destinations'])} destinations, "
              f"{len(d['findings'])} findings)")
    print(f"Report written to {out.resolve()}")
    print(f"JSON written to {Path(json_path).resolve()}")
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


def cmd_analyze(args) -> int:
    col = from_pcap(args.pcap, Collector(args.device))
    return _finish(col, args, {"source": args.pcap})


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
        sp.add_argument("--geoip", help="path to a GeoLite2/DB-IP country .mmdb")
        sp.add_argument("--profiles", help="extra directory of device profile YAML files")
        sp.add_argument("--scan", action=argparse.BooleanOptionalAction, default=True,
                       help="nmap-scan each --device after capture (default: on; --no-scan to skip)")

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
    c.set_defaults(func=cmd_capture)

    a = sub.add_parser("analyze", help="analyse an existing pcap")
    a.add_argument("pcap")
    common(a)
    a.set_defaults(func=cmd_analyze)

    s = sub.add_parser("scan", help="nmap open-port scan of one device")
    s.add_argument("ip")
    s.add_argument("--i-own-this-network", action="store_true")
    s.set_defaults(func=cmd_scan)

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
