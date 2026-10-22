"""Local web UI: `iotaudit web`.

Serves saved reports, a one-click LAN scan + capture page, and a pcap upload form (e.g. a
PCAPdroid capture from an Android phone).

Security model (deliberately conservative, this tool can ARP-spoof your network):
- Binds to 127.0.0.1 by default. Reaching it from a phone needs the explicit ``--lan`` flag.
- Every request needs the access token (printed at startup as part of the URL). The token is
  moved into an HttpOnly, SameSite=Strict cookie after the first visit.
- The Host header must be localhost or this machine's own address (blocks DNS rebinding), and
  POSTs with an Origin header must be same-origin (blocks cross-site requests from web pages).
- In ``--lan`` mode only clients from private/loopback addresses are served.
- Captures still need root and an explicit "I own this network" confirmation per capture.
"""

from __future__ import annotations

import html
import ipaddress
import json
import os
import re
import secrets
import socket
import threading
import time
from email.parser import BytesParser
from email.policy import default as email_policy
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

MAX_UPLOAD = 300 * 1024 * 1024
SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]{1,120}$")
COOKIE = "iotaudit_token"


def local_ips() -> set[str]:
    ips = {"127.0.0.1", "::1"}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("192.0.2.1", 9))  # no packet is sent for UDP connect
        ips.add(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ips.add(info[4][0])
    except OSError:
        pass
    return ips


def host_allowed(host_header: str | None, allowed_ips: set[str]) -> bool:
    if not host_header:
        return False
    h = host_header.strip().lower()
    if h.startswith("["):  # [::1]:8765
        h = h[1:].split("]", 1)[0]
    else:
        h = h.rsplit(":", 1)[0] if h.count(":") == 1 else h
    return h in ("localhost",) or h in {ip.lower() for ip in allowed_ips}


def client_allowed(client_ip: str, lan: bool) -> bool:
    try:
        a = ipaddress.ip_address(client_ip)
    except ValueError:
        return False
    if a.is_loopback:
        return True
    return lan and (a.is_private or a.is_link_local)


def safe_upload_name(name: str | None) -> str:
    base = os.path.basename(name or "upload.pcap")
    base = re.sub(r"[^A-Za-z0-9._-]", "_", base)[:80] or "upload.pcap"
    if not base.lower().endswith((".pcap", ".pcapng", ".cap")):
        base += ".pcap"
    return base


def parse_multipart(content_type: str, body: bytes) -> dict[str, tuple[str | None, bytes]]:
    """Return {field: (filename, data)} using the stdlib email parser (cgi is gone in 3.13)."""
    msg = BytesParser(policy=email_policy).parsebytes(
        b"Content-Type: " + content_type.encode() + b"\r\nMIME-Version: 1.0\r\n\r\n" + body
    )
    out: dict[str, tuple[str | None, bytes]] = {}
    if not msg.is_multipart():
        return out
    for part in msg.iter_parts():
        name = part.get_param("name", header="content-disposition")
        if not name:
            continue
        out[name] = (part.get_filename(), part.get_payload(decode=True) or b"")
    return out


def analyze_pcap_file(path: Path, out_html: Path, device: str | None = None) -> list[dict]:
    from .analyze import build_devices, to_dict
    from .capture import Collector, from_pcap
    from .enrich import Geo
    from .report import render_html

    col = from_pcap(str(path), Collector([device] if device else None))
    devs = [to_dict(d) for d in build_devices(col, Geo())]
    meta = {"source": f"upload:{path.name}"}
    apps = getattr(col, "apps", None)
    if apps:
        meta["source"] += " (PCAPdroid, apps: " + ", ".join(sorted(apps)[:8]) + ")"
    out_html.write_text(render_html(devs, meta), encoding="utf-8")
    out_html.with_suffix(".json").write_text(json.dumps(devs, indent=2))
    return devs


class Jobs:
    """One scan and one capture at a time; state polled by the page."""

    def __init__(self):
        self.lock = threading.Lock()
        self.scan = {"state": "idle", "devices": [], "error": None}
        self.capture = {"state": "idle", "report": None, "error": None, "ends": None}

    def start(self, kind: str, fn, *args) -> bool:
        with self.lock:
            st = getattr(self, kind)
            if st["state"] == "running":
                return False
            st.update({"state": "running", "error": None})

        def run():
            try:
                fn(*args)
                with self.lock:
                    getattr(self, kind)["state"] = "done"
            except Exception as e:  # noqa: BLE001
                with self.lock:
                    getattr(self, kind).update({"state": "error", "error": f"{type(e).__name__}: {e}"})

        threading.Thread(target=run, daemon=True, name=f"iotaudit-{kind}").start()
        return True


PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>iotaudit</title>
<style>body{{font-family:system-ui,sans-serif;max-width:860px;margin:1.5rem auto;padding:0 1rem;color:#1d1d1f}}
.card{{border:1px solid #ddd;border-radius:10px;padding:1rem;margin:1rem 0}}button{{padding:.5rem .9rem}}
table{{border-collapse:collapse;width:100%;font-size:.9rem}}
td,th{{border-bottom:1px solid #eee;padding:.3rem;text-align:left}}
.muted{{color:#666;font-size:.9rem}}.warn{{color:#b45309}}</style></head><body>
<h1>iotaudit</h1><p class="muted">Local only. Audit devices on a network you own.{lan_note}</p>
<div class="card"><h2>Reports</h2>{reports}</div>
<div class="card"><h2>Upload a capture (pcap / PCAPdroid)</h2>
<p class="muted">On Android, record with PCAPdroid (enable "PCAPdroid trailer" to keep app names), export the
.pcap, and upload it here. Optional: the IP to focus on.</p>
<form method="post" action="/upload" enctype="multipart/form-data">
<input type="file" name="pcap" accept=".pcap,.pcapng,.cap" required>
<input name="device" placeholder="device IP (optional)" size="16">
<button>Analyze</button></form></div>
<div class="card"><h2>Scan &amp; capture</h2>{capture_note}
<form method="post" action="/scan"><button>Scan my LAN</button></form>
<div id="scan"></div><div id="cap"></div></div>
<script>
// Device names/vendors come from the network (mDNS, SSDP, DHCP), so escape everything.
function e(v){{return String(v==null?'':v).replace(/[&<>"']/g,
 c=>({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[c]));}}
const DUR='<p>Duration <select name="duration"><option>120</option><option selected>600</option>'
 +'<option>1800</option><option>3600</option></select> s</p>';
const OK='<label><input type="checkbox" name="consent" value="yes" required> '
 +'I own this network and this device</label> <button>Start capture</button>';
async function poll(){{
 const r=await fetch('/api/status');if(!r.ok)return;const s=await r.json();
 let h='<p class="muted">Scan: '+e(s.scan.state)+(s.scan.error?': '+e(s.scan.error):'')+'</p>';
 if(s.scan.devices.length){{
  h+='<form method="post" action="/capture"><table>'
   +'<tr><th></th><th>IP</th><th>Looks like</th><th>Vendor</th></tr>';
  for(const d of s.scan.devices){{
   h+='<tr><td><input type="radio" name="device" value="'+e(d.ip)+'" required></td><td>'+e(d.ip)
    +'</td><td>'+e(d.looks_like)+'</td><td>'+e(d.vendor)+'</td></tr>';}}
  h+='</table>'+DUR+OK+'</form>';}}
 document.getElementById('scan').innerHTML=h;
 let c='<p class="muted">Capture: '+e(s.capture.state)+(s.capture.error?': '+e(s.capture.error):'')+'</p>';
 if(s.capture.report)c+='<p><a href="/report/'+encodeURIComponent(s.capture.report)+'">Open capture report</a></p>';
 document.getElementById('cap').innerHTML=c;
 if(s.scan.state=='running'||s.capture.state=='running')setTimeout(poll,3000);
}}
poll();
</script></body></html>"""


def make_server(host: str = "127.0.0.1", port: int = 8765, token: str | None = None,
                reports_dir: str | os.PathLike = "iotaudit-reports", lan: bool = False,
                scan_fn=None, capture_fn=None) -> ThreadingHTTPServer:
    token = token or secrets.token_urlsafe(18)
    rdir = Path(reports_dir).resolve()
    rdir.mkdir(parents=True, exist_ok=True)
    (rdir / "uploads").mkdir(exist_ok=True)
    jobs = Jobs()
    allowed_hosts = local_ips() | ({host} if host not in ("0.0.0.0", "::") else set())
    is_root = hasattr(os, "geteuid") and os.geteuid() == 0

    def default_scan():
        from .discover import arp_sweep

        devs = arp_sweep()
        with jobs.lock:
            jobs.scan["devices"] = [
                {k: d.get(k) for k in ("ip", "mac", "vendor", "looks_like", "role")}
                for d in devs if d.get("role") not in ("router", "this-host")
            ]

    def default_capture(ip: str, duration: int, out: Path):
        from .cli import build_parser

        args = build_parser().parse_args([
            "capture", "--mode", "arp", "--device", ip, "--duration", str(duration),
            "--i-own-this-network", "--out", str(out),
        ])
        args.func(args)
        with jobs.lock:
            jobs.capture["report"] = out.name

    scan_fn = scan_fn or default_scan
    capture_fn = capture_fn or default_capture

    class Handler(BaseHTTPRequestHandler):
        server_version = "iotaudit-web"

        def log_message(self, fmt, *a):  # quiet; no request logging with tokens
            pass

        # ---- auth -------------------------------------------------------------
        def _token_from_request(self) -> str | None:
            q = parse_qs(urlsplit(self.path).query)
            if q.get("token"):
                return q["token"][0]
            if self.headers.get("X-Iotaudit-Token"):
                return self.headers["X-Iotaudit-Token"]
            c = cookies.SimpleCookie(self.headers.get("Cookie", ""))
            return c[COOKIE].value if COOKIE in c else None

        def _guard(self, post: bool = False) -> bool:
            if not client_allowed(self.client_address[0], lan):
                self._send(403, "Forbidden: client not allowed")
                return False
            if not host_allowed(self.headers.get("Host"), allowed_hosts):
                self._send(421, "Misdirected request (Host not allowed)")
                return False
            tok = self._token_from_request()
            if not tok or not secrets.compare_digest(tok, token):
                self._send(401, "Unauthorized: open the URL with ?token=... printed by iotaudit web")
                return False
            if post:
                origin = self.headers.get("Origin")
                if origin and urlsplit(origin).netloc != self.headers.get("Host"):
                    self._send(403, "Forbidden: cross-origin request")
                    return False
            return True

        def _send(self, code: int, body: str | bytes, ctype: str = "text/plain; charset=utf-8",
                  extra: dict | None = None):
            data = body.encode() if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "DENY")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def _redirect(self, where: str, set_cookie: bool = False):
            self.send_response(303)
            self.send_header("Location", where)
            if set_cookie:
                self.send_header("Set-Cookie",
                                 f"{COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/")
            self.send_header("Content-Length", "0")
            self.end_headers()

        # ---- pages ------------------------------------------------------------
        def _index(self) -> str:
            files = sorted(rdir.glob("*.html"), key=lambda p: p.stat().st_mtime, reverse=True)
            if files:
                rows = "".join(
                    f'<li><a href="/report/{html.escape(p.name)}">{html.escape(p.name)}</a> '
                    f'<span class="muted">{time.strftime("%Y-%m-%d %H:%M", time.localtime(p.stat().st_mtime))}'
                    "</span></li>" for p in files[:50])
                reports = f"<ul>{rows}</ul>"
            else:
                reports = '<p class="muted">No reports yet. Upload a pcap or run a capture.</p>'
            lan_note = (" <b class='warn'>LAN mode: reachable from devices on this Wi-Fi with the token.</b>"
                        if lan else "")
            cap_note = ("" if is_root else
                        '<p class="warn">Captures need root: restart with <code>sudo iotaudit web</code>. '
                        "Scanning and uploads work without it.</p>")
            return PAGE.format(reports=reports, lan_note=lan_note, capture_note=cap_note)

        def do_GET(self):  # noqa: N802
            if not self._guard():
                return
            path = urlsplit(self.path).path
            if "token=" in (urlsplit(self.path).query or ""):
                return self._redirect(path or "/", set_cookie=True)
            if path == "/":
                return self._send(200, self._index(), "text/html; charset=utf-8")
            if path == "/api/status":
                with jobs.lock:
                    body = json.dumps({"scan": jobs.scan, "capture": jobs.capture})
                return self._send(200, body, "application/json")
            if path.startswith("/report/"):
                name = path[len("/report/"):]
                p = rdir / name
                if not SAFE_NAME.match(name) or not name.endswith(".html") or not p.is_file():
                    return self._send(404, "Not found")
                return self._send(200, p.read_bytes(), "text/html; charset=utf-8",
                                  {"Content-Security-Policy": "default-src 'none'; "
                                   "style-src 'unsafe-inline'; img-src data:"})
            return self._send(404, "Not found")

        def _body(self) -> bytes | None:
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_UPLOAD:
                self._send(413, "Upload too large")
                return None
            return self.rfile.read(n) if n else b""

        def do_POST(self):  # noqa: N802
            if not self._guard(post=True):
                return
            path = urlsplit(self.path).path
            body = self._body()
            if body is None:
                return
            ctype = self.headers.get("Content-Type", "")
            if path == "/upload":
                if "multipart/form-data" not in ctype:
                    return self._send(400, "Expected multipart/form-data")
                fields = parse_multipart(ctype, body)
                if "pcap" not in fields or not fields["pcap"][1]:
                    return self._send(400, "No pcap file")
                fname, data = fields["pcap"]
                device = (fields.get("device", (None, b""))[1] or b"").decode().strip() or None
                if device:
                    try:
                        ipaddress.ip_address(device)
                    except ValueError:
                        return self._send(400, "Bad device IP")
                stamp = time.strftime("%Y%m%d-%H%M%S")
                saved = rdir / "uploads" / f"{stamp}-{safe_upload_name(fname)}"
                saved.write_bytes(data)
                out = rdir / f"upload-{stamp}.html"
                try:
                    analyze_pcap_file(saved, out, device)
                except Exception as e:  # noqa: BLE001
                    return self._send(422, f"Could not analyze this file: {type(e).__name__}: {e}")
                return self._redirect(f"/report/{out.name}")
            form = {k: v[0] for k, v in parse_qs(body.decode("utf-8", "replace")).items()}
            if path == "/scan":
                jobs.start("scan", scan_fn)
                return self._redirect("/")
            if path == "/capture":
                if form.get("consent") != "yes":
                    return self._send(400, "Confirm you own this network and device.")
                ip = form.get("device", "")
                try:
                    if not ipaddress.ip_address(ip).is_private:
                        return self._send(400, "Only private-LAN devices can be captured.")
                except ValueError:
                    return self._send(400, "Bad device IP")
                try:
                    duration = max(30, min(int(form.get("duration", "600")), 3600))
                except ValueError:
                    duration = 600
                if not is_root and capture_fn is default_capture:
                    return self._send(403, "Captures need root: restart with sudo iotaudit web")
                out = rdir / f"capture-{time.strftime('%Y%m%d-%H%M%S')}.html"
                if not jobs.start("capture", capture_fn, ip, duration, out):
                    return self._send(409, "A capture is already running")
                return self._redirect("/")
            return self._send(404, "Not found")

    srv = ThreadingHTTPServer((host, port), Handler)
    srv.token = token  # type: ignore[attr-defined]
    srv.jobs = jobs  # type: ignore[attr-defined]
    srv.reports_dir = rdir  # type: ignore[attr-defined]
    return srv


def serve(port: int = 8765, lan: bool = False, token: str | None = None,
          reports_dir: str = "iotaudit-reports") -> None:
    host = "0.0.0.0" if lan else "127.0.0.1"
    srv = make_server(host, port, token, reports_dir, lan)
    tok = srv.token  # type: ignore[attr-defined]
    print(f"iotaudit web: http://127.0.0.1:{port}/?token={tok}")
    if lan:
        for ip in sorted(local_ips()):
            if ":" not in ip and not ip.startswith("127."):
                print(f"  from your phone (same Wi-Fi): http://{ip}:{port}/?token={tok}")
        print("  LAN mode: anyone on this Wi-Fi who has the token can use it. Ctrl+C to stop.")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
