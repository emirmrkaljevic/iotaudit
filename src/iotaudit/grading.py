"""A-F grading. Start at 100, subtract per finding, map to a letter.
Findings are indicators based on observed traffic, not proof of wrongdoing."""

from __future__ import annotations

PENALTY = {"high": 25, "medium": 10, "low": 4, "info": 0}
GRADES = [(90, "A"), (75, "B"), (60, "C"), (45, "D"), (30, "E"), (0, "F")]


def findings_for(device) -> list[dict]:
    f: list[dict] = []
    for d in device.destinations.values():
        label = ", ".join(sorted(d.domains)) or d.ip
        if not d.encrypted:
            f.append({"severity": "high", "title": "Unencrypted traffic to the internet",
                      "detail": f"Plaintext traffic to {label} (ports {sorted(d.ports)})."})
        if d.tracker:
            f.append({"severity": "medium", "title": "Tracker / analytics endpoint",
                      "detail": f"Contacts {label}, listed as a tracker/analytics service."})
        if d.expected is False:
            f.append({"severity": "low", "title": "Destination not in device profile",
                      "detail": f"{label} is not an expected destination for {device.profile}."})
    for flow_note in getattr(device, "_old_tls", []):
        f.append({"severity": "medium", "title": "Outdated TLS", "detail": flow_note})
    for p in device.open_ports:
        if p.get("risk"):
            f.append({"severity": p["risk"], "title": f"Open port {p['port']}/{p['proto']}"
                      f" ({p.get('service') or '?'})", "detail": p.get("why", "")})
    countries = {d.country for d in device.destinations.values() if d.country}
    if len(countries) >= 3:
        f.append({"severity": "low", "title": "Data sent to many countries",
                  "detail": "Destinations in: " + ", ".join(sorted(countries))})
    return f


def grade(findings: list[dict]) -> tuple[int, str]:
    score = 100
    for x in findings:
        score -= PENALTY.get(x["severity"], 0)
    score = max(score, 0)
    letter = next(g for t, g in GRADES if score >= t)
    return score, letter
