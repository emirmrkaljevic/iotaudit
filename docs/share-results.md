---
title: "Share your iotaudit results without leaking your network"
---
# Share your iotaudit results without leaking your network

When I ask for help with a strange device in a forum, I want to show what it does without posting my local IP addresses. Since 0.1.16, `iotaudit export` can leave them out.

```
pip install -U iotaudit
iotaudit export audit.json --format md --redact
```

Example output (sample data):

```
iotaudit summary: 3 devices, worst grade D, 1 finding

| name | ip | grade | findings | changed | status |
|---|---|---|---|---|---|
| Example Vendor |  | D | 1 |  | first_run |
| Example Vendor |  | C | 0 |  | first_run |
| device 3 |  | C | 0 |  | first_run |
```

- `--format md` gives a Markdown table for GitHub issues, Reddit or the Home Assistant forum.
- `--format csv` gives one row per device for a spreadsheet.
- `--compare earlier.json` fills in which devices changed since the last audit.
- `--redact` works with every format. Devices that only had an IP as their name become "device 1", "device 2", and so on.

The full HTML report still contains addresses, so share the exported summary rather than the report itself. Only audit networks and devices you own. All data stays local, no telemetry.

[All device pages](./)
