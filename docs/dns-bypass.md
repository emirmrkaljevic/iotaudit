---
title: DNS that bypasses your resolver
---
# DNS that bypasses your resolver

Since 0.1.19, iotaudit flags devices that send DNS around your router, not only classic hardcoded public DNS (for example 8.8.8.8 or 1.1.1.1, including IPv6). It also reports:

- DNS-over-TLS, when the device talks on port 853
- DNS-over-HTTPS, when it uses a known DoH hostname, or HTTPS to a known public resolver

These show up as findings and in the one-line verdict, next to the grade. The check is local: it looks at the capture, not at a cloud service.

This is a common surprise if you run a local DNS filter. The verdict treats hardcoded public DNS, DoT, and DoH as observed facts.
