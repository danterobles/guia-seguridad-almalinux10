# AlmaLinux 10 Server Security Guide

A comprehensive, production-ready guide for building a **hardened AlmaLinux 10 server** from scratch — capable of hosting **Laravel (PHP 8.5 / Filament)** and **Node.js (LTS 24)** applications with enterprise-grade security.

---

## What this guide covers

This runbook walks you through every layer of server security and configuration:

- **System hardening** — SELinux enforcing mode, minimal attack surface, version hiding
- **Secure SSH** — non-standard port, key-only authentication, drop-in configuration
- **Firewall** — firewalld with minimal open ports, Fail2Ban integration
- **Web stack** — Apache with HTTP/2, PHP-FPM pools, reverse proxy for Node.js
- **Database** — MySQL 8 bound to localhost with minimum-privilege users
- **In-memory store** — Valkey (Redis drop-in) via Unix socket, no TCP exposure
- **SSL/TLS** — Let's Encrypt with automatic renewal
- **Active defense** — Fail2Ban jails for SSH, Apache, and exploit scanning
- **Bot blocking** — User-Agent and exploit-path filtering at VirtualHost level
- **Form protection** — Cloudflare Turnstile server-side validation + rate limiting
- **Performance** — OPcache, per-app FPM pools, MySQL slow log, HTTP/2 caching
- **Deployment** — Git workflow with SELinux-safe ownership restoration

---

## Available languages

| Language | File |
|---|---|
| 🇬🇧 English | [README_EN.md](README_EN.md) |
| 🇪🇸 Español | [README_ES.md](README_ES.md) |
| 🇧🇷 Português | [README_PT.md](README_PT.md) |
| 🇫🇷 Français | [README_FR.md](README_FR.md) |
| 🇩🇪 Deutsch | [README_DE.md](README_DE.md) |
| 🇨🇳 简体中文 | [README_ZH.md](README_ZH.md) |

---

## Technology stack

| Component | Version | Role |
|---|---|---|
| AlmaLinux | 10 | Base OS (RHEL-compatible) |
| Apache | 2.4 | Web server / reverse proxy (MPM event + HTTP/2) |
| PHP | 8.5 (Remi) | Laravel / Filament runtime (via PHP-FPM) |
| MySQL | 8.4 | Relational database (loopback-only) |
| Valkey | 8 | Cache, sessions, queues (Unix socket, FOSS Redis fork) |
| Node.js | 24 LTS | JavaScript runtime (systemd service, loopback-only) |
| Let's Encrypt | — | Free TLS certificates with auto-renewal |
| firewalld | — | Host firewall (ports 4428, 80, 443 only) |
| SELinux | Enforcing | Mandatory access control |
| Fail2Ban | — | Active IP banning based on log patterns |
| Cloudflare Turnstile | — | Bot-resistant form protection (server-side) |

---

## Security posture at a glance

- SSH on a non-standard port (4428), root login disabled, password auth disabled
- SELinux in Enforcing mode — never permissive, never disabled
- MySQL and Node ports not reachable from outside the server
- Valkey with no TCP port, Unix socket only, password-protected
- HTTP security headers: HSTS, CSP, X-Frame-Options, Referrer-Policy
- Bot scanners blocked at Apache level before reaching PHP
- Fail2Ban monitoring SSH, Apache auth, and exploit scanning simultaneously
- Turnstile + rate limiting + email verification layered on public forms

---

## License

This guide is provided as-is for educational and operational use. Adapt it to your specific environment and security requirements.
