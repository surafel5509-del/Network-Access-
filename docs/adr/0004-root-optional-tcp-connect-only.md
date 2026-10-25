# ADR-0004 — No raw sockets or root in the foundation build

**Status:** Accepted · **Date:** 2026-10-25

## Context
SYN/FIN/NULL/XMAS scans, root libpcap capture, iptables/nftables firewall rules
and full traceroute need raw sockets or elevated privileges. Android's public
SDK does not expose `SOCK_RAW` to unprivileged apps; `libsu`/Shizuku are
optional dependencies that many users will not have.

## Decision
- Port scanning uses `java.net.Socket` TCP Connect only (works on every device,
  minSdk 26, no root).
- Capture uses `VpnService` (OS-granted permission) and only routes a synthetic
  lab subnet until transparent forwarding is implemented.
- Traceroute/MTR, SYN scans, iptables firewall and root libpcap capture are
  deferred and their interfaces report `NOT_IMPLEMENTED`.
- `EngineStatus` exposes `ROOT` / `SHIZUKU` / `HARDWARE` requirements so the UI
  explains what is missing rather than failing silently.

## Consequences
- ✅ Graceful degradation; the app runs on unmodified devices.
- ✅ Smaller Play policy surface.
- ❌ Higher false-negative rate for filtered ports; documented in the UI.
- Note: capture and firewall cannot both own the VPN — a shared VPN session
  manager is required in Phase 3/4.
