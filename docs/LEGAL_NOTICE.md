# Legal Notice — Authorized Use Only

**Last updated: 2026-10-25 · Version 1** (`ConsentPolicy.CURRENT_NOTICE_VERSION = 1`)

SentinelNet is a **defensive** network analysis and security auditing tool. It is
provided for:

- security testing of networks and devices you own,
- authorised penetration tests with **written permission** from the owner,
- education and research on isolated lab equipment,
- diagnosing your own Wi-Fi, LAN and device configuration.

> **Scanning networks or devices without the owner's permission may be illegal
> in your jurisdiction.** Laws such as the Computer Fraud and Abuse Act (US),
> the Computer Misuse Act (UK), the Network and Information Security Directive
> (EU) and equivalent national laws can impose criminal and civil penalties for
> unauthorised access, interception or interference. You are solely responsible
> for determining what is lawful where you are.

## What SentinelNet does NOT do

- It does **not** crack, bypass or recover Wi-Fi passwords from networks around
  you. It cannot put the radio into monitor mode, inject frames or send
  deauthentication packets.
- It does **not** exploit vulnerabilities. CVE "hints" are passive matches on
  version strings and link to public NVD pages.
- It does **not** intercept TLS traffic by default. The MITM proxy is not part
  of this build and, if added, will require a separate consent flow and a
  user-installed CA certificate.
- It does **not** contain a bundled password dictionary, cloud cracking, or any
  capability to attack a scanned SSID/BSSID.
- It does **not** collect IMSI, IMEI, serial numbers, contacts, SMS or call logs.

## The Security Lab

The offline WPA Security Lab implements IEEE 802.11i key derivation for
educational purposes. It only processes a handshake that **you already
possess** from a network you are authorised to test, or a synthetic handshake
generated on the device. It is deliberately capped (200 000 candidates,
30 seconds, single-threaded) so it can never become a high-throughput cracker.
See [SECURITY_LAB.md](SECURITY_LAB.md).

## Your obligations

By using an invasive feature you confirm, on each action, that:

1. You own the target network/device, or have written permission to test it.
2. You understand that unauthorised scanning may be illegal and you accept full
   responsibility.
3. You understand every action is recorded in a local, exportable audit log.
4. You understand this app performs no exploitation and only reports risks.

The audit log is your evidence of authorised testing. Export it and keep it with
your engagement paperwork. SentinelNet's author cannot verify your authority,
and provides no warranty (see [LICENSE](../LICENSE)).

## Root, Shizuku and elevated capabilities

Features that require root or Shizuku are not part of this build. When added,
they will be clearly labelled and will always warn that rooting a device voids
warranties, weakens the security model and may violate your carrier/employer
policy. SentinelNet never asks for root silently.

## Compliance

This notice, the [privacy policy](PRIVACY_POLICY.md), the [consent flow](CONSENT_FLOW.md)
and the [Play policy notes](PLAY_POLICY.md) are part of the app's onboarding and
cannot be skipped. Safe Mode is ON by default and disables every invasive
feature.
