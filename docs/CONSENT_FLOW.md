# Consent flow — how the legal gate is enforced in code

> "Enforce the legal/ethical gating in code, not just in documentation."
> This document maps each requirement to a concrete check.

## 1. Onboarding (one time, versioned)

`OnboardingScreen` shows the full legal notice and a single switch. The Continue
button is disabled until it is checked. `OnboardingViewModel.accept()` writes
`legalNoticeAccepted=true`, `noticeVersion=CURRENT_NOTICE_VERSION` and
`onboardingDone=true` to DataStore.

`ConsentGate` starts with `ConsentPolicy()` — **legal notice not accepted, Safe
Mode ON** — and `SentinelNetApp` synchronises it from DataStore. If the notice
changes, `CURRENT_NOTICE_VERSION` is bumped and every action is denied with
`STALE_LEGAL_NOTICE` until the user re-consents.

## 2. Per-action consent (every invasive action)

`Capability` is the single registry defining what "invasive" means. Each
capability declares: id, `invasive`, `requiresBiometric`, notice reference.

| Step | Where | Check |
|---|---|---|
| 1 | UI | user taps an action → `ConsentRequests.newNonce()` |
| 2 | `ConsentDialog` | four mandatory acknowledgements, scope selector, public-target warning + justification, biometric prompt |
| 3 | UI | builds `ConsentDecision` with the **same nonce** and `grantedAtMillis` |
| 4 | ViewModel | builds `ConsentRequest(capability, nonce, target, actor, sessionId, decision)` |
| 5 | Engine | calls `ConsentGate.guard(request) { ... }` **inside the cold flow**, so collection == action |
| 6 | Gate | 12 sequential checks (below) |
| 7 | Gate | writes an `AuditEvent` **before** running the action |
| 8 | Gate | returns `ConsentResult.Allowed(value)` or `Denied(reason, detail)` |

### Gate checks, in order

1. `legalNoticeAccepted` — else `LEGAL_NOTICE_NOT_ACCEPTED`
2. `acceptedNoticeVersion >= CURRENT_NOTICE_VERSION` — else `STALE_LEGAL_NOTICE`
3. `!(capability.invasive && safeMode)` — else `SAFE_MODE_BLOCKS_INVASIVE`
4. decision present — else `NO_DECISION`
5. `decision.isWellFormed && acknowledgedAuthorizedUse` — else `MALFORMED_DECISION`
6. `decision.capability == request.capability` — else `CAPABILITY_MISMATCH`
7. `decision.nonce == request.nonce` — else `NONCE_MISMATCH`
8. `decision.target == request.target` — else `TARGET_MISMATCH`
9. `!decision.isExpired(now, 10min)` — else `CONSENT_EXPIRED`
10. `!capability.requiresBiometric || decision.biometricVerified` — else `BIOMETRIC_REQUIRED`
11. `TargetValidator.validate(...)` for invasive actions — else `TARGET_OUT_OF_SCOPE` / `PUBLIC_TARGET_NOT_ACKNOWLEDGED`
12. `RateLimiter.tryAcquire(capability, maxInvasiveActionsPerMinute)` — else `RATE_LIMITED`
13. `markNonceUsed(nonce)` — else `NONCE_ALREADY_USED` (single-use replay protection)

A throwing action is caught, logged as `ERROR`, and returned as `ACTION_FAILED`.

## 3. Target scope

`TargetValidator` allows RFC 1918 / loopback / link-local / CGNAT / TEST-NET /
IPv6 ULA+link-local by default. It **always** rejects broadcast and multicast.
A public target requires (a) `publicTargetAcknowledged`, (b) a justification of
at least 8 characters, and (c) a scope of `OWN_NETWORK` or
`AUTHORIZED_ENGAGEMENT` — never `LOCAL_LAB`. The justification is stored in the
audit record.

## 4. Passive operations

`ConsentGate.observe()` is for passive capabilities (Wi-Fi scan, audit). It
still requires the legal notice, still writes an `OBSERVED` audit event, and
**refuses** to run invasive capabilities.

## 5. Audit log

`AuditLog` is append-only. `RoomAuditLog` persists to SQLCipher; tests use
`InMemoryAuditLog`. Each event has a monotonic sequence, UTC timestamp,
pseudonymous actor, capability, target, decision (`ALLOWED`/`DENIED`/
`OBSERVED`/`ERROR`), reason and session id. Denials are as important as
allowances: they prove the gate is active.

## 6. Automated enforcement

- `scripts/verify_project.py` checks the gate source contains every check,
  all invasive capability ids, and that no Kotlin file calls forbidden
  identifier APIs or active Wi-Fi attack primitives.
- `.semgrep.yml` fails CI on an invasive entry point called outside a guard and
  on IMEI/IMSI/serial collection.
- The conformance suite has 19 tests for the gate, including replay, expiry,
  safe mode, public targets, rate limiting and denial auditing.
