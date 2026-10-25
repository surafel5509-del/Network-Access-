# ADR-0002 — ConsentGate is the only path to invasive actions

**Status:** Accepted · **Date:** 2026-10-25

## Context
The spec requires legal gating "in code, not just documentation", per-action
consent, an audit log, Safe Mode, and root/Shizuku requirement checks. The
tempting approach is a `@RequiresConsent` annotation checked in the UI — but
annotations get forgotten and can be bypassed from another screen.

## Decision
- `Capability` is the single registry defining `invasive` and
  `requiresBiometric`.
- Every engine entry point takes a `ConsentRequest` and calls
  `ConsentGate.guard()` **inside its cold flow**, so collection == action.
- The gate returns a sealed `ConsentResult` (no exception-based bypass) and has
  **no** overload that skips checks.
- Decisions are single-use (nonce consumed on allowance), target-bound,
  capability-bound, 10-minute TTL, and rate-limited.
- Both allowed and denied attempts write an audit event before any work starts.
- A Semgrep rule and `scripts/verify_project.py` fail CI on bypasses.

## Consequences
- ✅ Denials are as auditable as allowances.
- ✅ A replayed decision cannot authorise a second scan.
- ❌ Slightly more plumbing: the UI must mint a nonce and pass the decision
  through the ViewModel. Documented in CONSENT_FLOW.md.
