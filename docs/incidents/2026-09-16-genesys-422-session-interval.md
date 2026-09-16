# Incident 2026-09-16 — Outbound calls rejected with 422 Session Interval Too Small

| | |
|---|---|
| **Date** | 2026-09-16 |
| **Server** | sip.nixi.tel — NIXI SBC |
| **Severity** | High (outbound calls through the PSTN trunk failing) |
| **Status** | Resolved (fix deployed 18:44 UTC, commit `9757058`) |

## Summary

A CPaaS customer (drachtio/jambonz stack) reported that every outbound
call through the Genesys-based PSTN trunk (`nixi-trunk-out`) was answered
`422 Session Interval Too Small / Min-SE: 14400`, although their INVITE
carried no session-timer headers at all. Registration and inbound calls
were unaffected.

The 422 came from the upstream operator, which enforces a Min-SE floor of
14400 s (4 h) on that trunk. The SBC, acting as UAC on the trunk leg,
offered `Session-Expires: 1800` and had no handling for a 422: it relayed
the operator's rejection to the customer and terminated the call instead of
re-sending the INVITE with the demanded value (RFC 4028 §7.4).

## Root cause

1. **Too-small offer on the trunk leg.** With `[security]
   session_timer_enabled = true`, the SBC stamped every trunk-leg INVITE with
   `Session-Expires: 1800 / Min-SE: 90` (the configured defaults). The
   operator's floor is 14400.
2. **No 422 handling.** `handle_response` had arms for 1xx, 2xx, 407 and a
   catch-all; a 422 was treated like any other 4xx: relayed to the caller,
   call torn down. RFC 4028 §7.4 expects the UAC to retry once with
   `Session-Expires ≥ Min-SE`.
3. **Additive header injection.** The customer's own retry with
   `Min-SE: 14400` reached the operator as *two* Min-SE headers plus the
   SBC's `Session-Expires: 1800`, so it was rejected again. Injection must
   replace, never append.

Contributing, found during the fix and corrected in the same change:

- The SBC never ACKed non-2xx final responses on the trunk leg, so UDP
  trunks retransmitted 407/422/486/487 for 32 s; a retransmitted 407 could
  tear down an already-authenticated call.
- Responses were attributed to a call by Call-ID only: after a failover, the
  first trunk's late 487 or its 200-to-CANCEL still reached the live call.
- CSeq was not mapped between legs after a retry (ACK/CANCEL toward the
  trunk, responses toward the caller); the relayed CANCEL never carried the
  INVITE's Via branch.
- `terminate_call` did not release the media session (RTP port leak on every
  error relay); a 481/408 to the SBC's own refresh re-INVITE tore down or,
  after the first fix, would have zombie-refreshed the call.

## Timeline (2026-09-16, UTC)

- **~13:43 / 13:45** — Customer's two test calls fail with 422; report with
  traces received.
- **16:00–17:00** — Root cause located in `invite_handler.rs` /
  `response_handler.rs`; fix designed and adversarially reviewed.
- **17:22** — Customer re-tests: same 422 (fix not deployed yet).
- **17:12** — Backups taken on the server (binary, config, sources).
- **18:11** — Release build started on the server (33 min on 2 vCPU).
- **18:44:36** — `systemctl stop sbc` (0 active calls) → new binary →
  start. `[security] session_expires` raised from 1800 to 14400.
- **18:44:42** — Trunk OPTIONS health check answered 200; **18:47** customer
  account re-registered. Smoke test 17/17 OK.

## Impact

Every outbound INVITE through `nixi-trunk-out` was rejected while the
operator enforced the 14400 s floor (all outbound PSTN calls of the affected
accounts). No inbound or registration impact, no data exposure.

## Remediation applied (commit `9757058`)

1. **RFC 4028 §7.4 retry.** On a trunk 422 carrying Min-SE, the SBC ACKs it
   and re-sends the INVITE once per trunk attempt with Session-Expires and
   Min-SE raised to the operator's floor, as a new transaction (fresh branch,
   CSeq+1). The caller only sees the 422 when a retry is impossible (timers
   off, missing/bogus Min-SE, budget exhausted).
2. **Replace semantics.** Session-timer headers are replaced on the outbound
   trunk leg (gate: `trunk_id`), never appended to the caller's.
3. **Trunk-leg transaction layer.** Every INVITE attempt (initial, 407/422
   retry, failover) is recorded with its Via branch; responses are attributed
   to the attempt they belong to; every non-2xx final is ACKed; CANCEL/ACK
   reuse the attempt's branch/CSeq; relayed responses carry the caller's own
   CSeq; media is released on every teardown path; a lost dialog (481/408
   to a refresh) is torn down with a BYE to the caller.
4. **Operations.** `session_expires = 14400` in production (the trunk's
   floor), so the first INVITE is accepted without a round trip; the
   `[security]` session-timer values are now applied on SIGHUP. New metric
   `sbc_session_timer_422_retries_total`, Grafana tile and alert
   `SBCSessionTimer422Retries` (a non-zero rate means a trunk's floor is
   above the configured value).

Tests: 505 (was 486), including transaction-level tests that drive the
response handler over channels (422 → retry → budget, retransmitted 422,
stale 2xx, refresh 500/481, stray final after teardown).

## Follow-up actions

- [ ] Ask the customer to confirm outbound calls; watch
  `sbc_session_timer_422_retries_total` (should stay flat with 14400
  configured).
- [ ] Per-trunk `session_expires` / `min_se` overrides (store + API) if a
  second trunk needs a different floor.
- [ ] Rewrite `Session-Expires` / `Require: timer` toward the caller in the
  200 OK (RFC 4028 §9: never larger than the caller's offer).
- [ ] Honour `refresher=uas`; wire `security.call_setup_timeout` (parsed
  but never read).
- [ ] Reader task for outbound TCP trunk connections (responses on
  SBC-initiated TCP connections are never read; UDP/TLS unaffected).

## Lessons

- A B2BUA that injects a negotiation header on a leg must own that
  negotiation end to end: replace the other party's headers, handle the
  rejection codes the RFC defines, and never leak the far end's rejection
  of *our* offer to a party that did not make it.
- Every SBC-originated transaction needs its own identity (branch/CSeq) so
  late or retransmitted answers can be attributed and ACKed; "match by
  Call-ID" is not enough once retries and failover exist.
- Keep the operator's known floors in configuration (`session_expires`)
  and alert on the retry counter, so a trunk-side change shows up in
  monitoring instead of in a customer ticket.
