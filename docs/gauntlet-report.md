# Nexus Gateway - Security Gauntlet 3.0 Report

**Date:** 2026-10-17 17:56:08
**Summary:** 8/8 scenarios behaved as designed: 1 legitimate purchase allowed, 7 attack classes stopped.
**Performance:** Gateway decision overhead (100 local runs): p50=82.7ms, p95=106.8ms before network round-trip.

| Test Class | Reason Code | Technical Detail |
|---|---|---|
| Baseline Purchase (Allowed) | `OK` | CAPTURED in sandbox |
| Price Tampering (Blocked) | `DENY_PRICE_TAMPERING` | PayPal was never called |
| Payee Swap (Blocked) | `DENY_PAYEE_MISMATCH` | PayPal was never called |
| Replay Attack (Neutralized) | `REPLAY_HANDLED_SAFELY` | Returns original result cleanly |
| Split Purchase Exhaustion (Blocked) | `DENY_EXCEEDS_BUDGET` | Multiple buys stopped. Breaker active. |
| Poisoned Agent Payload (Blocked) | `DENY_EXCEEDS_PER_TXN` | Blocked by strict limits. |
| Forged Webhook Signature (Blocked) | `HTTP 400` | Signature check failed |
| Concurrency Lock | `RACE_PREVENTED` | Exactly 1 processed, 9 duplicate/already-reserved codes securely |
