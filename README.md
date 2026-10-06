# QARKE — Post-Quantum Secure Tunnel

**Hybrid post-quantum key exchange + signed handshakes, verified against NIST's official test vectors.**

QARKE (Quantum-Agile Routing & Key-Enclave) is a research implementation of a hybrid
classical/post-quantum secure tunnel: every handshake runs X25519 **and** ML-KEM
(FIPS 203) side by side, signs the transcript with ML-DSA (FIPS 204), and transports
data over ChaCha20-Poly1305 with per-epoch rekeying. Built in 90 days, on a phone,
in Termux — and checked against the same vectors NIST publishes for everyone.

> **Motto:** *Lead with Love. Think for Yourself.*

## Verification (the part that matters)

| Primitive | Standard | Vectors | Result | Date |
|---|---|---|---|---|
| ML-KEM-768 keygen / encap / decap | FIPS 203 | NIST ACVP | 25/25 · 25/25 · 10/10 | 2026-09-24 |
| ML-KEM-1024 keygen / encap / decap | FIPS 203 | NIST ACVP | 25/25 · 25/25 · 10/10 | 2026-09-24 |
| ML-DSA-65 signature verification | FIPS 204 | NIST ACVP (`ML-DSA-sigVer-FIPS204`, all 4 modes) | 60/60 | 2026-09-28 |
| Full tunnel self-test (28 checks incl. 12 embedded ACVP vectors) | — | local | 28/28 PASS | 2026-09-28 |
| Prior build, on-device self-test (Termux) | — | local | 27/27 PASS | 2026-09-28 |

Full details, vector sources, and build fingerprints: [`PQC-VERIFICATION.md`](PQC-VERIFICATION.md).

## Architecture

- **Hybrid KEM handshake** — ephemeral X25519 + ML-KEM-768/1024 in the same flight;
  session secret = KDF over both shared secrets bound to a transcript hash.
  No silent downgrade: policy mismatch aborts, never falls back.
- **Signed handshakes** — every handshake signed with ML-DSA-65; `verify_prehash()`,
  `verify_mu()`, and `verify_internal()` entry points, matching the FIPS 204 interfaces.
- **Transport** — ChaCha20-Poly1305 with directional keys (initiator→responder ≠
  responder→initiator), epoch/sequence nonces, replay window, per-epoch rekey.
- **Monitoring doctrine** — dual dissimilar monitors (statistical + signature-based)
  over metadata only, quarantine on agreement, every decision appended to a
  SHA-256-chained audit ledger. Defensive only: detect, alert, quarantine. Never
  counter-attack.
- **Identities** — Ed25519 mutual auth with fingerprint pinning (ML-DSA migration
  tracked as the remaining classical component — stated openly, not hidden).

## Quick start

```bash
git clone https://github.com/23starchild/Qarke.git
cd Qarke
python3 qarke_tunnel_v15.py --self-test   # runs the 28-check suite
```

Requires Python 3.10+ (stdlib only — no dependencies to install).

## Honest limits

- Research prototype. **Not production-ready**, not audited by a third party.
- The newest build's on-device self-test output is pending; the 27/27 phone result
  above belongs to the prior build.
- Identity authentication is still classical Ed25519; the ML-DSA migration is tracked
  but not yet implemented.
- If the endpoint is compromised, no cryptography saves it. Stated plainly.

## Author

Marc Phillip Braden ([@23starchild](https://github.com/23starchild)) — independent
cryptography implementer, Lafayette, Indiana.

Available for post-quantum migration and implementation work. If your team is moving
to FIPS 203/204 and needs someone who has implemented it — not just read the spec —
get in touch.
