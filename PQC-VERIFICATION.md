# PQC Verification Record — QARKE

This document records exactly what was tested, against what, and when.
Nothing here is claimed beyond what the test output shows.

## 1. ML-KEM (FIPS 203) — 2026-09-24

Source: NIST ACVP vectors (`usnistgov/ACVP-Server`, ML-KEM test groups).

| Parameter set | KeyGen | Encap | Decap |
|---|---|---|---|
| ML-KEM-768 | 25/25 | 25/25 | 10/10 |
| ML-KEM-1024 | 25/25 | 25/25 | 10/10 |

Round-trip and tamper-rejection also verified (mutated ciphertexts/keys rejected).

## 2. ML-DSA-65 (FIPS 204) — 2026-09-28

Source: NIST ACVP vectors (`usnistgov/ACVP-Server`, `ML-DSA-sigVer-FIPS204`),
covering **all 4 FIPS 204 parameter modes**.

| Check | Result |
|---|---|
| Signature verification, all modes | 60/60 PASS |

Wired into the implementation as three entry points matching the FIPS 204
interfaces: `verify_prehash()`, `verify_mu()`, `verify_internal()`.

**Notable catch during verification:** test group `tgId 10` exercises the
*internal* signing interface. An external-only verifier correctly rejects these
vectors — the implementation handles this by routing them to `verify_internal()`.
This is correct behavior, not a failure, and it is documented here so nobody
"fixes" it later.

## 3. Full tunnel self-test — 2026-09-28

28-check suite run against the KAT build below, including 12 embedded ACVP
vectors as check #28.

**Result: 28/28 PASS.**

## 4. Build fingerprints

**Current KAT build** (`qarke_tunnel_v15.py`):

- Size: 372,731 bytes · 4,296 lines
- SHA-256: `ac35d65858089fe1942b2869a1dc2d97e42687f8a0850e222486a59cf135f13a`
- Handshake version: `HS_VERSION = 4`
- Verified: `sha256sum` match on 2026-10-06

**Prior build** (phone-tested 2026-09-28):

- Size: 150,132 bytes
- SHA-256: `f1742211bb2df5c4e5fb19c3de6b057687c24790f58984f1d2a29b7a7591844b`
- On-device self-test (Termux, Android): **27/27 PASS**

## 5. What's verified vs. what's pending

| Item | Status |
|---|---|
| ML-KEM-768/1024 vs NIST ACVP vectors | ✅ Verified 2026-09-24 |
| ML-DSA-65 vs NIST ACVP vectors (all 4 modes) | ✅ Verified 2026-09-28 |
| Full self-test, KAT build, local | ✅ 28/28 PASS 2026-09-28 |
| Self-test, prior build, on-device (Termux) | ✅ 27/27 PASS 2026-09-28 |
| Self-test, KAT build, on-device (Termux) | ⏳ Build on device, output pending |
| Third-party audit | ⏳ Not done |
| ML-DSA identity auth (replaces Ed25519) | ⏳ Tracked, not implemented |

## 6. How to reproduce

```bash
sha256sum qarke_tunnel_v15.py
# expect: ac35d65858089fe1942b2869a1dc2d97e42687f8a0850e222486a59cf135f13a

python3 qarke_tunnel_v15.py --self-test
# expect: 28/28 PASS
```

No dependencies beyond Python 3.10+ stdlib.

---

*Record maintained by Marc Phillip Braden. Entries are dated; corrections amend
rather than overwrite.*
