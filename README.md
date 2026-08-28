# Qarke

**Quantum-Agile Routing & Key-Enclave**

Qarke is an experimental research prototype exploring quantum-agile networking concepts. It combines multi-hop (onion-style) routing with isolated key-enclave validation and system observability components. The project prioritizes defensive coding practices, cryptographic integrity awareness, and security-first design principles.

> **Motto:** *Lead with Love. Think for Yourself.*

This repository is under active early-stage development. It is **not production-ready** and should be treated as a conceptual and educational codebase.

## Core Concepts

- **Quantum-Agile Cryptography** — Support for post-quantum algorithms (e.g., CRYSTALS-Kyber, NTRU-HRSS, SPHINCS+) in hybrid key-exchange and validation flows.
- **Key-Enclave Validation** — Isolated validation of cryptographic metadata that issues Enclave Validation Tokens (EVTs) only after structural and algorithm compliance checks.
- **Dynamic Hop Routing (QARMR)** — Asynchronous multi-hop packet processing with fixed-size onion packets, hop canonicalization, constant-time comparisons, epoch-based replay protection, soft rate limiting, and connection pooling.
- **Defensive Parsing & Hostile Input Handling** — Strict structural validation, bounds checking, and rejection of malformed, oversized, or replayed packets.
- **System Observability (Aegis)** — Lightweight dashboard for monitoring CPU, RAM, network throughput, VPN/proxy status, with optional Termux notifications.

## Repository Structure

| Component | Description |
|-----------|-------------|
| `qarmrlite.py` / `qarmr_v9_core.py` | Core QARMR multi-hop routing engine |
| `qarke_enclave.py` | Loopback key-enclave validator daemon |
| `qarke_router.py` | Router that queries the enclave and applies FORWARD/DROP decisions |
| `qarke_master.py` / `qarke_validator.py` | Manifest-driven state machine and enclave validation |
| `Aegis.py` / `aegis_dashboard.py` | System metrics dashboard |
| `AGENTS.md` | Detailed contribution and agent operational guidelines |
| `start_nodes.sh` / `stop_nodes.sh` | Helper scripts for node lifecycle |
| `test_*.py` / `test_manifest.json` | Test harnesses and sample configuration |

## Quick Start (Experimental)

**Requirements**
- Python 3.10+
- `psutil` (for Aegis dashboard)

```bash
# Clone the repository
git clone https://github.com/23starchild/Qarke.git
cd Qarke

# Example: Start the enclave validator (loopback)
python qarke_enclave.py

# In another terminal: Run the router simulation
python qarke_router.py

# Run the master validator against the sample manifest
python qarke_master.py

# Launch the system dashboard (optional)
python Aegis.py