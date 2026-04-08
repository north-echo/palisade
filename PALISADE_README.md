# PALISADE

**Practical Audit Library for Industrial Security, Asset Discovery, and Edge Defense**

PALISADE is a free, open-source security toolkit for small and mid-size utilities, municipal systems, and critical infrastructure operators who don't have dedicated OT security teams or budgets for commercial platforms.

Phase 1 focuses on a single capability: **unauthenticated edge-device exposure triage**. PALISADE identifies likely internet-facing or management-edge appliances, extracts whatever product/version evidence can be gathered safely, and highlights potentially relevant Known Exploited Vulnerabilities (KEVs) for operator review.

PALISADE is designed for the gap between "we know this is a problem" and "we can afford an OT security platform." It turns public vulnerability intelligence and lightweight fingerprinting into a concrete, operator-usable action list.

## Why PALISADE Exists

Most OT security offerings assume one of two environments:

- A mature program with budget for commercial monitoring and asset visibility
- A security team with time to translate threat intelligence into environment-specific action

Many utilities and municipal operators have neither. They still need a way to answer basic questions:

- What edge devices are we exposing?
- Which of them are likely tied to known exploited vulnerabilities?
- What should we fix first?
- How do we document that work for leadership, regulators, or auditors?

PALISADE is intended to answer those questions with local tooling, plain-language output, and a small operational footprint.

## The Problem

Thousands of water utilities, electric co-ops, transit agencies, and municipal systems run critical infrastructure with:

- No visibility into what's on their OT networks
- No budget for commercial OT security platforms (Dragos, Claroty, Nozomi)
- One IT person who also manages email, phones, and printers
- Edge devices (firewalls, VPN appliances, remote access gateways) exposed to the internet with known-exploited vulnerabilities
- No incident response plan for OT environments
- Compliance requirements (CISA CPGs, AWIA, state regulations) with no practical path to meet them

Meanwhile, adversaries like Volt Typhoon are actively targeting these exact organizations — not through exotic zero-days on PLCs, but through unpatched edge devices and basic network hygiene failures.

## What PALISADE Does

PALISADE provides **executable security tools and guidance** — not PDFs full of recommendations, but scripts, configs, checklists, and templates that a single IT/OT operator can pick up and use immediately.

For the first release, that means producing a defensible, evidence-backed shortlist of likely exposed edge devices and likely relevant KEVs. It does **not** promise perfect product identification or authoritative exploitability validation from unauthenticated probes alone.

## Who It's For

PALISADE is built for operators who need practical help more than platform engineering:

- Small and mid-size utilities
- Municipal IT/OT teams
- Electric co-ops and public works environments
- Security-conscious operators working without a dedicated OT security product budget

## What It Is Not

PALISADE is not:

- A passive full-network monitoring platform
- A replacement for a professional penetration test or architecture review
- An exploit framework or offensive security tool
- A guarantee of exploitability, patch status, or regulatory compliance

## Why It May Be Useful

PALISADE is most useful if you need something that is:

- Narrow enough to deploy quickly
- Opinionated enough to prioritize action
- Local-first and usable in constrained environments
- Written for operators instead of product buyers or threat researchers

### Modules

| Module | Description | Status |
|--------|-------------|--------|
| **`edge-audit`** | Best-effort exposure triage for edge devices (SonicWall, Fortinet, F5, Cisco, Palo Alto, Ivanti, Citrix) using non-intrusive fingerprinting plus curated KEV signature matching | 🔨 In Progress |
| **`net-discover`** | Lightweight OT network asset discovery and traffic mapping using commodity hardware | 📋 Planned |
| **`harden`** | Prioritized, environment-specific hardening checklists for common utility OT configurations | 📋 Planned |
| **`ir-runbooks`** | Fill-in-the-blank incident response runbooks for OT-specific scenarios | 📋 Planned |

Every tool and checklist maps to [CISA Cross-Sector Cybersecurity Performance Goals (CPGs)](https://www.cisa.gov/cross-sector-cybersecurity-performance-goals) so operators can demonstrate compliance with concrete evidence.

## Current Status

PALISADE is pre-release. Phase 1 is limited to `edge-audit`, with future modules planned but not yet implemented.

## Design Principles

- **Runs on what you have.** No agents, no cloud dependencies, no license keys. A Linux box (or WSL), Python, and network access.
- **Opinionated over flexible.** PALISADE tells you what to do, not what you could do. Prioritized by real-world threat data (CISA KEV, known campaign TTPs).
- **Written for operators, not security engineers.** Plain language. No jargon without explanation. Every recommendation includes *why* and *how*.
- **Offline-capable.** Core functionality works in air-gapped or limited-connectivity environments after an initial KEV/signature sync. Data can be updated via USB transfer.
- **Evidence-generating.** Every check produces output that can be saved as compliance evidence or shared with regulators.

## Quick Start

### Prerequisites

- Python 3.9+
- Network access to target devices (for edge-audit)
- `nmap` (optional, for net-discover module)

### Installation

```bash
git clone https://github.com/north-echo/palisade.git
cd palisade
pip install -e .
```

### Run Edge Audit

```bash
# Update KEV database (requires internet, one-time or periodic)
palisade kev-sync

# Scan a single device
palisade edge-audit --target 192.168.1.1 --vendor sonicwall

# Scan a subnet for known edge devices
palisade edge-audit --target 192.168.1.0/24 --discover

# Generate a saved report from the latest scan
palisade report --latest --format html --output palisade-report.html
```

## Edge Audit Module

The `edge-audit` module performs **best-effort, non-intrusive** fingerprinting of edge devices and compares the resulting product/version evidence against a curated signature set derived from CISA's Known Exploited Vulnerabilities (KEV) catalog.

This is deliberately not a full attack-surface management platform. The design goal is a smaller and more practical outcome: identify likely exposed edge infrastructure, tie it to current KEV-driven risk, and produce output an operator can act on immediately.

### Supported Vendors

| Vendor | Product Families | Detection Method |
|--------|-----------------|------------------|
| SonicWall | SMA, NSA, TZ, Gen 7 | TLS cert, headers, body patterns, banner |
| Fortinet | FortiGate, FortiOS | TLS cert, headers, body patterns, banner |
| F5 | BIG-IP, BIG-IQ | TLS cert, headers, body patterns, banner |
| Cisco | ASA, FTD | TLS cert, headers, body patterns, banner |
| Palo Alto | PAN-OS, GlobalProtect | TLS cert, headers, body patterns, banner |
| Ivanti | Connect Secure, Policy Secure | TLS cert, headers, body patterns, banner |
| Citrix | NetScaler ADC, Gateway | TLS cert, headers, body patterns, banner |

### How It Works

1. **Device Discovery** — Identifies edge devices on the target network via service fingerprinting (banner grab, TLS certificate inspection, HTTP response headers).
2. **Evidence Extraction** — Collects externally observable product and version evidence through non-intrusive methods (no authentication required, no exploitation).
3. **Signature Matching** — Compares identified device evidence against a local signature set derived from KEV plus vendor advisories to flag likely exposures.
4. **CPG Mapping** — Maps findings to relevant CISA CPGs (primarily CPG `1.A`: Mitigate Known Exploited Vulnerabilities).
5. **Report Generation** — Produces human-readable and machine-parseable (JSON) reports with remediation guidance.

### Important Notes

- **Non-intrusive only.** PALISADE never attempts exploitation, sends malformed packets, or performs actions that could disrupt device operation.
- **No authentication required.** All checks use externally observable information (banners, headers, certificates, version strings).
- **Best-effort identification.** Some platforms expose limited unauthenticated version data. PALISADE may identify vendor/product confidently while reporting version confidence as medium or low.
- **False positives possible.** Signature-based matching cannot confirm exploitability — it identifies *potential* exposure that warrants investigation.

## CISA CPG Mapping

Each PALISADE module maps to specific CPGs:

| CPG | Description | PALISADE Module |
|-----|-------------|-----------------|
| 1.A | Mitigate Known Exploited Vulnerabilities | `edge-audit` |
| 1.E | Network Segmentation | `net-discover`, `harden` |
| 2.A | Changing Default Passwords | `harden` |
| 2.B | Minimum Password Strength | `harden` |
| 2.F | Network Monitoring & Defense | `net-discover` |
| 3.A | Organizational Cybersecurity Leadership | `ir-runbooks` |
| 5.A | Assets in Inventory | `net-discover` |
| 7.A | Incident Reporting | `ir-runbooks` |
| 7.B | Incident Response (IR) Plan | `ir-runbooks` |

## Project Structure

```
palisade/
├── README.md
├── LICENSE                    # Apache 2.0
├── pyproject.toml
├── src/
│   └── palisade/
│       ├── __init__.py
│       ├── cli.py             # Click CLI entrypoint
│       ├── core/
│       │   ├── db.py          # SQLite schema, connections, migrations
│       │   ├── kev.py         # KEV database sync and query
│       │   ├── device.py      # Device fingerprinting engine
│       │   ├── version.py     # Vendor-specific version comparison
│       │   ├── report.py      # Report generation (text, JSON, HTML)
│       │   └── cpg.py         # CPG mapping definitions
│       ├── edge_audit/
│       │   ├── __init__.py
│       │   ├── scanner.py     # Main audit orchestrator
│       │   ├── vendors/
│       │   │   ├── sonicwall.py
│       │   │   ├── fortinet.py
│       │   │   ├── f5.py
│       │   │   ├── cisco.py
│       │   │   ├── paloalto.py
│       │   │   └── ivanti.py
│       │   └── signatures/    # Version-to-CVE mapping data
│       │       └── kev_edge.json
│       ├── net_discover/      # Future: asset discovery
│       ├── harden/            # Future: hardening checklists
│       └── ir_runbooks/       # Future: IR templates
├── tests/
│   ├── test_kev.py
│   ├── test_device.py
│   ├── test_version.py
│   ├── test_scanner.py
│   ├── test_report.py
│   └── fixtures/              # Sample banners, responses
├── data/
│   └── palisade.db            # Local SQLite cache and scan history
└── docs/
    ├── GETTING_STARTED.md     # Operator-focused quickstart
    ├── EDGE_AUDIT.md          # Detailed edge-audit docs
    ├── CPG_MAPPING.md         # Full CPG crosswalk
    └── SIGNATURES.md          # Signature format and contribution guide
```

## Contributing

PALISADE welcomes contributions, especially from:

- **Utility operators** — Tell us what's actually useful and what's not. Open an issue or start a discussion.
- **Security researchers** — Add vendor detection modules, improve fingerprinting accuracy, contribute KEV-to-version mappings.
- **Technical writers** — Help make documentation clearer for non-specialist audiences.

All contributions require `Signed-off-by` (DCO). See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## Disclaimer

PALISADE is provided as-is for defensive security assessment purposes. It is **not** a substitute for professional security assessment, and its results do not guarantee security or compliance. Operators should validate findings and consult qualified professionals for critical security decisions. Always obtain proper authorization before scanning networks or devices.

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.

## Acknowledgments

- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — Vulnerability prioritization data
- [CISA CPGs](https://www.cisa.gov/cross-sector-cybersecurity-performance-goals) — Compliance mapping framework
- [WaterISAC](https://www.waterisac.org/) — Water sector threat intelligence

---

**PALISADE is a [North Echo Security Research](https://github.com/north-echo) project.**
