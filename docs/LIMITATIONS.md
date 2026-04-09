# Limitations

PALISADE is intentionally narrow. Reviewers should read these limitations before evaluating results.

## Detection Limits

- PALISADE only uses unauthenticated, non-intrusive probes in the current release.
- Vendor and product detection may be reliable even when exact versioning is not.
- Version extraction is best-effort and should be treated conservatively.
- A finding does not prove exploitability. It indicates likely exposure or prioritization relevance based on available evidence.

## Coverage Limits

Current vendor support is limited to:

- SonicWall
- Fortinet
- F5
- Cisco
- Palo Alto
- Ivanti
- Citrix
- pfSense
- OPNsense

Unsupported devices may be missed entirely or classified as unknown.

## Environment Limits

- PALISADE is not a passive OT monitoring platform.
- PALISADE does not authenticate to devices in the current release.
- PALISADE does not validate exploits or perform intrusive verification.
- PALISADE is not intended to replace engineering review, vendor guidance, or penetration testing.

## KEV Source Limits

- CISA KEV remains the baseline public source.
- Supplemental sources may expand coverage, but they are not equivalent to CISA KEV.
- `strict` mode and `expanded` mode are intentionally different risk views.

## Identity And Diff Limits

- Asset identity is stronger than raw IP/port-only matching, but it is not a full CMDB or asset-correlation system.
- Cross-scan identity remains most reliable when a device remains at the same network location with similar fingerprint evidence.
- Device moves, NAT changes, or materially different response surfaces may still appear as new assets.

## Validation Limits

- Current validation is strong at the fixture and replay-lab level.
- Current validation is weaker on live-appliance coverage and broad field diversity.
- Wide-release confidence should not be claimed until more real-world validation is complete.

## Recommended Use

PALISADE is best used for:

- edge exposure triage
- KEV-informed prioritization
- lightweight operator evidence and reporting

It is not best used for:

- authoritative full-network inventory
- guaranteed version confirmation
- exploitability determination
- internet-scale discovery
