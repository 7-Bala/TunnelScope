# 16 — Market landscape: who solves this today, how, and what they miss

**Date:** 2026-09-26 · **Trigger:** owner request after SIH results ("find out what tools are used to bridge
this problem and the closest alternatives, paid too, current and previous") · **Extends:**
`11-EXISTING-SOLUTIONS-DEEP-DIVE.md` (open-source parsers, scanners, SIH competitors) with commercial
products · **Feeds:** the product roadmap in `TODO.md` (T-109 onward).

**Method.** Web research on 2026-09-26, vendor documentation preferred over marketing and third-party
pages. Where the vendor's own page did not state something, it is marked `[UNK]`, never assumed.
Tags: `[FACT]` stated in the vendor's own docs · `[3P]` third-party source only · `[UNK]` not stated.

**Context.** A judge said existing tools already do this: one finds the vulnerability, one patches it,
and bundling them is not new. The owner was unsure of the product names. This file maps the whole field.

---

## 1. Headline

**No single product does what TunnelScope does, but every piece of it exists somewhere.** An analyst
today combines a packet viewer (Wireshark, Arkime, Corelight), a config auditor (Nipper, only with the
device's config) and a traffic-classification engine (Rohde & Schwarz, Vehere). The unserved gap:
**judging IPsec cryptography from traffic, on any vendor's tunnel, including post-quantum downgrade.**
Every passive crypto-inventory product documents TLS/SSH only; every IPsec checker needs the config or
admin access.

## 2. Closest alternative — Titania Nipper (paid)

- `[FACT]` Deterministic, configuration-based assessment through "a virtual device model"; pass/fail
  with evidence against DISA STIGs including VPN; CAT I/II/III severity; remediation steps, not applied
  automatically. Runs fully offline, exports no telemetry. Over 100 defence, government and
  critical-infrastructure organisations; used by U.S. military teams for over a decade.
- `[FACT]` 15 vendors: Cisco, Aruba, Check Point, Palo Alto, Dell, Juniper, Sophos, Huawei, Fortinet, F5,
  Arista, Brocade, Extreme, SonicWall, WatchGuard.
- **Misses:** needs the config file (owner-only); never sees traffic, so cannot see what was actually
  negotiated, a PQ downgrade, rekey/PFS behaviour, or change over time.

## 3. Passive cryptographic-inventory probes (paid) — TunnelScope's real market

| Product | Method | IPsec? |
|---|---|---|
| SandboxAQ AQtive Guard | Live sensor `yanadump` or PCAP upload; compact JSONL | `[FACT]` TLS and SSH handshakes only |
| Keyfactor CipherInsights (ex-Quantum Xchange, acquired May 2025) | Passive appliance on SPAN/TAP/packet broker | `[FACT]` docs describe TLS; IPsec `[UNK]` |
| CryptoNext COMPASS | Passive probe, "100+ IT and OT protocols", CBOM | `[3P]` "VPN" in a third-party list; vendor page does not name IPsec |
| Tychon Quantum Command | Endpoint discovery + passive "ACDI Sniffer" on pcap | `[FACT]` claims "VPN and IPsec configurations"; method `[UNK]` (likely endpoint) |
| IBM Guardium Quantum Safe, ISARA Advance | Code/endpoint/telemetry discovery | not mentioned |

## 4. Network detection and traffic classification (paid)

| Product | What it does | Crypto grading of IPsec? |
|---|---|---|
| Cisco Secure Network Analytics — ETA Cryptographic Audit | TLS version, cipher, key length; PCI/FIPS proof | No — TLS |
| ExtraHop RevealX | TLS weak-cipher and PQ key-exchange audit | No IPsec mentioned |
| Corelight VPN Insights (Zeek) | Detects IPsec/WireGuard/OpenVPN; fingerprints 350+ VPN providers; duration, volume, geolocation | No |
| Rohde & Schwarz ipoque PACE 2 | OEM DPI engine; ML "encrypted traffic intelligence" classifies apps inside encryption incl. VPN protocols | No |
| Vehere (Kolkata) | NDR on encrypted traffic without decryption; serves intelligence agencies, CERTs, national SOCs | No |

## 5. Find-and-patch bundles (the judge's "two tools")

| Bundle | Finds by | Fixes by | Limit |
|---|---|---|---|
| Fortinet FortiGuard → Security Rating + FortiManager | Firmware version vs Fortinet PSIRT advisories | "Create Firmware Template" upgrade | Fortinet Fabric devices only; IPsec crypto checks `[3P]` not included |
| Cisco Catalyst Center Security Advisories | CLI login (`show version`, `show running-config`); version + config match | Upgrade to "Fixed Version" | Cisco inventory only |
| SolarWinds NCM | Nightly NIST CVE feed matched to managed nodes | Config push | `[3P]` users report CVEs shown only for Cisco/Juniper |
| Qualys VMDR + Patch Management | Cloud agent | Automated patching | Servers/endpoints, not VPN gear |

`[FACT]` FortiOS 7.6+ supports hybrid PQ IPsec (RFC 9370, ML-KEM) for its own tunnels, as does PAN-OS
12.1. **Never claim "nobody does PQ IPsec"** — the gap is PQ *assessment* of *any* vendor's tunnel from
traffic.

## 6. Previously used, now gone or fading

- Skybox Security — shut down without notice 2025-02-24, 300 staff; assets sold to Tufin.
- Cisco Vulnerability Management (Kenna) — end-of-sale/end-of-life announced 2026-05-06.
- ike-scan (last release 2013), Zeek IKEv2 plugin (archived 2020), Greenbone IKE checks (IKEv1 version
  lookups) — see 11-EXISTING §3.

## 7. What to copy, and the drawback to bridge (→ TODO roadmap)

| Copy from | Feature | Their drawback we bridge |
|---|---|---|
| Nipper | Offline config audit, 15 vendors, evidence + fix steps | Owner-only, no traffic → **config-vs-wire reconciliation** |
| SandboxAQ / CipherInsights / COMPASS | Passive sensor, CBOM, high-speed compact output | TLS/SSH only → **IPsec (and PQ downgrade) coverage** |
| Corelight VPN Insights | VPN detection + provider/implementation fingerprinting | No crypto grading → fingerprint **and** grade |
| Cisco ETA / ExtraHop | Continuous crypto compliance proof | TLS only, vendor hardware → any capture, IPsec |
| R&S PACE 2 / Vehere | Traffic type inside encryption | Opaque accuracy → honest, measured, abstaining classifier |
| FortiGuard/FortiManager, Catalyst Center, SolarWinds | Find vulnerability → fix | Vendor-locked, needs login, version-only → **any vendor, from traffic, behaviour-based CVE detection, per-vendor fix templates** |

## 8. Sources (fetched 2026-09-26)

- Titania: https://www.titania.com/solutions/compliance/disa-stigs · https://www.titania.com/nipper-infrasight/supported-devices
- SandboxAQ Network Analyzer: https://aqtiveguard.sandboxaq.com/docs/sensors/network-analyzer/
- Keyfactor CipherInsights: https://software.keyfactor.com/Guides/CipherInsights/Current/Content/General/Introduction.htm · acquisition: https://www.keyfactor.com/press-releases/keyfactor-acquires-infosec-global-and-cipherinsights/
- CryptoNext COMPASS: https://www.cryptonext-security.com/en/products-cryptography-discovery-and-inventory/ · third-party list: https://www.encryptionconsulting.com/cryptographic-inventory-vendors/
- Tychon: https://tychon.io/use-cases/quantumreadiness/ · https://tychon.io/products/tychon/pqc-management-module/
- IBM Guardium Quantum Safe: https://www.ibm.com/docs/en/gdsc/3.x?topic=guardium-quantum-safe
- Cisco ETA Crypto Audit: https://www.cisco.com/c/dam/en/us/td/docs/security/stealthwatch/release_notes_for_apps/v3_3_4_ETA_Cryptographic_Audit_Release_Notes_DV_1_0.pdf
- ExtraHop: https://www.extrahop.com/blog/weak-cryptography-search-leads-to-unexpected-discoveries-with-revealx
- Corelight: https://corelight.com/blog/vpns-are-increasingly-common · https://corelight.com/products/analytics/encrypted-traffic
- R&S PACE 2: https://www.ipoque.com/products/deep-packet-inspection-for-software-vendors/dpi-engine-rs-pace-2-for-application-awareness
- Vehere: https://vehere.com/products/network-detection-and-response/
- FortiManager PSIRT: https://docs.fortinet.com/document/fortimanager/7.2.0/new-features/122840/fortimanager-displays-psirt-information-when-a-vulnerability-is-detected-for-managed-devices-7-2-2
- FortiGate Security Rating (third-party walkthrough): https://infosecmonkey.com/fortigate-security-rating-and-vulnerabilities-tab-a-practical-walkthrough/
- FortiOS PQ IPsec: https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/229631/post-quantum-cryptography-for-ipsec-key-exchange
- Cisco Catalyst Center advisories: https://www.cisco.com/c/en/us/td/docs/cloud-systems-management/network-automation-and-management/catalyst-center/2-3-7/user_guide/b_cisco_catalyst_center_user_guide_237/b_cisco_dna_center_ug_2_3_7_chapter_01011.html
- SolarWinds NCM: https://documentation.solarwinds.com/en/success_center/ncm/content/ncm-vulnerability-summary.htm · https://thwack.solarwinds.com/products/network-configuration-manager-ncm/f/forum/92112/ncm-firmware-vulnerability-not-updating
- Qualys: https://www.qualys.com/apps/vmdr-patch
- Skybox: https://www.securityweek.com/skybox-security-shuts-down-lays-off-entire-workforce/
- Kenna EOL: https://www.tenable.com/blog/how-to-prepare-for-cisco-vulnerability-management-formerly-kenna-end-of-life-with-tenable-one
