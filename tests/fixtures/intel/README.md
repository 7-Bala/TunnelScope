Trimmed real API responses recorded 2026-09-27 for `tests/test_intel.py` (so tests never use the network):
- `nvd_strongswan.json`: NVD CVE API 2.0, keywordSearch=strongswan, 3 of 55 results kept (one lists
  strongSwan's CPE, CVE-2026-25998 only mentions it: strongMan). "This product uses data from the NVD API but is
  not endorsed or certified by the NVD."
- `euvd_strongswan.json`: ENISA EUVD search vendor=strongswan, 1 item kept (CVE-2026-78135, the pre-auth CREATE_CHILD_SA bypass TunnelScope detects).
- `cisa_kev.json`: CISA Known Exploited Vulnerabilities catalog (CC0), 3 entries kept (2 MikroTik, 1 Fortinet).
