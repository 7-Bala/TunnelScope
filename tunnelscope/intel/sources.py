"""T-130 / DEC-040: the threat-intelligence sources TunnelScope may use, with who owns them and on what terms.
Only sources whose terms allow use in a product are listed; `licence_verified` records whether the terms were read
at the source (2026-09-27). A source not verified is used for local lookups only and never put in a bundle meant
for redistribution."""

SOURCES = {
    "nvd": {
        "name": "National Vulnerability Database (CVE API 2.0)", "owner": "NIST (US government)", "government": True,
        "api": "https://services.nvd.nist.gov/rest/json/cves/2.0", "key_env": "TUNNELSCOPE_NVD_API_KEY",
        "key_header": "apiKey", "rate_limit": "5 requests / 30 s without a key, 50 with one (NVD documentation)",
        "licence": "US Government work (NIST). Terms page is JavaScript-rendered and could not be read 2026-09-27",
        "licence_verified": False, "redistributable": False,
        "attribution": "This product uses data from the NVD API but is not endorsed or certified by the NVD.",
    },
    "cisa_kev": {
        "name": "Known Exploited Vulnerabilities catalog", "owner": "CISA (US Department of Homeland Security)",
        "government": True, "api": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "key_env": None, "licence": "CC0 1.0 (cisagov/kev-data)", "licence_verified": True, "redistributable": True,
        "attribution": "Known Exploited Vulnerabilities catalog, CISA.",
    },
    "euvd": {
        "name": "European Vulnerability Database", "owner": "ENISA (European Union Agency for Cybersecurity)",
        "government": True, "api": "https://euvdservices.enisa.europa.eu/api", "key_env": None,
        "licence": "not verified: the EUVD FAQ/API pages were unavailable 2026-09-27", "licence_verified": False,
        "redistributable": False, "attribution": "European Vulnerability Database (EUVD), ENISA.",
    },
    "mitre_attack": {
        "name": "MITRE ATT&CK (Enterprise, STIX 2.1)", "owner": "The MITRE Corporation (non-profit, not government)",
        "government": False,
        "api": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
        "key_env": None, "licence": "royalty-free, incl. commercial use, with MITRE's copyright designation and license "
        "reproduced (ATT&CK Terms of Use)", "licence_verified": True, "redistributable": True,
        "attribution": "© The MITRE Corporation. This work is reproduced and distributed with the permission of The "
                       "MITRE Corporation. MITRE ATT&CK®.",
    },
    "mitre_capec": {
        "name": "MITRE CAPEC (STIX 2.1)", "owner": "The MITRE Corporation (non-profit, not government)",
        "government": False, "api": "https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json",
        "key_env": None, "licence": "royalty-free, incl. commercial use, with MITRE's copyright designation and license "
        "reproduced (CAPEC Terms of Use)", "licence_verified": True, "redistributable": True,
        "attribution": "© The MITRE Corporation. CAPEC™.",
    },
}

# which product names each fingerprinted implementation (T-127) is known by in each source
PRODUCTS = {
    "strongSwan": {"nvd_keyword": "strongswan", "cpe": ":strongswan:strongswan:", "kev": ("strongswan", None), "euvd_vendor": "strongswan"},
    "Libreswan": {"nvd_keyword": "libreswan", "cpe": ":libreswan:libreswan:", "kev": ("libreswan", None), "euvd_vendor": "libreswan"},
    "MikroTik RouterOS": {"nvd_keyword": "mikrotik routeros", "cpe": ":mikrotik:routeros:", "kev": ("mikrotik", "routeros"), "euvd_vendor": "mikrotik"},
}
