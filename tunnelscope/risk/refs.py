"""T-130: the threat matrix (tunnelscope/risk/risk.py) named in the catalogues analysts already use.

Every ID and name below was checked against MITRE's own data on 2026-09-27 (ATT&CK Enterprise v19.2 STIX and
CAPEC STIX 2.1 from mitre/cti); tests/test_intel.py checks this table against the snapshot in
risk/data/mitre_names.json. A mapping names what the threat IS in the catalogue; it never changes a score.
© The MITRE Corporation. ATT&CK® and CAPEC™ are used under their royalty-free terms of use."""

THREAT_REFS = {
    "TH-01": [("CAPEC-97", "Cryptanalysis")],
    "TH-02": [("T1040", "Network Sniffing"), ("CAPEC-97", "Cryptanalysis")],
    "TH-03": [("T1557", "Adversary-in-the-Middle"), ("T1600.001", "Reduce Key Space"),
              ("CAPEC-620", "Drop Encryption Level"), ("CAPEC-220", "Client-Server Protocol Manipulation")],
    "TH-04": [("T1600", "Weaken Encryption"), ("CAPEC-20", "Encryption Brute Forcing")],
    "TH-05": [("T1565.002", "Transmitted Data Manipulation"), ("CAPEC-94", "Adversary in the Middle (AiTM)")],
    "TH-06": [("T1110.002", "Password Cracking"), ("CAPEC-55", "Rainbow Table Password Cracking"),
              ("CAPEC-49", "Password Brute Forcing")],
    "TH-07": [("T1040", "Network Sniffing"), ("CAPEC-157", "Sniffing Attacks")],
    "TH-08": [("CAPEC-60", "Reusing Session IDs (aka Session Replay)")],
    "TH-09": [("T1190", "Exploit Public-Facing Application"), ("CAPEC-115", "Authentication Bypass")],
    "TH-10": [("T1040", "Network Sniffing"), ("CAPEC-192", "Protocol Analysis")],
    "TH-11": [("T1040", "Network Sniffing"), ("CAPEC-97", "Cryptanalysis")],
    "TH-12": [("T1600", "Weaken Encryption")],
}


def refs_for(threat_id: str) -> list[dict]:
    return [{"id": i, "name": n, "catalogue": "CAPEC" if i.startswith("CAPEC") else "ATT&CK"}
            for i, n in THREAT_REFS.get(threat_id, [])]
