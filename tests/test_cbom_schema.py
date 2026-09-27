"""T-124: the exported CBOM is valid CycloneDX 1.6, checked against the OFFICIAL schema file
(tests/fixtures/cyclonedx, unmodified), and it round-trips to what the engine saw.

The checker below walks the official schema itself. It supports the JSON-Schema keywords our documents
reach and raises on any other keyword, so it can fail loudly but never pass silently. A full validation
with the `jsonschema` package over every capture's export is recorded in TODO.md."""
import json
import os
import re

import pytest

from tunnelscope.evidence.extract import build_records
from tunnelscope.pq.cbom import build_cbom, to_cyclonedx

HERE = os.path.dirname(__file__)
CAP = os.path.join(HERE, "..", "testbed", "captures")
SCHEMA = json.load(open(os.path.join(HERE, "fixtures", "cyclonedx", "bom-1.6.schema.json")))
ANNOTATIONS = {"title", "description", "$comment", "examples", "meta:enum", "default", "format", "$id",
               "$schema", "deprecated", "readOnly", "contentMediaType", "contentEncoding"}


def _resolve(node):
    while "$ref" in node:
        ref = node["$ref"]
        if not ref.startswith("#/"):
            raise NotImplementedError(f"external $ref {ref}: not reached by a valid TunnelScope CBOM")
        node = SCHEMA
        for part in ref[2:].split("/"):
            node = node[part]
    return node


def errors(doc, node=SCHEMA, path="$"):
    node = _resolve(node)
    out = []
    for kw in node:
        if kw not in ANNOTATIONS | {"type", "properties", "additionalProperties", "required", "enum", "items",
                                    "minimum", "maximum", "pattern", "oneOf", "anyOf", "allOf", "uniqueItems",
                                    "minItems", "const", "definitions", "patternProperties", "minLength"}:
            raise NotImplementedError(f"{path}: schema keyword {kw!r} not supported by this checker")
    t = node.get("type")
    types = {"object": dict, "array": list, "string": str, "boolean": bool, "integer": int, "number": (int, float)}
    if t and not isinstance(doc, types[t]) or (t == "integer" and isinstance(doc, bool)):
        return [f"{path}: expected {t}"]
    if "enum" in node and doc not in node["enum"]:
        out.append(f"{path}: {doc!r} not in enum")
    if "const" in node and doc != node["const"]:
        out.append(f"{path}: {doc!r} != {node['const']!r}")
    if "minimum" in node and doc < node["minimum"] or "maximum" in node and doc > node["maximum"]:
        out.append(f"{path}: {doc} out of range")
    if "pattern" in node and not re.search(node["pattern"], doc):
        out.append(f"{path}: {doc!r} does not match pattern")
    if "minLength" in node and len(doc) < node["minLength"]:
        out.append(f"{path}: too short")
    if isinstance(doc, dict):
        props = node.get("properties", {})
        for k in node.get("required", []):
            if k not in doc:
                out.append(f"{path}: missing required {k!r}")
        for k, v in doc.items():
            if k in props:
                out += errors(v, props[k], f"{path}.{k}")
            elif node.get("additionalProperties") is False:
                out.append(f"{path}: additional property {k!r} not allowed")
    if isinstance(doc, list):
        if "minItems" in node and len(doc) < node["minItems"]:
            out.append(f"{path}: too few items")
        if node.get("uniqueItems") and len({json.dumps(x, sort_keys=True) for x in doc}) != len(doc):
            out.append(f"{path}: items not unique")
        for i, x in enumerate(doc):
            if "items" in node:
                out += errors(x, node["items"], f"{path}[{i}]")
    for sub in node.get("allOf", []):
        out += errors(doc, sub, path)
    for kw, need in (("oneOf", 1), ("anyOf", None)):
        if kw in node:
            ok = sum(not errors(doc, sub, path) for sub in node[kw])
            if (need and ok != need) or (not need and ok == 0):
                out.append(f"{path}: {kw} matched {ok} alternatives")
    return out


CAPTURES = ["classical-baseline.pcap", "pq-mlkem768.pcap", "pq-downgrade.pcap", "tfc-sample.pcap",
            "rekey-cs-pfs-off-aes256gcm16-run2.pcap", os.path.join("cloud", "c-v1.pcap")]


@pytest.mark.parametrize("cap", CAPTURES)
def test_export_is_valid_cyclonedx_1_6(cap):
    bom = to_cyclonedx(build_records(os.path.join(CAP, cap)), os.path.join(CAP, cap))
    assert errors(bom) == []
    refs = [c["bom-ref"] for c in bom["components"]]
    assert len(refs) == len(set(refs))                               # bom-refs unique
    for c in bom["components"]:                                      # every transform points at a listed asset
        pp = c["cryptoProperties"].get("protocolProperties", {})
        for r in [r for v in pp.get("ikev2TransformTypes", {}).values() for r in v] + pp.get("cryptoRefArray", []):
            assert r in refs, r


def test_the_checker_catches_what_the_old_export_got_wrong():
    bom = to_cyclonedx(build_records(os.path.join(CAP, "classical-baseline.pcap")))
    old = json.loads(json.dumps(bom))
    old["tunnelscope_sa_summary"] = []                               # the pre-T-124 custom root key
    next(c for c in old["components"] if c["name"] == "MODP-2048")["cryptoProperties"]["algorithmProperties"]["primitive"] = "dh"
    errs = errors(old)
    assert any("tunnelscope_sa_summary" in e for e in errs) and any("'dh' not in enum" in e for e in errs)


def _levels(cap):
    bom = to_cyclonedx(build_records(os.path.join(CAP, cap)))
    return {c["name"]: c["cryptoProperties"]["algorithmProperties"].get("nistQuantumSecurityLevel")
            for c in bom["components"] if c["cryptoProperties"]["assetType"] == "algorithm"}


def test_quantum_levels_are_the_defined_ones_never_guessed():
    pq = _levels("pq-mlkem768.pcap")
    assert pq["ML-KEM-768"] == 3                                     # FIPS 203 category 3
    classical = _levels("classical-baseline.pcap")
    assert classical["MODP-2048"] == 0                               # Shor-breakable: no category met
    for name, level in {**pq, **classical}.items():
        if name.startswith(("HMAC", "ChaCha20")):
            assert level is None, name                               # no NIST category exists: left out
        if name.startswith("AES-") and name.endswith("256"):
            assert level == 5, name                                  # category 5 = AES-256 key search


def test_round_trip_matches_what_the_engine_saw():
    """Posture, gaps and algorithms read back from the exported file equal the internal CBOM."""
    for cap in CAPTURES:
        recs = build_records(os.path.join(CAP, cap))
        internal = build_cbom(recs)
        bom = json.loads(json.dumps(to_cyclonedx(recs)))
        sas = [c for c in bom["components"] if c["cryptoProperties"]["assetType"] == "protocol"]
        assert len(sas) == len(internal["tunnelscope_sa_summary"]), cap
        for sa, want in zip(sas, internal["tunnelscope_sa_summary"]):
            props = [(p["name"], p["value"]) for p in sa["properties"]]
            assert ("tunnelscope:quantum_posture", want["quantum_posture"]) in props, cap
            assert len([n for n, _ in props if n == "tunnelscope:gap"]) == len(want["gaps"]), cap
        algos = {c["name"] for c in bom["components"] if c["cryptoProperties"]["assetType"] == "algorithm"}
        assert algos == {c["name"] for c in internal["components"]
                         if c["cryptoProperties"]["assetType"] == "algorithm"}, cap
