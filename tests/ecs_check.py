"""Check Elastic Common Schema documents against the official field reference (ecs_flat.yml, tag v9.5.0, vendored).
Used by tests/test_siem_ecs.py and experiments/exp46-siem-export/analyze.py. Only `tunnelscope.*` (our own namespace)
is exempt; every other field must exist in ECS with a value of the field's type."""
import ipaddress
import re
from pathlib import Path

import yaml

ECS_FLAT = Path(__file__).resolve().parent / "fixtures" / "ecs" / "ecs_flat.yml"
_ISO = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$")
_ECS = None


def ecs():
    global _ECS
    if _ECS is None:
        with open(ECS_FLAT) as fh:
            _ECS = yaml.safe_load(fh)
    return _ECS


def flatten(doc, prefix=""):
    """{'a': {'b': 1}} -> {'a.b': 1}; lists are leaves."""
    out = {}
    for k, v in doc.items():
        name = f"{prefix}{k}"
        if isinstance(v, dict):
            out.update(flatten(v, name + "."))
        else:
            out[name] = v
    return out


def _type_ok(kind, v):
    if kind in ("keyword", "constant_keyword", "match_only_text", "text", "wildcard"):
        return isinstance(v, str)
    if kind == "date":
        return isinstance(v, str) and bool(_ISO.match(v))
    if kind == "ip":
        try:
            ipaddress.ip_address(v)
            return isinstance(v, str)
        except ValueError:
            return False
    if kind in ("long", "integer"):
        return isinstance(v, int) and not isinstance(v, bool)
    if kind == "boolean":
        return isinstance(v, bool)
    return False                      # a type this checker does not know is a failure, never a silent pass


def problems(doc: dict) -> list[str]:
    ref = ecs()
    out = []
    for name, val in flatten(doc).items():
        if name.startswith("tunnelscope."):
            continue
        spec = ref.get(name)
        if spec is None:
            out.append(f"{name}: not an ECS field")
            continue
        vals = val if isinstance(val, list) else [val]
        if isinstance(val, list) and "array" not in (spec.get("normalize") or []):
            out.append(f"{name}: ECS does not define this field as an array")
        for x in vals:
            if not _type_ok(spec["type"], x):
                out.append(f"{name}: {x!r} is not a valid {spec['type']}")
        allowed = {a["name"] for a in spec.get("allowed_values") or []}
        if allowed:
            for x in vals:
                if x not in allowed:
                    out.append(f"{name}: {x!r} is not one of ECS's allowed values")
    cats = {c["name"]: set(c.get("expected_event_types") or []) for c in ref["event.category"]["allowed_values"]}
    for t in flatten(doc).get("event.type", []) or []:
        if not all(t in cats.get(c, set()) for c in flatten(doc).get("event.category", [])):   # strict: valid for EVERY category
            out.append(f"event.type {t!r} is not valid for categories {flatten(doc).get('event.category')}")
    if "@timestamp" not in doc:
        out.append("@timestamp is missing (required by ECS)")
    if "ecs" not in doc or "version" not in doc["ecs"]:
        out.append("ecs.version is missing (required by ECS)")
    return out
