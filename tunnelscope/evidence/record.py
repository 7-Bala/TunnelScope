"""Core evidence types — the spine of TunnelScope (ADR-002, invariant I4).

Every extracted fact is a `Finding`, and a Finding cannot exist without a
`status`. There is deliberately no way to produce a bare value: an extractor
that cannot see something returns a Finding with status NOT_OBSERVABLE or
UNKNOWN, never `None` silently upgraded later. This makes "we did not see it"
and "it is not there" distinct, first-class outcomes (DEC-008/010).
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field, asdict
from typing import Any


class Status(enum.Enum):
    """How a Finding was arrived at. The assessor treats the last three as
    answers, never as missing data to be filled in."""
    OBSERVED = "OBSERVED"            # read directly from plaintext on the wire
    MEASURED = "MEASURED"            # quantified over time / distribution (e.g. rekey interval, leakage bits)
    INFERRED = "INFERRED"            # deduced with a stated method + confidence
    UNKNOWN = "UNKNOWN"              # could be present, but this vantage/capture cannot tell
    NOT_OBSERVABLE = "NOT_OBSERVABLE"  # provably not recoverable at this tier (e.g. AES key length at T0)
    CONTRADICTORY = "CONTRADICTORY"  # two surfaces disagree (e.g. T0/T1 inference vs T2 telemetry)


class Vantage(enum.Enum):
    T0 = "T0"  # passive, ESP only
    T1 = "T1"  # passive + IKE visible
    T2 = "T2"  # endpoint telemetry (swanctl/pluto/config)
    T3 = "T3"  # keying material
    T4 = "T4"  # authorized active probe


@dataclass(frozen=True)
class EvidencePtr:
    """A pointer back to the exact bytes that justify a Finding (invariant I2)."""
    pcap: str = ""
    frame: int | None = None
    field: str = ""
    raw: str = ""


@dataclass
class Finding:
    attribute: str
    status: Status
    vantage: Vantage
    method: str                       # which validated method produced this (e.g. "EXP-01 sieve")
    value: Any = None                 # the finding; may be a value, a candidate set, or None
    confidence: float = 1.0           # 1.0 for deterministic; calibrated for the leakage instrument
    evidence: list[EvidencePtr] = field(default_factory=list)
    note: str = ""

    def __post_init__(self):
        if not isinstance(self.status, Status):
            raise TypeError("Finding.status must be a Status (ADR-002): no bare values")
        if not isinstance(self.vantage, Vantage):
            raise TypeError("Finding.vantage must be a Vantage (invariant I2)")
        # A value-bearing status must actually carry a value; an absence status must not pretend to.
        if self.status in (Status.OBSERVED, Status.MEASURED, Status.INFERRED) and self.value is None:
            raise ValueError(f"{self.attribute}: status {self.status.value} requires a value")
        if self.status in (Status.UNKNOWN, Status.NOT_OBSERVABLE) and self.value is not None:
            raise ValueError(f"{self.attribute}: status {self.status.value} must not carry a value")
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError("confidence must be in [0, 1]")

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        d["vantage"] = self.vantage.value
        return d


@dataclass
class EvidenceRecord:
    """All findings for one Security Association, keyed by its SPIs."""
    ike_spi_i: str = ""
    ike_spi_r: str = ""
    child_spi_in: str = ""
    child_spi_out: str = ""
    src: str = ""
    dst: str = ""
    source_pcap: str = ""
    findings: dict[str, Finding] = field(default_factory=dict)

    def add(self, f: Finding) -> None:
        """Add a finding. If one already exists for this attribute from a
        different vantage with a conflicting value, mark it CONTRADICTORY
        (DEC-010) rather than silently overwriting."""
        existing = self.findings.get(f.attribute)
        if existing is None:
            self.findings[f.attribute] = f
            return
        both_valued = (existing.value is not None and f.value is not None)
        if both_valued and existing.value != f.value:
            self.findings[f.attribute] = Finding(
                attribute=f.attribute, status=Status.CONTRADICTORY,
                vantage=f.vantage, method=f"{existing.method} vs {f.method}",
                value=None, confidence=1.0,
                evidence=existing.evidence + f.evidence,
                note=(f"{existing.vantage.value}={existing.value!r} ({existing.method}) "
                      f"disagrees with {f.vantage.value}={f.value!r} ({f.method})"),
            )
        else:
            # higher vantage (more authoritative) wins when one side is an absence
            prefer = f if f.vantage.value > existing.vantage.value else existing
            self.findings[f.attribute] = prefer

    def key(self) -> str:
        return f"{self.ike_spi_i or '?'}_{self.ike_spi_r or '?'}"

    def to_dict(self) -> dict:
        return {
            "sa_key": self.key(),
            "ike_spi_i": self.ike_spi_i, "ike_spi_r": self.ike_spi_r,
            "child_spi_in": self.child_spi_in, "child_spi_out": self.child_spi_out,
            "src": self.src, "dst": self.dst, "source_pcap": self.source_pcap,
            "findings": {k: v.to_dict() for k, v in self.findings.items()},
        }
