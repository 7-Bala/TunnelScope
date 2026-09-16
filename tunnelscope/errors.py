"""Typed errors, so a failure carries its own exit code to the CLI.

The project's standing invariant is that absence of evidence is never scored
as compliance (I8, DEC-007). That applies to *failures* too: a run that could
not produce evidence must not be indistinguishable from a clean run. Each
error below maps to a distinct exit code so an automated caller (role D's
SIEM workflow) can tell "scanned, nothing wrong" from "never actually
scanned".
"""
from __future__ import annotations


class TunnelScopeError(Exception):
    """Base for errors the CLI reports as a message rather than a traceback."""

    exit_code = 1


class InputError(TunnelScopeError):
    """The caller pointed us at something unusable: a missing pcap, a path
    that does not exist, a directory holding no captures."""

    exit_code = 2


class DependencyError(TunnelScopeError):
    """The external analysis stack is missing, unusable, or has drifted —
    tshark absent, or no longer exposing a field an extractor reads."""

    exit_code = 3
