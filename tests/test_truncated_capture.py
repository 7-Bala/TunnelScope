"""A capture that ends inside its last packet (EXP-37).

The whole packets before the cut are real evidence and are analysed; the file is flagged; anything that would
rest on what is NOT in the file is UNKNOWN. A file that is not a capture at all still raises.
Built from our own lab capture so no external data is needed.
"""
import struct
from pathlib import Path

import pytest

from tunnelscope.errors import InputError
from tunnelscope.evidence.extract import build_records
from tunnelscope.ingest import tshark

SRC = Path(__file__).resolve().parent.parent / "testbed" / "captures" / "classical-baseline-6.1.0.pcap"


def _records(raw: bytes):
    """Byte offsets of every packet record in a little-endian classic pcap."""
    assert raw[:4] == b"\xd4\xc3\xb2\xa1"
    pos, out = 24, []
    while pos + 16 <= len(raw):
        incl = struct.unpack("<I", raw[pos + 8:pos + 12])[0]
        out.append((pos, pos + 16 + incl))
        pos += 16 + incl
    return out


@pytest.fixture(autouse=True)
def _fresh():
    tshark.clear_cache()
    yield
    tshark.clear_cache()


def _first_init(raw):
    tshark.clear_cache()
    p = Path(__import__("tempfile").mkdtemp()) / "whole.pcap"
    p.write_bytes(raw)
    init = [m for m in tshark.ike_messages(str(p)) if m["exchange"] == 34]
    tshark.clear_cache()
    return init[0]["frame"], init


def _findings(path):
    recs = [r for r in build_records(str(path)) if getattr(r, "_ike", [])]
    assert recs, "the readable part should still yield an IKE record"
    return recs[0].findings


def test_cut_file_is_analysed_flagged_and_keeps_its_early_findings(tmp_path):
    raw = SRC.read_bytes()
    spans = _records(raw)
    p = tmp_path / "cut.pcap"
    p.write_bytes(raw[:spans[12][0] + 16 + 5])        # five bytes into packet 13
    s = tshark.capture_summary(str(p))
    assert s["capture_truncated"] is True and s["has_ike_sa_init"] is True
    f = _findings(p)
    assert f["capture_integrity"].status.value == "OBSERVED" and f["capture_integrity"].value == "truncated"
    whole = tmp_path / "whole.pcap"
    whole.write_bytes(raw)
    tshark.clear_cache()
    g = _findings(whole)
    assert f["ike_version"].value == g["ike_version"].value == "IKEv2"
    assert f["ike_encr"].value == g["ike_encr"].value          # read from whole packets, same value as the intact file


def test_intact_file_has_no_integrity_finding_and_keeps_its_summary_shape(tmp_path):
    p = tmp_path / "whole.pcap"
    p.write_bytes(SRC.read_bytes())
    assert "capture_truncated" not in tshark.capture_summary(str(p))
    assert "capture_integrity" not in _findings(p)


def test_request_without_response_is_peer_unreachable_only_when_the_file_is_intact(tmp_path):
    raw = SRC.read_bytes()
    spans = _records(raw)
    frame, init = _first_init(raw)
    req = next(m for m in init if not m["is_response"])["frame"]
    end_of_request = spans[req - 1][1]
    clean = tmp_path / "clean.pcap"
    clean.write_bytes(raw[:end_of_request])                        # ends exactly after the request
    cut = tmp_path / "cut.pcap"
    cut.write_bytes(raw[:end_of_request + 16 + 3])                 # three bytes into the next packet
    assert _findings(clean)["negotiation_outcome"].value == "peer-unreachable"
    tshark.clear_cache()
    out = _findings(cut)["negotiation_outcome"]
    assert out.status.value == "UNKNOWN" and out.value is None     # the response may be in the lost part
    assert "cut short" in out.note


def test_a_file_that_is_not_a_capture_still_raises(tmp_path):
    p = tmp_path / "junk.pcap"
    p.write_bytes(b"this is not a capture file at all" * 20)
    with pytest.raises(InputError, match="isn't a capture file|could not read"):
        tshark.capture_summary(str(p))


def test_a_file_cut_off_inside_its_header_is_an_error_not_an_empty_analysis(tmp_path):
    """tshark words this like a mid-packet cut; there is no whole packet to analyse, so it must still raise."""
    p = tmp_path / "header_only.pcap"
    p.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 4)
    with pytest.raises(InputError, match="could not read"):
        tshark.capture_summary(str(p))
