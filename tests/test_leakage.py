import os
from tunnelscope.evidence.extract import build_records
CAP = os.path.join(os.path.dirname(__file__), "..", "testbed", "captures")

def _m(p):
    return max(build_records(os.path.join(CAP,p)),key=lambda r:len(getattr(r,'_esp',[]))).findings["metadata_exposure"]

def test_unpadded_leaks_size_and_timing():
    v = _m("cs-aes256gcm16.pcap").value
    assert v["size_bits"] > 1 and v["timing_bits"] > 0 and not v["tfc_padding_active"]

def test_tfc_padding_zeroes_size_not_timing():
    v = _m("tfc-sample.pcap").value
    assert v["size_bits"] == 0.0 and v["tfc_padding_active"] and v["timing_bits"] > 0

def test_leakage_never_labels_traffic():
    # CS-01/DEC-021: the value is bits, never a traffic class
    v = _m("cs-aes256gcm16.pcap").value
    assert set(v.keys()) == {"size_bits", "timing_bits", "tfc_padding_active"}
