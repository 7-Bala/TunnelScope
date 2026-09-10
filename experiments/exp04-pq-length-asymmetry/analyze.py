#!/usr/bin/env python3
"""EXP-04 — PQ / hybrid key-exchange observability (RFC 9370 ADDKE / ML-KEM-768).

Original hypothesis (PQ-6, 07-DISCOVER-pq-and-late-findings.md): a KEM is
distinguishable from classical (EC)DH by INITIATOR/RESPONDER KE-payload
LENGTH ASYMMETRY alone (encapsulation key vs ciphertext are different sizes
for ML-KEM, whereas every classical DH group sends identical-length payloads
both directions).

What this experiment actually found is STRONGER and covers more ground than
that narrow hypothesis. Comparing a `classical-baseline` capture (proposals
= aes256-sha256-modp2048) against a `pq-mlkem768` capture (proposals =
aes256-sha256-modp2048-ke1_mlkem768), all traffic between the SAME two
endpoints, same PSK auth, same everything else — FOUR independent,
deterministic, plaintext signals separate them, in order of appearance on
the wire:

  SIGNAL 1 (earliest, message 1): presence of the `INTERMEDIATE_EXCHANGE_SUPPORTED`
      notify (type 16438, RFC 9242) inside IKE_SA_INIT. Already correctly
      dissected by Wireshark/tshark (unlike the ML-KEM transform ID itself,
      GitLab issue #21072) — this is NOT the thing that dissector bug hides.
  SIGNAL 2: IKE_SA_INIT SA-payload size delta from the extra ADDKE transform
      substructure (+16 bytes in our capture, both directions).
  SIGNAL 3 (strongest, simplest): presence of ANY `IKE_INTERMEDIATE`
      exchange-type message (ISAKMP exchange type 43, RFC 9242) at all. The
      classical-baseline capture contains ZERO such messages; the PQ capture
      contains 3 (one fragmented). Exchange type is a PLAINTEXT ISAKMP header
      field — no decryption or transform-ID decoding needed whatsoever.
  SIGNAL 4 (original PQ-6 hypothesis, refined): KE-payload length asymmetry
      WITHIN the IKE_INTERMEDIATE exchange. Confirmed in principle but
      COMPLICATED by an unanticipated interaction: ML-KEM-768's ~1184-byte
      public key pushed the encrypted IKE_INTERMEDIATE message over IKEv2's
      fragmentation threshold (RFC 7383), so the initiator's message arrived
      as 2 fragments and the responder's as 1 — meaning "fragmentation
      occurred at all" is itself a plaintext signal, but a naive per-packet
      length comparison needs fragment reassembly first to be clean. This
      was NOT anticipated in the original hypothesis and is reported as a
      genuine correction, not smoothed over.

Ground truth: testbed/configs/alice-pq/swanctl.conf (T2) — `pq-mlkem768`
proposes `ke1_mlkem768`, `classical-baseline` does not. Confirmed
additionally by strongSwan's own IKE_SA_INIT proposal-selection log line
("...MODP_2048/KE1_ML_KEM_768") captured in the .groundtruth.json files.
"""
import json
import subprocess
import sys
from pathlib import Path

IKE_SA_INIT = "34"
IKE_INTERMEDIATE = "43"
INTERMEDIATE_EXCHANGE_SUPPORTED = "16438"


def tshark_fields(pcap, display_filter, fields):
    args = ["tshark", "-r", str(pcap), "-Y", display_filter, "-T", "fields"]
    for f in fields:
        args += ["-e", f]
    out = subprocess.run(args, capture_output=True, text=True, check=True).stdout
    rows = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) == len(fields):
            rows.append(parts)
    return rows


def analyze_capture(pcap: Path, arm_name: str) -> dict:
    # Signal 1 + 2: IKE_SA_INIT notify types and ip.len
    init_rows = tshark_fields(pcap, f"isakmp.exchangetype=={IKE_SA_INIT}",
                               ["ip.src", "ip.len", "isakmp.notify.msgtype"])
    has_intermediate_supported = any(
        INTERMEDIATE_EXCHANGE_SUPPORTED in (notify or "").split(",")
        for _, _, notify in init_rows
    )
    init_sizes = {src: int(l) for src, l, _ in init_rows}

    # Signal 3: any IKE_INTERMEDIATE exchange messages at all
    intermediate_rows = tshark_fields(pcap, f"isakmp.exchangetype=={IKE_INTERMEDIATE}",
                                       ["ip.src", "ip.len"])
    n_intermediate_msgs = len(intermediate_rows)
    intermediate_sizes_by_src = {}
    for src, l in intermediate_rows:
        intermediate_sizes_by_src.setdefault(src, []).append(int(l))

    return {
        "arm": arm_name,
        "signal1_intermediate_exchange_supported_notify_present": has_intermediate_supported,
        "signal2_ike_sa_init_sizes_by_src": init_sizes,
        "signal3_n_ike_intermediate_messages": n_intermediate_msgs,
        "signal3_ike_intermediate_present": n_intermediate_msgs > 0,
        "signal4_ike_intermediate_sizes_by_src": intermediate_sizes_by_src,
        "signal4_fragmentation_observed": any(len(v) > 1 for v in intermediate_sizes_by_src.values()),
    }


def main():
    captures_dir = Path(sys.argv[1] if len(sys.argv) > 1 else "../../testbed/captures")
    results_dir = Path(sys.argv[2] if len(sys.argv) > 2 else "results")
    results_dir.mkdir(parents=True, exist_ok=True)

    classical = analyze_capture(captures_dir / "classical-baseline.pcap", "classical-baseline")
    pq = analyze_capture(captures_dir / "pq-mlkem768.pcap", "pq-mlkem768")

    # Cross-check against T2 ground truth. NOTE: ground truth files were
    # captured with `swanctl --list-sas`, which lists ALL currently-installed
    # SAs, not just the one this run initiated — an earlier manual test left
    # a second (pq-mlkem768) SA running when the classical-baseline capture's
    # ground truth was recorded, so a naive whole-blob substring search is
    # wrong. Parse the SPECIFIC arm's block instead.
    def arm_block(list_sas_text: str, arm: str) -> str:
        lines = list_sas_text.splitlines()
        out, capturing = [], False
        for line in lines:
            if line.startswith(f"{arm}:"):
                capturing = True
            elif capturing and line and not line[0].isspace():
                break
            if capturing:
                out.append(line)
        return "\n".join(out)

    gt_pq = json.loads((captures_dir / "pq-mlkem768.groundtruth.json").read_text())
    gt_confirms_pq = "ML_KEM_768" in arm_block(gt_pq.get("alice_list_sas", ""), "pq-mlkem768")
    gt_classical = json.loads((captures_dir / "classical-baseline.groundtruth.json").read_text())
    gt_confirms_classical_no_pq = "ML_KEM" not in arm_block(gt_classical.get("alice_list_sas", ""), "classical-baseline")

    # Compute the deltas the four signals report
    init_delta = None
    common_srcs = set(classical["signal2_ike_sa_init_sizes_by_src"]) & set(pq["signal2_ike_sa_init_sizes_by_src"])
    if common_srcs:
        init_delta = {
            src: pq["signal2_ike_sa_init_sizes_by_src"][src] - classical["signal2_ike_sa_init_sizes_by_src"].get(src, 0)
            for src in pq["signal2_ike_sa_init_sizes_by_src"]
        }

    report = {
        "classical_baseline": classical,
        "pq_mlkem768": pq,
        "ground_truth_check": {
            "pq_capture_confirmed_ml_kem_768_in_swanctl_log": gt_confirms_pq,
            "classical_capture_confirmed_no_ml_kem": gt_confirms_classical_no_pq,
        },
        "signal1_verdict": {
            "classical_has_notify": classical["signal1_intermediate_exchange_supported_notify_present"],
            "pq_has_notify": pq["signal1_intermediate_exchange_supported_notify_present"],
            "discriminates": (classical["signal1_intermediate_exchange_supported_notify_present"]
                               != pq["signal1_intermediate_exchange_supported_notify_present"]),
            "caveat": "Empirically observed in strongSwan 6.0.2: this notify appeared ONLY when the "
                      "LOCAL connection config actually proposes an ADDKE, not as an unconditional "
                      "software-capability flag. Not guaranteed by RFC 9242 text alone across all "
                      "implementations — verify per-implementation before relying on this signal (OQ-07-new).",
        },
        "signal2_verdict": {
            "ike_sa_init_size_delta_bytes": init_delta,
            "discriminates": init_delta is not None and all(v != 0 for v in init_delta.values()),
        },
        "signal3_verdict": {
            "classical_ike_intermediate_count": classical["signal3_n_ike_intermediate_messages"],
            "pq_ike_intermediate_count": pq["signal3_n_ike_intermediate_messages"],
            "discriminates": (classical["signal3_n_ike_intermediate_messages"] == 0
                               and pq["signal3_n_ike_intermediate_messages"] > 0),
            "note": "Strongest signal: plaintext ISAKMP exchange-type field, zero decoding required, "
                    "works even though Wireshark cannot render the ML-KEM transform ID (issue #21072).",
        },
        "signal4_verdict": {
            "pq_fragmentation_observed": pq["signal4_fragmentation_observed"],
            "classical_fragmentation_observed": classical["signal4_fragmentation_observed"],
            "note": "Original PQ-6 hypothesis (clean initiator/responder KE-payload length asymmetry) "
                    "is CONFIRMED IN PRINCIPLE but COMPLICATED: ML-KEM-768's ~1184-byte public key "
                    "pushed the encrypted IKE_INTERMEDIATE message over the IKEv2 fragmentation "
                    "threshold (RFC 7383) for the initiator only in this run, so a clean per-packet "
                    "comparison requires fragment reassembly first. This interaction was NOT "
                    "anticipated in the original hypothesis. Fragmentation-occurred-at-all is itself "
                    "an additional (weaker, corroborating) signal.",
        },
    }

    (results_dir / "exp04_results.json").write_text(json.dumps(report, indent=2))

    print("=== EXP-04 Results ===")
    print(f"Ground truth confirmed: PQ capture used ML_KEM_768={gt_confirms_pq}, "
          f"classical capture used no ML-KEM={gt_confirms_classical_no_pq}")
    print(f"\nSignal 1 (INTERMEDIATE_EXCHANGE_SUPPORTED notify): "
          f"classical={report['signal1_verdict']['classical_has_notify']} "
          f"pq={report['signal1_verdict']['pq_has_notify']} "
          f"discriminates={report['signal1_verdict']['discriminates']}")
    print(f"Signal 2 (IKE_SA_INIT size delta): {init_delta} bytes -> "
          f"discriminates={report['signal2_verdict']['discriminates']}")
    print(f"Signal 3 (IKE_INTERMEDIATE message presence): "
          f"classical_count={classical['signal3_n_ike_intermediate_messages']} "
          f"pq_count={pq['signal3_n_ike_intermediate_messages']} -> "
          f"discriminates={report['signal3_verdict']['discriminates']} *** STRONGEST SIGNAL ***")
    print(f"Signal 4 (KE-payload asymmetry / fragmentation): "
          f"pq_fragmented={pq['signal4_fragmentation_observed']} "
          f"classical_fragmented={classical['signal4_fragmentation_observed']}")
    print(f"\nWrote {results_dir / 'exp04_results.json'}")


if __name__ == "__main__":
    main()
