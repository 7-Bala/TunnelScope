# TunnelScope: jury Q&A prep

Questions a technical jury is likely to ask, with short answers.

## About the AI

**Q: Where is the AI in this?**
Three places. Random Forest models we trained ourselves predict the type of traffic inside an encrypted
tunnel from packet size and timing, with a confidence for each prediction. A second model detects
tunnels that carry mixed traffic. And anomaly detection learns each tunnel's normal behaviour and flags
a cipher change or a downgrade. Reading the plaintext IKE fields is done by exact parsing, which is the
right tool for fields that are sitting in the clear.

**Q: How can you tell what is inside an encrypted tunnel?**
Encryption hides the content, not the shape. Packet sizes, timing and direction differ between web
browsing, video, voice, chat and file transfer, and the models learn those shapes from traffic we sent
through real tunnels in our lab and from public VPN traffic.

**Q: Are the models trained by you?**
Yes, every one. No pretrained or third-party model is used, and a test fails if one is ever added.
The models are small, ship as plain arrays and train in seconds from the scripts in the repository.

## About the assessment

**Q: Wireshark can already parse ML-KEM. What is new?**
Parsing is not assessment. Wireshark shows the key-exchange field. TunnelScope tells you the tunnel was
offered post-quantum but negotiated classical, ties that to the DST guidance, and does it across a
fleet of tunnels.

**Q: Which standards do you check against?**
DISA VPN SRG, RFC 8247 for IKEv2, RFC 8221 and RFC 4303 for ESP and AH, and a post-quantum readiness
baseline from the DST report. The rules are YAML files, and every verdict cites the rule and standard
behind it.

**Q: Why several scores instead of one?**
DISA and RFC 8247 sometimes rate the same tunnel differently, so each standard keeps its own score,
and the auditor sees both. On top of that there is one 0-100 risk score with its drivers.

**Q: How do you handle new vulnerabilities?**
Two layers. Known patterns are rules over IKE message order and payloads, and adding one is a file
change. For everything else the anomaly model flags a tunnel whose behaviour moves away from its own
history, before anyone has a name for the cause.

## About the fixes

**Q: Isn't this still just a report?**
No. Every failed check gets a remediation plan with the exact change. For weak strongSwan settings
TunnelScope applies the fix itself: the command is checked against an allowlist, the change is tried on
a copy and loaded in a throwaway copy of the VPN, the current state is saved, the fix is applied, and a
fresh capture confirms the rule now passes and nothing else got worse. If anything fails it rolls back
automatically, and every step goes into an audit log. It works in the lab and on real strongSwan
gateways over SSH, where a named person accepts written terms for the gateway first and confirms each
change with the exact sentence the preview shows.

## About trust

**Q: How do we know the numbers were not tuned to look good?**
Every experiment is pre-registered: the expected result was written and committed to git before any
data was collected, so the git history shows what we predicted and when.

**Q: Isn't validating against your own tool circular?**
No. The correct answer for each capture comes from the configuration we set and the VPN endpoint's own
`swanctl` or `pluto` log, never from TunnelScope's output.

**Q: Can I trust the report later?**
Yes. The evidence ledger hash-chains every finding and verdict to the capture's SHA-256, and
`tunnelscope ledger-verify` detects any later change.

## About deployment

**Q: What does it need to run?**
One analyst machine or server inside the organisation, Python and tshark. It needs no VPN keys and
decrypts nothing. It is open source under Apache 2.0, so there is no licence cost.

**Q: Does it work with other vendors?**
The signals it uses are defined by the IPsec and IKE protocols, and it has been checked on three
independent implementations: strongSwan, Libreswan and OpenBSD iked.

## The one-sentence close
"TunnelScope tells you what your IPsec tunnels actually negotiated, whether they are post-quantum or
fell back to classical, which standard they meet, and then helps you fix what does not."
