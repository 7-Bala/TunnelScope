# 13 — Mentor feedback review: "go application-oriented" (DLP, paper leaks, defence, cloud)

**Date:** 2026-09-18 · **Status:** analysis only, no scope change made · **Author:** Claude, for Bala

**What this is.** After a conversation with the mentor, the gist was: make TunnelScope more
application-oriented; use it to prevent data loss between organisations; stop India's exam paper
leaks; sell it to education, defence and other institutions, not just government; let defence use
it to share data securely; and think about "cloud" and "private cloud (local)". This document
(1) explains the terms, (2) tests each point against what TunnelScope actually does and against
public evidence, and (3) recommends what to keep, what to reframe and what to drop.

Confidence tags follow the project convention: `[FACT]` verified from a primary or strong source,
`[STRONG]` well supported, `[INFER]` my reasoning, `[HYP]` untested.

---

## 0. The verdict in one table

| # | Mentor's point | Verdict | One-line reason |
|---|---|---|---|
| M1 | Be more application-oriented | **Right. Do it.** | Juries score impact and a clear user. Our pitch today is technology-first. |
| M2 | Use it to prevent data loss (DLP) between organisations | **Wrong as stated. Partly right if reworded.** | TunnelScope can't see file contents, because the tunnel encrypts them. It *can* stop one kind of loss: data being read in transit because the tunnel is weak. |
| M3 | Stop paper leaks in India | **Wrong. Don't say it to a jury.** | The documented leaks were physical and insider leaks, plus remote-access cheating at exam centres. None of them went through a weak IPsec tunnel. |
| M4 | Not just government: education, defence, other institutions | **Partly right.** | Any organisation with site-to-site IPsec is a user. Defence and banks fit well. Colleges fit poorly. |
| M5 | Defence can use it to share data securely | **Right, with one important correction.** | TunnelScope doesn't *share* data. It *proves the channel used for sharing is safe*, including against future quantum attacks. This is our strongest application. |
| M6 | Cloud / private cloud (local) | **Right, and the most useful point he made.** | It matters twice: where TunnelScope runs (locally, never as a public web service), and what it audits (the IPsec tunnels that connect offices to the cloud). |

**Bottom line:** the mentor is right about the *direction* (show who uses it and why it matters)
and wrong about *two of the examples* (DLP and paper leaks). Change **the story**, not **the
product**. If we pivot the product toward DLP or exam security, we leave the NTRO problem statement
we're judged against, and we break the honesty that makes this project different.

---

## 1. First, what TunnelScope actually is (so the rest makes sense)

A useful picture:

> Organisations send sensitive data to each other through **armoured trucks** (IPsec VPN tunnels).
> TunnelScope is **the inspector who checks the trucks**: are the locks strong? Is the armour
> thin? Will the lock hold against tomorrow's tools (quantum computers)? Did someone quietly swap
> in a weaker lock (downgrade)? What can a bystander learn just by watching the truck's size and
> schedule (metadata leakage)?
>
> TunnelScope is **not a guard who opens the truck and checks what's inside.** It can't open the
> truck, and that's the whole point of the armour.

What the repo proves today `[FACT]` (see `experiments/RESULTS.md`, `build/E2E-VALIDATION.md`):

- It reads IKE/ESP captures and reports a posture: cipher family (narrowed to a candidate set),
  whether PFS is on (EXP-03), whether post-quantum ML-KEM was offered or selected (EXP-04),
  whether there's a downgrade pattern, a known strongSwan CVE pattern (EXP-09), rekey cadence, and
  what the traffic sizes and timing leak.
- It judges each finding against a named standard: `rules/disa-vpn-srg-v2r6.yaml`,
  `rules/rfc8247-ikev2.yaml`, `rules/dst-nqm-pq.yaml`.
- It says UNKNOWN when something can't be seen. AES-128 and AES-256 can't be told apart from the
  wire, and that's proven (EXP-02).
- It runs **locally**: `tunnelscope serve` binds to 127.0.0.1 only and deletes uploads after
  analysis (T-059).

What it **cannot** do, and no amount of AI changes this: read the *contents* of the tunnel. That
single fact decides most of the verdicts below.

---

## 2. The terms the mentor used, explained

### 2.1 Data Loss Prevention (DLP)

**DLP** is a product category that stops sensitive *content* from leaving an organisation. Examples:
blocking an email that carries an Aadhaar number, stopping a file marked "SECRET" from going to a
USB drive, or flagging an upload of a question paper to Google Drive.

DLP works by **looking at the content itself**. That's why it lives in exactly three places:

| Where DLP runs | How it sees content | Examples |
|---|---|---|
| **On the endpoint** (laptop or PC agent) | Before encryption, on the device | Microsoft Purview endpoint DLP, Forcepoint, Symantec DLP |
| **At a decrypting gateway** | The organisation's proxy decrypts TLS, inspects, re-encrypts | Secure web gateways, email gateways |
| **In the cloud app** (CASB) | Through the cloud service's API | Scanning files already in OneDrive or Drive |

**Why this matters for us `[FACT]`:** a DLP system has to be *before* encryption or *break* the
encryption. TunnelScope sits on the wire, *after* IPsec has encrypted everything. By design it can't
tell whether an ESP packet carries a question paper or a cat video. So "TunnelScope as DLP" is
technically impossible, not just hard.

### 2.2 Cloud: public, private, hybrid, community, and "local"

| Term | Plain meaning | Who owns the hardware | Everyday analogy |
|---|---|---|---|
| **Public cloud** | Rent computers in someone else's data centre, over the internet. Many customers share it. | AWS, Azure, Google Cloud, Indian providers | Staying in a hotel |
| **Private cloud** | Cloud-style self-service computing used by **one** organisation only | Usually the organisation itself (in its own building). Sometimes a provider runs an isolated slice | Owning your own house |
| **On-premise ("on-prem", "local")** | The software runs on the organisation's own machines, in its own building | The organisation | Cooking at home |
| **Air-gapped** | On-prem with **no internet connection at all** | The organisation | A room with no doors to the outside |
| **Hybrid cloud** | Some systems on-prem, some in the public cloud, **joined by a secure link, very often an IPsec VPN** | Both | A house plus a rented storage unit, with a locked road between them |
| **Community / government cloud** | Cloud reserved for one community, e.g. Indian government bodies | Provider, under government rules | A gated staff colony |

When the mentor said **"private cloud (local)"**, he most likely meant **on-premise deployment**:
the tool runs inside the organisation, and captured traffic never leaves the building. `[INFER]`

**One naming trap to know about `[STRONG]`:** in MeitY's GI Cloud (MeghRaj) programme, "private
cloud" means *a logically isolated environment inside a provider's cloud*, not "in your own
building". The fully government-only option is called *community cloud*. If a jury member is from
government IT, "private cloud" may mean something different to them than to the mentor. Say
**"on-premise / air-gapped"** when you mean "runs in their own building".

**SaaS vs self-hosted.** *SaaS* ("software as a service") means we would host TunnelScope on the
internet and customers would upload captures to us. *Self-hosted* means the customer runs it
themselves. For NTRO and defence, **only self-hosted, preferably air-gapped, is acceptable**,
because a packet capture of a defence network is itself sensitive intelligence. `[INFER, high
confidence]`

---

## 3. Point-by-point validation

### M1 — "Be more application-oriented" → **Right**

`[INFER, high confidence]` Our current material (pitch deck, README) leads with *how* it works:
tiers, observability, length signatures. A jury remembers **who got hurt and who gets saved**. The
research already names four real users (research/03, §1): VPN engineer, compliance auditor,
pentester, SOC analyst. But the pitch never tells a story from one of them.

**Honest caveat:** "application-oriented" means *showing the use*. It doesn't mean *inventing
uses the tool doesn't have*. Two of the mentor's own examples (M2, M3) fall into that trap.

### M2 — "Prevent data loss between organisations" → **Wrong as stated, partly right reworded**

**Why it's wrong as stated:** see §2.1. DLP needs content. TunnelScope never has content. Also, DLP
is a mature, crowded market (Microsoft, Broadcom/Symantec, Forcepoint and others). A hackathon
prototype won't beat them, and a jury knows that.

**What's actually true (this is the rewording to use):** data is lost *in transit* in three ways
TunnelScope directly addresses:

1. **The tunnel is weak today.** Old DH groups, SHA-1, no PFS. An attacker who records the traffic
   has a realistic path to reading it. TunnelScope flags these against DISA/RFC 8247.
   `[FACT: implemented]`
2. **The tunnel will be weak tomorrow ("harvest now, decrypt later").** An adversary records
   encrypted traffic today and decrypts it once quantum computers can break classical key exchange.
   TunnelScope checks whether PQ key exchange (ML-KEM) was offered, whether it was selected, and
   whether someone forced it down. `[FACT: EXP-04, rule dst-nqm-pq]`
3. **The tunnel leaks through its shape.** Even without decryption, packet sizes and timing reveal
   what kind of traffic is inside. TunnelScope measures that exposure (metadata-leakage module,
   EXP-05). `[FACT: implemented; strength of signal per EXP-05]`

**Honest phrase:** *"TunnelScope prevents data exposure in transit between organisations. It is
not a DLP product; it checks the channel that DLP-protected data travels through."*

**Tempting idea to avoid:** "detect exfiltration from unusual tunnel volume using AI." Our own
research (memory finding 4, research/04) showed that ML on encrypted traffic performs far worse
than published papers claim, and a volume spike can't be told apart from a legitimate backup.
Don't add it.

### M3 — "Stop paper leaks in India" → **Wrong. Don't claim it.**

This is the point to be most honest about, because a jury member *will* ask: *"Which real leak
would TunnelScope have stopped?"* Right now the honest answer is **none**.

**How the major leaks actually happened `[FACT]`:**

- **NEET-UG 2024.** Question-paper trunks reached Oasis Public School, Hazaribagh, on exam morning.
  The principal and vice-principal let the mastermind into the room, and he opened the trunks. The
  paper was photocopied and solved by a group of medical students, and CBI identified 144
  candidates who paid for it. This was a **physical, insider** leak.
  ([Wikipedia summary of CBI findings](https://en.wikipedia.org/wiki/2024_NEET_controversy),
  [Careers360](https://news.careers360.com/neet-paper-leak-case-cbi-reveals-collusion-between-oasis-school-principal-vice-principal-mastermind))
- **Online (computer-based) exams.** Delhi Police busted gangs that installed **disguised
  remote-access software** (TeamViewer-style) on exam-centre machines, so outside "solvers" could
  answer for candidates, including in SSC exams.
  ([Deccan Herald](https://www.deccanherald.com/india/online-exam-solving-module-busted-six-arrested-delhi-police-1068147.html),
  [Tribune](https://www.tribuneindia.com/news/delhi/delhi-police-bust-inter-state-paper-leak-gang-arrest-4-228048))
- **The law's own answer.** The Public Examinations (Prevention of Unfair Means) Act, 2024
  (in force since 21 June 2024) lists CCTV, biometrics and jammers as its technical safeguards.
  VPN auditing isn't mentioned.
  ([India Code](https://www.indiacode.nic.in/handle/123456789/20100?view_type=browse),
  [Wikipedia](https://en.wikipedia.org/wiki/Public_Examinations_(Prevention_of_Unfair_Means)_Act,_2024))

**Why TunnelScope doesn't fit, even in theory `[INFER, high confidence]`:**

1. **The leaks happen at the endpoints, after decryption:** a trunk, a printer, a phone camera, a
   compromised exam PC. Even a perfect tunnel doesn't help once the paper is printed in a room with
   a corrupt insider.
2. **Remote-access cheating isn't IPsec.** Those tools use TLS or their own protocols. Detecting
   them is endpoint lockdown and network-policy work, a different product (and possibly a
   different SIH problem statement).
3. **"Harvest now, decrypt later" doesn't apply to exam papers.** A question paper is secret for
   hours or days. Nobody will wait ten years to decrypt it. This is the key contrast with defence
   (M5). The same capability that's *vital* for defence is *irrelevant* for exams.

**The one legitimate, small exam-related use `[INFER]`:** when an exam body sends encrypted papers
or results between its head office, regional centres and a cloud platform over IPsec, TunnelScope
can prove that channel is configured correctly. That's "we audited the pipe", not "we stopped
leaks". Mention it, if at all, as one line among several sectors, never as the headline.

**If the team feels strongly about exam integrity:** that's a *different project*. Our research
method would say: register it as a new hypothesis and check whether another SIH statement covers
it. Don't graft it onto SIH26160.

### M4 — "Education, defence and other institutions, not just government" → **Partly right**

`[INFER]` The real user is **anyone who runs site-to-site IPsec and has to prove it's secure**:

| Sector | Fit | Why |
|---|---|---|
| Defence, strategic, NTRO-type agencies | **Strong** | Long-lived secrets (HNDL matters), mandated PQ migration, can't use cloud tools |
| Banks and payment networks | **Strong** | Branch-to-DC IPsec everywhere, heavy audit burden |
| Critical infrastructure (power, telecom) | **Strong** | Named in the DST/NQM PQ mandate (research/07) |
| Government departments on hybrid cloud | **Good** | Office-to-cloud IPsec (see M6) |
| Hospitals, large enterprises | Moderate | Have IPsec, less audit pressure |
| Universities and colleges | **Weak** | Few site-to-site tunnels worth auditing, no budget or mandate |

**Brutal note:** "anyone can use it" is a weak pitch. Juries prefer *one* sharp user. Keep
NTRO/defence as the primary user (it's their problem statement) and list the rest as "also
applies to".

### M5 — "Defence orgs can share data securely" → **Right, with one correction**

**Correction:** TunnelScope doesn't *do* the sharing. IPsec does. TunnelScope **verifies** that the
sharing channel is secure, and keeps verifying it.

**Why this is our strongest application `[STRONG]`:**

- Defence data stays sensitive for decades, so **harvest-now-decrypt-later is a real threat**, and
  PQ readiness is the right question to ask.
- India's DST / National Quantum Mission task force calls for cryptographic inventory and
  downgrade prevention for critical systems by 2027 (research/07, `rules/dst-nqm-pq.yaml`).
  TunnelScope already produces a CycloneDX **CBOM** (cryptographic bill of materials), which is
  exactly an inventory artefact. `[FACT: T-033]`
- It works **passively, without keys**. An auditor can assess a link between two organisations
  without either one handing over configs or keys, which neatly answers the cross-organisation
  trust problem.

**Suggested story:** *"Two defence establishments exchange data over IPsec. Nobody can prove today
whether that link would survive a quantum adversary recording it. TunnelScope proves it, from a
capture, without touching either side's keys, and produces the inventory the 2027 mandate asks
for."*

### M6 — "Cloud / private cloud (local)" → **Right, and it opens two real angles**

**Angle A: where TunnelScope runs (deployment).** For NTRO and defence, the answer must be
**on-prem / air-gapped**. The good news `[FACT]`: we already built it that way. `tunnelscope serve`
is stdlib-only, binds to 127.0.0.1, and deletes uploads; the dashboard runs offline. What's missing
is only a **written deployment story**: an offline install bundle, no telemetry, no outbound
calls. That's a documentation task, not a product change.

**Angle B: what TunnelScope audits (hybrid-cloud tunnels). This one is a genuine new application.**
When a government office or bank connects to AWS, Azure or GCP, the standard link is a
**site-to-site IPsec VPN**. For example, AWS Site-to-Site VPN by default still *allows* SHA-1
integrity and DH group 2 among its accepted proposals, alongside strong options. The customer's
router decides what actually gets negotiated.
([AWS docs: tunnel options](https://docs.aws.amazon.com/vpn/latest/s2svpn/tunnel-configure.html))
Weak-but-allowed defaults are exactly what TunnelScope is built to catch. Also, all three
hyperscalers are MeitY-empanelled for government use
([MeitY GI Cloud](https://www.meity.gov.in/content/gi-cloud-meghraj)), so this is a real Indian
government scenario.

**Brutal caveat `[HYP]`:** we have **never tested TunnelScope on a capture of a real cloud VPN
tunnel**. Our lab is strongSwan / Libreswan / OpenBSD iked. Before we claim "audits your AWS/Azure
VPN", we need at least a lab reproduction: configure strongSwan with the proposal sets a cloud
gateway accepts, capture, and confirm the rules fire correctly. Until then, say "designed for" and
not "works with".

---

## 4. The risks of following the advice literally

1. **Leaving the problem statement.** SIH26160 is NTRO's IPsec analyzer statement, and it's
   evaluated against its own deliverables. A pivot to DLP or exam security scores poorly on "did
   you solve *this* problem", and the portal submission (T-046) already describes the IPsec tool.
2. **Overclaiming destroys our differentiator.** The whole project is built on *"we say what we
   can't see"* (UNKNOWN / NOT-OBSERVABLE as first-class results). Claiming to stop paper leaks
   contradicts that on stage, and a technical jury member can take it apart with one question.
3. **Time.** Submission steps are still pending (T-046). A new product direction now would
   endanger a finished, verified build (69/69 unit, 69/69 E2E).
4. **Crowded market.** DLP competes with mature commercial suites. PQ posture assessment for IPsec
   has, per our research (research/11), no direct competitor. Stay where we're unique.

---

## 5. Recommendation

**Keep the product. Rewrite the story around applications.**

**New one-line pitch (suggestion):**
> *"TunnelScope is the inspection instrument for the encrypted links organisations use to share
> sensitive data. It proves they are strong today and quantum-safe tomorrow, without ever
> decrypting them, and it runs entirely inside your own walls."*

**Application scenarios, ranked by how defensible they are:**

1. **Defence / strategic inter-site links:** PQ readiness, downgrade detection, CBOM for the 2027
   mandate. *(Already built.)*
2. **Hybrid-cloud interconnect audit:** government and banks linking offices to MeghRaj-empanelled
   clouds over IPsec. *(Needs one lab experiment before claiming.)*
3. **Compliance evidence for "encryption in transit":** the DPDP Rules require reasonable security
   safeguards, including encryption, for personal data
   ([DPDP Rule 6 text](https://www.dpdpa.com/dpdparules/rule6.html), secondary source).
   TunnelScope produces standard-referenced evidence for the transit part. *(Built; mapping to DPDP
   wording not yet written.)*
4. **Exam bodies' data links:** only as "audits the digital distribution channel", never as "stops
   paper leaks".

**Small, honest work that would back this up (proposed tasks, not started):**

| Proposed | What | Size |
|---|---|---|
| A | One "applications" slide and demo narrative using scenario 1 | Small; deck/doc only |
| B | `build/05-DEPLOYMENT-ONPREM.md`: air-gapped install, no outbound calls, data handling | Small |
| C | Pre-registered lab experiment: cloud-gateway-style proposal sets (incl. SHA-1 / DH2 allowed) → do the rules fire correctly? | Medium |
| D | Map rule outputs to DPDP "reasonable security safeguards" and CERT-In wording | Small–medium |

---

## 6. Questions to take back to the mentor

1. When you said "private cloud (local)", did you mean *on-premise deployment of our tool*, or
   *auditing organisations' links to the cloud*? (Both are good. They're different work.)
2. For paper leaks, which leak mechanism did you have in mind? The public cases we found were
   physical/insider leaks and remote-access cheating, which our tool can't see. Is there a
   digital-transmission case we missed?
3. Is it acceptable to keep NTRO/defence as the primary user and list other sectors as secondary?
4. Given submission is close, is this feedback for the **pitch** (story), or does he want a
   **product change** before the finals?

---

## 7. Glossary

- **IPsec:** a set of protocols that encrypt traffic between two networks or devices at the IP layer.
- **IKE (IKEv2):** the "handshake" in which two IPsec peers agree on algorithms and keys.
- **ESP:** the encrypted data packets that carry the actual traffic.
- **Site-to-site VPN:** a permanent IPsec tunnel joining two offices, or an office and a cloud.
- **PFS (Perfect Forward Secrecy):** fresh keys per session, so one stolen key doesn't unlock past traffic.
- **PQ / ML-KEM:** post-quantum key exchange, designed to resist future quantum computers.
- **HNDL (harvest now, decrypt later):** record encrypted traffic today, decrypt it years later.
- **Downgrade:** an attacker or misconfiguration pushes both sides to a weaker option than both support.
- **CBOM:** Cryptographic Bill of Materials, an inventory of which crypto is used where.
- **DLP:** Data Loss Prevention, products that inspect content to stop it leaving.
- **CASB:** Cloud Access Security Broker, DLP-like controls for cloud apps.
- **On-prem / air-gapped:** runs on your own machines / with no internet connection at all.
- **SaaS:** software someone else hosts for you over the internet.

## Sources

- NEET 2024: [Wikipedia (CBI findings summary)](https://en.wikipedia.org/wiki/2024_NEET_controversy), [Careers360](https://news.careers360.com/neet-paper-leak-case-cbi-reveals-collusion-between-oasis-school-principal-vice-principal-mastermind), [Tribune](https://www.tribuneindia.com/news/india/neet-paper-was-leaked-in-hazaribagh-cbi-643377)
- Remote-access exam cheating: [Deccan Herald](https://www.deccanherald.com/india/online-exam-solving-module-busted-six-arrested-delhi-police-1068147.html), [Tribune](https://www.tribuneindia.com/news/delhi/delhi-police-bust-inter-state-paper-leak-gang-arrest-4-228048)
- Public Examinations Act 2024: [India Code](https://www.indiacode.nic.in/handle/123456789/20100?view_type=browse), [Wikipedia](https://en.wikipedia.org/wiki/Public_Examinations_(Prevention_of_Unfair_Means)_Act,_2024)
- Paper leaks overview: [List of paper leaks in India](https://en.wikipedia.org/wiki/List_of_paper_leaks_in_India)
- Cloud VPN: [AWS Site-to-Site VPN tunnel options](https://docs.aws.amazon.com/vpn/latest/s2svpn/tunnel-configure.html), [Google Cloud VPN supported IKE ciphers](https://docs.cloud.google.com/network-connectivity/docs/vpn/concepts/supported-ike-ciphers)
- Government cloud: [MeitY GI Cloud (MeghRaj)](https://www.meity.gov.in/content/gi-cloud-meghraj), [AWS MeitY empanelment](https://aws.amazon.com/compliance/MeitY/)
- DPDP Rules: [Rule 6 (dpdpa.com)](https://www.dpdpa.com/dpdparules/rule6.html), secondary source; verify against the Gazette before quoting on a slide
- Internal: `research/03-DISCOVER-stakeholders.md`, `research/07-DISCOVER-pq-and-late-findings.md`, `research/11-EXISTING-SOLUTIONS-DEEP-DIVE.md`, `experiments/RESULTS.md`
