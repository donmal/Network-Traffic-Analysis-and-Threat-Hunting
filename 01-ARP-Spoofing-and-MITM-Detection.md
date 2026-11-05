# 01 - ARP Spoofing, Scanning & MITM Detection

## Executive Summary

This investigation examined Address Resolution Protocol (ARP) traffic in an HTB Academy network capture using Wireshark. The investigation combined two complementary exercises: source-specific ARP request analysis and chronological gateway-IP mapping analysis. Filtering identified **507 ARP requests among 994 captured packets (51.0%)** from one MAC address. A second filter identified the earliest displayed ARP reply associating `192.168.10.1` with MAC `2c:30:33:e2:d5:c3`. The visible traffic included requests for multiple destination IPv4 addresses. These observations support further investigation of possible ARP scanning or abnormal address resolution; they do **not**, by themselves, confirm ARP poisoning or a successful man-in-the-middle (MITM) attack.

## Investigation Objectives

- Isolate ARP requests (opcode `1`) from the supplied source MAC address.
- Quantify matching packets and document reproducible Wireshark filtering.
- Identify the earliest observed ARP reply mapping for gateway IP `192.168.10.1`.
- Examine evidence of duplicate/conflicting gateway-IP claims without presuming successful MITM.
- Identify indicators that merit further ARP spoofing or reconnaissance investigation.
- Separate verified packet-level observations from attack hypotheses.
- Recommend additional validation and defensive monitoring measures.

## Background

### ARP and Normal Network Behavior

ARP resolves IPv4 addresses to MAC addresses on a local network. ARP requests typically broadcast a question such as “Who has 192.168.10.1?”; ARP replies provide a mapping. Normal hosts use ARP to reach local peers and gateways.

### ARP Spoofing and MITM

ARP spoofing or poisoning involves misleading hosts about an IP-to-MAC mapping, potentially diverting traffic through an attacker-controlled device. Suspicious patterns can include unsolicited ARP replies, conflicting mappings for a gateway IP, and unexpected changes to hosts’ ARP caches. A high request count alone is not proof of spoofing.

### MITRE ATT&CK Mapping

| Technique | ATT&CK ID | Relevance |
|---|---|---|
| Adversary-in-the-Middle: ARP Cache Poisoning | T1557.002 | Relevant threat hypothesis; **not confirmed** by the observed request count |
| Network Service Discovery | T1046 | Possible explanation for broad target-IP probing; **not confirmed** as malicious scanning |

## Data Sources & Tools

| Source / Tool | Purpose |
|---|---|
| `ARP_Poison.pcapng` | HTB Academy packet capture used for analysis |
| Wireshark | Inspect ARP packets and apply display filters |
| Parrot OS terminal | Extract lab archive and launch the capture |
| Wireshark packet list and status bar | Validate matching frames and packet counts |

## Investigation Scope

The exercise focused on ARP **requests** sent by Ethernet source MAC `08:00:27:53:0c:ba` within one supplied capture. The evidence available for this report comprises the analyst’s notes and six screenshots. A second exercise examined ARP replies advertising `192.168.10.1`. The screenshot shows duplicate-IP warnings and different sender MAC addresses, but does not prove which device is authorized or that traffic interception succeeded.

## Investigation Methodology

1. Extract the HTB-provided capture archive in the lab environment.
2. Open `ARP_Poison.pcapng` in Wireshark.
3. Filter for ARP requests using opcode `1`.
4. Narrow the results to the specified Ethernet source MAC.
5. Read the filtered packet count from the Wireshark status bar.
6. Examine the visible target IP distribution and identify what additional evidence would be needed to substantiate poisoning or MITM.
7. Filter ARP replies advertising `192.168.10.1`, sort by frame order and identify the first sender MAC.
8. Review later replies for inconsistent IP-to-MAC claims and consider legitimate explanations.

## Investigation Artifacts

| Artifact | Value |
|---|---|
| Capture filename | `ARP_Poison.pcapng` |
| Investigated MAC address | `08:00:27:53:0c:ba` |
| ARP request opcode | `1` |
| Network context visible in packet list | `192.168.10.x` targets |
| Gateway-IP mapping investigated | `192.168.10.1` |
| First observed ARP reply sender MAC | `2c:30:33:e2:d5:c3` |

The original PCAP is **not included** in this repository; access it through the relevant HTB Academy module subject to its terms.

## Investigation Commands & Wireshark Filters

### Preparation — Open the Capture

The capture was extracted from the module resources and opened locally:

```bash
unzip pcap_files.zip
wireshark Intermediate_Network_Traffic_Analysis/ARP_Poison.pcapng
```

![Terminal showing extraction of the module capture files](images/01-pcap-extraction.png)

*Figure 1 — Lab capture archive extraction in the Parrot terminal.*

### Filter #1 — Identify ARP Requests

**Purpose:** Limit the display to ARP request frames rather than replies.

```wireshark
arp.opcode == 1
```

### Filter #2 — Attribute Requests to the Source MAC

**Purpose:** Identify ARP requests transmitted by the specified Ethernet MAC address.

```wireshark
arp.opcode == 1 && eth.src == 08:00:27:53:0c:ba
```

- `arp.opcode == 1` selects ARP requests.
- `eth.src == 08:00:27:53:0c:ba` selects Ethernet frames from the specified source.
- `&&` requires both conditions to match.

![Wireshark showing ARP requests from the investigated MAC](images/02-arp-filter.png)

*Figure 2 — Combined ARP opcode and source MAC display filter.*

### Results

| Field | Observed value |
|---|---|
| Total captured packets | **994** |
| Packets displayed after combined filter | **507** |
| Percentage of capture displayed | **51.0%** |
| Packet type | ARP requests |
| Source Ethernet MAC | `08:00:27:53:0c:ba` |

![Wireshark status bar showing 994 total and 507 displayed packets](images/03-arp-count.png)

*Figure 3 — Wireshark status bar confirms 507 matching frames (51.0% of the capture).*

### Filter #3 — Identify ARP Replies for the Gateway IP

**Purpose:** Determine which MAC address was **first observed** claiming the IP address `192.168.10.1` in ARP replies. This is a chronological finding, not a determination of the legitimate gateway.

```wireshark
arp.opcode == 2 && arp.src.proto_ipv4 == 192.168.10.1
```

- `arp.opcode == 2` selects ARP replies.
- `arp.src.proto_ipv4 == 192.168.10.1` selects replies whose ARP **sender protocol address** is the investigated IP.
- Inspect the earliest matching packet by **frame number** (ascending); don't assume the latest mapping is the original.

![Terminal showing capture archive extraction](images/04-arp-reply-investigation.png)

*Figure 4 — Module capture files available in the Parrot terminal.*

![Wireshark capture opened for ARP analysis](images/05-arp-reply-investigation.png)

*Figure 5 — Original capture opened before applying the reply filter.*

![Wireshark showing filtered ARP replies and the first gateway mapping](images/06-arp-reply-investigation.png)

*Figure 6 — Filtered ARP replies for `192.168.10.1`. The earliest displayed matching frame is frame 513, reporting `192.168.10.1 is at 2c:30:33:e2:d5:c3`.*

### Results — Gateway-IP Mapping Investigation

| Field | Observed value |
|---|---|
| Capture | `ARP_Poison.pcapng` |
| Gateway IP investigated | `192.168.10.1` |
| ARP reply filter | `arp.opcode == 2 && arp.src.proto_ipv4 == 192.168.10.1` |
| Earliest matching frame shown | `513` |
| First advertised MAC for the IP | **`2c:30:33:e2:d5:c3`** |
| Matching replies shown | `261` of `994` total packets (`26.3%`) |
| Additional visible observations | Later replies advertise a different MAC, `08:00:27:53:0c:ba`, for the same IP; Wireshark shows duplicate-IP-use warnings |

**Interpretation:** The capture visibly contains inconsistent ARP sender-MAC claims for `192.168.10.1`, a stronger potential ARP-poisoning indicator than request volume alone. Still, the screenshot cannot establish which MAC is legitimate, whether these replies were accepted into a victim's ARP cache, or whether a MITM occurred. Verify gateway ownership and endpoint ARP-cache changes before asserting compromise.

## Investigation Findings

The capture contains **507 ARP requests** originating from `08:00:27:53:0c:ba`, representing **51.0%** of the 994 packets. The visible packet list shows ARP requests targeting multiple `192.168.10.x` addresses. This is a concrete indicator of repeated address-resolution activity from one source and is worth investigating in context.

The ARP reply investigation additionally identified **`2c:30:33:e2:d5:c3` as the first observed MAC associated with `192.168.10.1`** (frame 513 in the filtered view). Subsequent visible replies claim the same IP using another MAC, and Wireshark displays duplicate-IP warnings. This supports an **ARP mapping conflict / possible poisoning** hypothesis, but not confirmed interception.

**Evidence limitation:** The packet count and screenshots do not establish whether the source was malicious, which of the competing ARP mappings was authoritative, or whether a victim was redirected. A rate-based conclusion would require checking the full capture timestamps and a baseline.

## Detection Logic

### Indicator #1 — Repeated ARP Requests from One Source

Monitor per-source ARP request volumes over defined time windows and compare with expected local network behavior. A large number of requests is a **triage signal**, not a definitive alert in isolation.

### Indicator #2 — Broad Target-IP Distribution

Look for a single source querying many distinct IPs in a short interval. Review whether the behavior is consistent with legitimate inventory, troubleshooting, or network scanning.

### Indicator #3 — Conflicting IP-to-MAC Mappings

For a stronger ARP poisoning hypothesis, inspect ARP replies (`arp.opcode == 2`) for multiple MAC addresses claiming the same sensitive IP, particularly the default gateway. Correlate with gateway and endpoint ARP tables.

### Defensive Validation and Response

- Correlate suspicious activity with DHCP leases, switch inventory and endpoint ownership.
- Review switch counters and timestamps to establish frequency and scope.
- Enable DHCP Snooping and Dynamic ARP Inspection where supported and appropriately configured.
- Investigate or isolate a source only when corroborating evidence supports malicious behavior.

## IOC / Observable Summary

| Observable | Value / interpretation |
|---|---|
| Source MAC | `08:00:27:53:0c:ba` — lab-specific investigated source, **not** a universal malicious IOC |
| ARP opcode | `1` — request |
| Matching packets | `507` |
| Total capture packets | `994` |
| Target address pattern | Multiple `192.168.10.x` addresses visible |
| First observed mapping for `192.168.10.1` | `2c:30:33:e2:d5:c3` (lab observation) |
| Competing MAC claim for same IP | `08:00:27:53:0c:ba` visible in later replies |
| Duplicate-IP warning | Visible in Wireshark |
| Confirmed forged gateway mapping | **Not established** |
| Confirmed MITM interception | **Not established** |

## Lessons Learned

| Lesson | Description |
|---|---|
| Protocol-level filtering | Combining ARP opcode and Ethernet source conditions isolates a precise traffic subset. |
| Evidence-based reporting | A packet count is an observed fact, not automatic proof of an attack. |
| Anomaly validation | ARP request rates, target diversity and reply consistency must be interpreted together. |
| Chronological analysis | The first observed mapping can differ from later claims; inspect frame order rather than assuming the current mapping. |
| Conflicting claims | Duplicate-IP warnings strengthen suspicion but require validation against the real gateway MAC and host ARP caches. |
| SOC correlation | Endpoint ARP tables, DHCP and switch evidence improve confidence in ARP poisoning investigations. |

## Conclusion

Wireshark analysis isolated **507 ARP request frames** from MAC `08:00:27:53:0c:ba` in a 994-packet capture. The result demonstrates reproducible packet filtering, source attribution and anomaly triage. The earliest observed ARP reply mapped `192.168.10.1` to `2c:30:33:e2:d5:c3`; later replies included a competing MAC claim and duplicate-IP warnings. These observations warrant follow-up for possible ARP poisoning, but **successful MITM interception was not confirmed** by the available evidence. A complete investigation would inspect ARP replies, IP-to-MAC changes, timing and corroborating host/network telemetry.

## Attribution & Reproducibility

Based on the author’s work in Hack The Box Academy’s *Intermediate Network Traffic Analysis* module. The original lab capture is not redistributed. This report includes the analyst’s investigation steps, observations and screenshots; readers with authorized access to the module resources can reproduce the filters, counts and first-observed mapping.

