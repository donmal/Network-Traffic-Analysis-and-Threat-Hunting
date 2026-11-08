# 02 - TCP Reconnaissance & Session Hijacking Investigation

## Executive Summary

This investigation examined two network packet captures from Hack The Box Academy's *Intermediate Network Traffic Analysis* training: 
`nmap_syn_scan.pcapng` and `TCP-hijacking.pcap`. 

Using Wireshark, the analysis quantified TCP packets with the ACK flag set and inspected a plaintext Telnet conversation to identify the username visible in the captured session.

The first capture contained **429 ACK-flagged packets out of 848 total packets (50.6%)**; the second revealed the username **`administrator`** in a followed TCP stream.

These findings demonstrate packet-level triage and session reconstruction, but neither the ACK count nor the username alone proves malicious scanning or successful session hijacking.

## Investigation Objectives

- Examine TCP flag behavior in a capture associated with SYN scanning.
  
- Quantify packets carrying the TCP ACK flag and validate the result using Wireshark statistics.
  
- Inspect a separate TCP capture containing Telnet communication.
  
- Reconstruct application-layer content using **Follow TCP Stream**.
  
- Identify the username visible in the plaintext Telnet session.
  
- Distinguish directly observed evidence from attack hypotheses.
  
- Outline practical network detection and response opportunities.

## Background

### TCP Handshake and Reconnaissance

A normal TCP connection is generally established through **SYN → SYN/ACK → ACK**. 

The ACK flag acknowledges received sequence data and is also present in many established-session packets, as well as some reset packets. 

SYN scanning typically probes ports without completing full connections; interpretation requires considering the **direction, sequence, flags, ports, and timing**, rather than treating all ACK-flagged packets as malicious.

### TCP Resets and Session Hijacking

TCP RST packets abruptly terminate or reject connections. 

TCP session hijacking involves an unauthorized party interfering with or taking over an existing TCP session. 

Evidence of hijacking generally requires more than readable session contents: analysts should investigate unexpected sequence behavior, competing senders, anomalous resets, and other corroborating indicators.

### Telnet Exposure

Telnet commonly transports interactive terminal content without encryption. 

A packet capture may therefore reveal terminal output, typed commands, and sometimes usernames or credentials.

The visibility of `administrator` in this captured session demonstrates **plaintext session exposure**, not necessarily that the user authenticated successfully or that an attacker hijacked the session.

### MITRE ATT&CK Mapping

| Technique | ATT&CK ID | Relevance |
|---|---|---|
| Network Service Discovery | T1046 | Context for TCP port probing; not established solely by the ACK count |
| Network Sniffing | T1040 | Plaintext Telnet traffic can expose session information to a network observer |
| Adversary-in-the-Middle | T1557 | Possible conceptual relationship to session interception; not confirmed in the provided evidence |

## Data Sources and Tools

| Source / Tool | Purpose |
|---|---|
| `nmap_syn_scan.pcapng` | TCP flag and packet-count analysis |
| `TCP-hijacking.pcap` | Telnet stream inspection |
| Wireshark | Display filtering, protocol statistics, TCP stream reconstruction |
| Parrot OS terminal | Opening local capture files |
| Hack The Box Academy | Source of the training environment and captures |

## Investigation Scope

Two **separate** captures were analyzed. 

The investigation does not assert that their traffic belongs to one intrusion sequence.

Scope was limited to the reported TCP ACK count and visible Telnet username, supplemented by detection-oriented interpretation. 

The underlying PCAP files were not independently supplied for reanalysis; reported findings are based on the provided lab notes and screenshots.

## Investigation Methodology

1. Open `nmap_syn_scan.pcapng` in Wireshark.
   
2. Apply `tcp.flags.ack == 1` to isolate ACK-flagged TCP packets.
   
3. Compare the filtered packet count with the full capture count and inspect **Statistics → Protocol Hierarchy**.
   
4. Open `TCP-hijacking.pcap` as a separate investigation artifact.
   
5. Locate Telnet traffic and select **Follow → TCP Stream**.
   
6. Read the reconstructed plaintext terminal conversation and record the username shown.
   
7. Document the evidence and avoid overinterpreting the two investigation findings.

## Investigation Artifacts

| Artifact | Type | Analytical purpose |
|---|---|---|
| `nmap_syn_scan.pcapng` | PCAPNG | TCP ACK-flag measurement |
| `TCP-hijacking.pcap` | PCAP | Telnet stream review |
| `192.168.10.1` → `192.168.10.5` | Observed traffic direction in first screenshot | Context for visible TCP packets |
| `administrator` | Plaintext session observable | Username displayed in Telnet stream |

## Investigation #1 — TCP Handshake Abnormalities

### Purpose

Determine how many packets in the SYN-scan training capture have the TCP ACK flag set.

### Open the Capture

```bash
wireshark Intermediate_Network_Traffic_Analysis/nmap_syn_scan.pcapng
```

If working with the HTB-provided resource archive, obtain it through the module's authorized Resources section and extract it locally before opening the capture.

### Wireshark Display Filter

```wireshark
tcp.flags.ack == 1
```

This selects **any** TCP packet with ACK set, including `ACK`, `PSH, ACK`, `SYN, ACK`, and `RST, ACK` combinations. It does **not** mean that all matched packets are standalone ACKs or evidence of a scan.

### Evidence — ACK-Flagged Traffic

Figure 1 — Wireshark display filter isolating ACK-flagged TCP traffic, including visible RST, ACK packets.

The supplied screenshot shows TCP traffic from `192.168.10.1` to `192.168.10.5`, including several packets labeled `RST, ACK`, with the ACK filter applied.

### Statistics Validation

Open **Statistics → Protocol Hierarchy** while the display filter is active.

Figure 2 — Wireshark Protocol Hierarchy displaying 429 ACK-flagged packets in the filtered capture.

### Results

| Field | Observed value |
|---|---|
| Capture | `nmap_syn_scan.pcapng` |
| Total captured packets | **848** |
| Filter | `tcp.flags.ack == 1` |
| Matching packets | **429** |
| Share of total capture | **50.6%** |
| Example visible flag combination | `RST, ACK` |

**Finding:** The capture contains **429 packets with the ACK flag set**. 

The count is verified by the Wireshark status bar and Protocol Hierarchy view. 

This statistic alone does not establish the number of SYN probes, the number of targeted ports, or whether a scan succeeded.

## Investigation #2 — TCP Session and Telnet Analysis

### Purpose

Inspect the Telnet communication in `TCP-hijacking.pcap` and identify the username visible in the reconstructed TCP stream.

### Open the Capture

```bash
wireshark Intermediate_Network_Traffic_Analysis/TCP-hijacking.pcap
```

### Wireshark Display Filter

```wireshark
telnet
```

A supplementary filter for standard Telnet traffic is:

```wireshark
tcp.port == 23
```

Port 23 is conventional, but Telnet may run on other ports. 

The protocol decoder and stream content should be checked rather than relying only on the port number.

### Follow the Conversation

Select a Telnet packet, then **right-click → Follow → TCP Stream**. This reconstructs the selected bidirectional TCP conversation and makes readable application data easier to inspect.

Figure 3 — Wireshark Follow TCP Stream functionality used to reconstruct the Telnet conversation.

### Evidence — Reconstructed Telnet Stream

Figure 4 — Reconstructed plaintext Telnet session displaying the administrator username and terminal activity.

The screenshot visibly contains the prompt text `administrator@kali` and the command `uname -a`, followed by Linux system information. 

Wireshark uses different colors for the two directions of the stream; these colors represent directions, **not intrinsically malicious versus legitimate traffic**.

### Results

| Field | Observed value |
|---|---|
| Capture | `TCP-hijacking.pcap` |
| Protocol | Telnet over TCP |
| Analysis technique | Follow TCP Stream |
| Username visible in stream | **`administrator`** |
| Example visible command | `uname -a` |
| Session content | Readable terminal text |

**Finding:** The username **`administrator`** is visible in the reconstructed Telnet session. 

The screenshot supports the username attribution to displayed terminal text, but does not independently establish whether a login was successful, whether credentials were captured, or whether session hijacking occurred.

## Investigation Findings

| Investigation | Evidence | Supported conclusion | Limitation |
|---|---|---|---|
| TCP Handshake Abnormalities | ACK filter and Protocol Hierarchy | 429 of 848 packets carry ACK | ACK prevalence alone does not prove reconnaissance |
| Telnet Session Inspection | Follow TCP Stream screenshot | `administrator` appears in readable terminal content | No direct proof of hijacking or credential theft |

The two investigations collectively demonstrate **transport-layer filtering** and **application-layer session reconstruction**, two complementary SOC network-analysis skills.

## Detection Logic

### Indicator #1 — Suspicious TCP Scanning Patterns

Monitor for unusually broad or rapid SYN probes, multiple destination ports, repeated resets, and short-lived connections. Investigate with filters such as:

```wireshark
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

```wireshark
tcp.flags.reset == 1
```

Correlate source/destination pairs, destination-port diversity, timing, and any relevant firewall, IDS, or Zeek connection logs. **Neither filter alone is a definitive malicious-activity signature.**

### Indicator #2 — Unexpected Telnet Communication

Look for Telnet sessions involving sensitive hosts, administrative accounts, unusual source addresses, or unexpected time windows. Use:

```wireshark
telnet || tcp.port == 23
```

Where policy allows, review exposed commands or login material and correlate with endpoint and authentication records. 

Avoid publishing actual passwords or private session data.

### Indicator #3 — Potential TCP Session Interference

Investigate unexplained bursts of RST packets, inconsistent TCP sequence/acknowledgment patterns, and abrupt changes in traffic behavior. 

Confirm against surrounding packets and other telemetry before attributing session hijacking.

**Detection engineering consideration**: TCP flag anomalies should be correlated with connection state, sequence numbers, timing, and endpoint telemetry. This reduces false positives caused by legitimate connection resets and normal TCP behavior.

## MITRE ATT&CK Mapping — Investigation Relevance

| Tactic | Technique | ATT&CK ID | Status in this investigation |
|---|---|---|---|
| Discovery | Network Service Discovery | T1046 | Contextual mapping for SYN-scan dataset; not independently confirmed from ACK count |
| Credential Access | Network Sniffing | T1040 | Relevant to exposure of plaintext Telnet data; attacker sniffing not confirmed |
| Credential Access / Collection | Adversary-in-the-Middle | T1557 | Conceptual mapping to hijacking scenarios; no demonstrated MITM in screenshots |

## IOC / Observable Summary

These are **investigation observables**, not verified malicious IOCs.

| Observable type | Value |
|---|---|
| PCAP | `nmap_syn_scan.pcapng` |
| TCP ACK filter | `tcp.flags.ack == 1` |
| ACK-flagged packet count | 429 |
| Total packet count | 848 |
| Example IP pair | `192.168.10.1` → `192.168.10.5` |
| PCAP | `TCP-hijacking.pcap` |
| Protocol | Telnet |
| Username shown | `administrator` |
| Reconstructed command | `uname -a` |

## Lessons Learned

| Lesson | Description |
|---|---|
| TCP Flag Context | ACK is common in normal TCP traffic and must be interpreted alongside other flags and connection behavior. |
| Statistics Cross-Check | Wireshark Protocol Hierarchy provides an independent way to validate the count displayed after filtering. |
| Stream Reconstruction | Follow TCP Stream is effective for understanding bidirectional application conversations. |
| Plaintext Protocol Risk | Telnet can expose sensitive terminal activity to network observers. |
| Evidence Discipline | A suspicious filename or lab title is not itself proof of successful exploitation or session hijacking. |
| Detection Correlation | Network findings become more reliable when combined with timing, host logs, and IDS/EDR telemetry. |

## Conclusion

This investigation used Wireshark to analyze two distinct network captures. In `nmap_syn_scan.pcapng`, **429 of 848 packets** matched the TCP ACK flag filter. In `TCP-hijacking.pcap`, following a Telnet TCP stream revealed the username **`administrator`** and readable terminal content.

Together, the investigations demonstrate essential SOC capabilities in TCP flag analysis, protocol statistics, and plaintext session inspection. 

Further packet-level and cross-source evidence would be required to establish active reconnaissance or a successful TCP session hijacking incident.


