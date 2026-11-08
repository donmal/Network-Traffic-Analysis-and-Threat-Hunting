# Network Traffic Analysis — SOC Threat Hunting & Anomaly Detection
Write-up of Hack the Box Academy labs. Practice work.

**A five-part, hands-on network security investigation portfolio using Wireshark, packet captures, protocol analysis, and detection-oriented reasoning.**

## Executive Summary

This project documents five investigations developed from hands-on exercises in Hack The Box Academy's *Intermediate Network Traffic Analysis* module. It examines suspicious behavior across ARP, TCP, HTTP, DNS, ICMP, and Telnet traffic, translating individual packet-analysis exercises into structured SOC-style case studies.

The focus is on **what the evidence shows, how to reproduce the analysis, what it may indicate, and what additional telemetry would be required to confirm an attack**. Results are based on the supplied lab captures and notes; examples are not presented as production incidents.

## Investigation Objectives

- Establish a baseline understanding of normal protocol behavior and recognize anomalies.
  
- Use Wireshark display filters, protocol statistics, and stream reconstruction to isolate relevant evidence.
  
- Distinguish packet-level observations from inferred attacker intent or confirmed compromise.
  
- Develop practical detection and triage recommendations for SOC workflows.
  
- Communicate technical findings in reproducible, evidence-based reports.

## Project Structure

| Chapter | Investigation | Focus | Selected Findings |
|---|---|---|---|
| 01 | [ARP Spoofing, Scanning & MITM Detection](01-ARP-Spoofing-and-MITM-Detection/01-ARP-Spoofing-and-MITM-Detection.md) | ARP requests, IP-to-MAC mappings, spoofing indicators | 507 filtered ARP requests; first observed MAC for `192.168.10.1`: `2c:30:33:e2:d5:c3` |
| 02 | [TCP Reconnaissance & Session Hijacking](02-TCP-Reconnaissance-and-Session-Hijacking/02-TCP-Reconnaissance-and-Session-Hijacking.md) | TCP flags, connection resets, plaintext Telnet streams | 429 ACK-flagged packets; Telnet username `administrator` |
| 03 | [Web Attack Detection & HTTP Anomalies](03-Web-Attack-Detection-and-HTTP-Anomalies/03-Web-Attack-Detection-and-HTTP-Anomalies.md) | HTTP GET patterns, HTTP 400 responses, cookie exposure | 204 filtered GET requests; 7 HTTP 400 responses; cookie value observed in a request |
| 04 | [Covert Channels & Tunneling Detection](04-Covert-Channels-and-Tunneling-Detection/04-Covert-Channels-and-Tunneling-Detection.md) | Base64 decoding, layered encoding, Telnet over IPv6 | Decoded strings and plaintext Telnet stream artifacts |
| 05 | [SOC Network Anomaly Investigation](05-SOC-Network-Anomaly-Investigation/05-SOC-Network-Anomaly-Investigation.md) | DNS and ICMP anomaly triage | Lab classifications: DNS tunneling and ICMP tunneling |

## Tools & Data Sources

| Tool / Source | Role |
|---|---|
| **Wireshark** | Packet inspection, display filters, protocol hierarchy, TCP stream reconstruction |
| **PCAP / PCAPNG captures** | Recorded network traffic for retrospective investigation |
| **Linux / Parrot OS terminal** | Capture access, file handling, Base64 decoding |
| **TCP/IP, ARP, HTTP, DNS, ICMP, Telnet** | Protocol-level evidence and behavioral interpretation |
| **MITRE ATT&CK** | Contextual mapping of relevant adversary techniques where supported |

## Investigation Workflow

1. **Scope:** Define the suspicious protocol, investigation objective, and available capture.
   
2. **Filter:** Narrow the traffic using protocol fields and packet characteristics.
   
3. **Inspect:** Examine packet details, timing, counts, conversations, and payloads where available.
   
4. **Correlate:** Compare findings with expected protocol behavior and other observations.
   
5. **Assess:** Separate confirmed facts from possible attack hypotheses and identify gaps.
   
6. **Recommend:** Document useful detection logic, validation steps, and mitigations.

## Example Wireshark Filters

```wireshark
arp.opcode == 1 && eth.src == 08:00:27:53:0c:ba
```

```wireshark
tcp.flags.ack == 1
```

```wireshark
http.request.method == "GET" && tcp.dstport == 80
```

```wireshark
http.response.code == 400
```

```wireshark
icmp && frame.len > 42
```

These are investigation-specific examples, **not standalone indicators of malicious activity**. See each chapter for the capture context and interpretation.

## Key SOC Takeaways

- **ARP:** High-volume requests or changing IP-to-MAC mappings warrant investigation, but do not alone establish MITM or ARP poisoning.
  
- **TCP:** ACK and RST counts provide useful context; handshake sequences and connection state are needed before attributing reconnaissance or hijacking.
  
- **HTTP:** Request patterns, error responses, and unexpected data in URLs can surface enumeration and exfiltration leads, but require context.
  
- **Encoded data:** Base64 is an encoding mechanism, not encryption or proof of a covert channel; traffic behavior and payload context matter.
  
- **DNS / ICMP:** Suspicious payloads and anomalous exchanges can indicate tunneling; confirmation benefits from fuller packet inspection and host telemetry.

## Evidence, Attribution & Reproducibility

This portfolio is based on **Hack The Box Academy** training labs. Each chapter describes its source capture and analysis steps. The original lab PCAP files are **not redistributed here**; access may depend on the training platform and its terms. Screenshots are included where available, and some chapters have more visual evidence than others.

The reports distinguish **observed artifacts**, **lab-provided classifications**, and **analyst hypotheses**. Packet counts and sample values are specific to these lab captures and should not be generalized as universal detection thresholds. Any visible credentials, cookies, or lab flags are training artifacts rather than live secrets.

## Repository Layout

```text
Network-Traffic-Analysis/
├── README.md
├── 01-ARP-Spoofing-and-MITM-Detection/
│   ├── 01-ARP-Spoofing-and-MITM-Detection.md
│   └── images/
├── 02-TCP-Reconnaissance-and-Session-Hijacking/
│   ├── 02-TCP-Reconnaissance-and-Session-Hijacking.md
│   └── images/
├── 03-Web-Attack-Detection-and-HTTP-Anomalies/
│   ├── 03-Web-Attack-Detection-and-HTTP-Anomalies.md
│   └── images/
├── 04-Covert-Channels-and-Tunneling-Detection/
│   ├── 04-Covert-Channels-and-Tunneling-Detection.md
│   └── images/
└── 05-SOC-Network-Anomaly-Investigation/
    ├── 05-SOC-Network-Anomaly-Investigation.md
    └── images/
```

## Conclusion

Together, these five investigations demonstrate a repeatable approach to network-based threat hunting: selecting relevant packet evidence, analyzing protocol behavior, interpreting anomalies cautiously, and turning technical observations into actionable SOC investigation notes. The emphasis is on **analytical methodology and defensible findings**, rather than simply reproducing lab answers.

