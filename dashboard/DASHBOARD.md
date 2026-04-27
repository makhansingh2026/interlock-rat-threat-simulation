# Wazuh SIEM Dashboard — INTERLOCK RAT Threat Hunting

This document mirrors **Appendix A of the project report**. It describes the unified Wazuh OpenSearch Dashboards view built to provide a security analyst with immediate situational awareness across all three detection layers (Suricata IDS/IPS, Zeek NSM via Suricata forwarding, and Wazuh HIDS).

The dashboard is reachable at `https://10.0.10.1` from any host on the victim subnet, with `wazuh-alerts-*` as the index pattern and a 7-day time range covering both the March 3rd attack execution and the March 5th IPS-mode validation.

## Log Ingestion Architecture

The Wazuh manager on the Router (10.0.10.1) correlates three independent telemetry streams into a single index:

| Source | Agent / Method | Log Types | Key Detections |
|---|---|---|---|
| Goku-mak (DC, 10.0.10.200) | Wazuh Agent + Sysmon (SwiftOnSecurity config) | Sysmon Event 1 (process), 11 (file), 13 (registry); Windows Security | Custom rule 100001 (PowerShell Bypass), 92031 (Discovery), 92021 (PS file deletion) |
| Krillin-mak (Workstation, 10.0.10.205, Agent ID 003) | Wazuh Agent | Windows Security Event 4624 (Logon Success) | Built-in 60106 (Logon Success), 92657 (Remote Logon / possible pass-the-hash) |
| Router (Suricata) | Local `eve.json` integration | Suricata alerts, drops, HTTP metadata | Wazuh rule 86601 carrying all 9 custom Suricata SIDs and IPS-blocked events |

![Figure 54: Log Flow Summary Table — Data sources, agents, log types, and key detections mapped across all three ingestion paths](../images/fig54-log-flow-summary-table.png)

*Figure 54: Log Flow Summary Table — Data sources, agents, log types, and key detections mapped across all three ingestion paths.*

![Figure 55: Custom Wazuh Detection Rules Table — Six rules (100001–100006) with severity levels, descriptions, and MITRE ATT&CK mappings](../images/fig55-custom-wazuh-rules-table.png)

*Figure 55: Custom Wazuh Detection Rules Table — Six rules (100001–100006) with severity levels, descriptions, and MITRE ATT&CK mappings.*

![Figure 56: Wazuh Agents Overview — Three connected agents reporting to the Wazuh Manager](../images/fig56-wazuh-agents-overview.png)

*Figure 56: Wazuh Agents Overview — Three connected agents (Router, Gokuadm-mak, Krillin-mak) reporting to the Wazuh Manager.*

---

## Visualization 1 — INTERLOCK Alert Distribution (Donut)

**Type:** Donut Pie Chart · **Field:** `rule.description` (Terms, size 15) · **Filter:** `rule.id: "100001" OR "92657" OR "92031" OR "86601" OR "92021" OR "92201"`

![Figure 57: INTERLOCK Alert Distribution — Suricata RDP Pivot 63.42%, PowerShell User-Agent 14.44%, C2 Command Poll 12.52%, plus endpoint detections](../images/fig57-viz1-alert-distribution.png)

*Figure 57: Visualization 1: INTERLOCK Alert Distribution.*

**Analytical finding.** Network-layer detection (Suricata via Wazuh rule 86601) provides the highest alert volume, while endpoint detection (Sysmon/Wazuh) provides higher-fidelity, lower-volume alerts with direct MITRE context. A mature SOC would use the Suricata stream for trend analysis and the endpoint alerts for incident confirmation and triage prioritization.

---

## Visualization 2 — INTERLOCK Attack Timeline (Line Chart)

**Type:** Line Chart with Date Histogram (minute interval) · **Filter:** `rule.groups: "sysmon" OR rule.description: "INTERLOCK*" OR rule.id: "86601"`

![Figure 58: Alert volume spike on March 3rd peaking at ~2,000 alerts, with a smaller secondary spike on March 5th during the IPS test](../images/fig58-viz2-attack-timeline.png)

*Figure 58: Visualization 2: INTERLOCK Attack Timeline.*

**Analytical finding.** The chart cleanly delineates the attack window from baseline operations, allowing an analyst to time-bound an incident investigation. The sharp onset (zero to thousands of alerts in minutes) is characteristic of automated malware execution rather than gradual reconnaissance — consistent with the RAT's automated Phase 1 discovery firing immediately on launch.

---

## Visualization 3 — MITRE ATT&CK Techniques (Horizontal Bar)

**Type:** Horizontal Bar Chart · **Field:** `rule.mitre.technique` (Terms, size 10) · **Filter:** Limited to attack-relevant techniques

![Figure 59: Eight attack-relevant techniques detected including Valid Accounts (T1078), Ingress Tool Transfer (T1105), and PowerShell (T1059.001)](../images/fig59-viz3-mitre-techniques.png)

*Figure 59: Visualization 3: MITRE ATT&CK Techniques.*

**Analytical finding.** Coverage spans five MITRE tactics — Initial Access, Execution, Discovery, Lateral Movement, and Command and Control. Exfiltration (T1041) and Persistence (T1547.001) were detected at the network and host layers but were not surfaced here because the corresponding Wazuh rules lacked `<mitre>` tags; adding those tags is the next iteration's improvement.

---

## Visualization 4 — Suricata IPS Actions (Donut)

**Type:** Donut Pie Chart · **Field:** `data.alert.action` · **Filter:** `rule.id: "86601"`

![Figure 60: Suricata IPS Blocked vs Allowed — 99.83% allowed (March 3rd attack, pre-IPS) and 0.17% blocked (March 5th DROP rules active)](../images/fig60-viz4-ips-blocked-vs-allowed.png)

*Figure 60: Visualization 4: Suricata IPS Blocked vs Allowed.*

**Analytical finding.** Before-and-after evidence that the IPS automation works. With DROP rules active on March 5th, Suricata blocked the PowerShell download (SID 1000012) at the Delivery phase, preventing the entire kill chain from progressing — no beacon, no exfil, no discovery, no lateral movement. This is the case for transitioning validated IDS signatures into IPS mode.

---

## Visualization 5 — Alerts by Agent (Donut)

**Type:** Donut Pie Chart · **Field:** `agent.name` (Terms, size 5) · **Filter:** None

![Figure 61: Alerts by Agent — msingh827/Router 48%, Gokuadm-mak 47%, Krillin-mak ~4%](../images/fig61-viz5-alerts-by-agent.png)

*Figure 61: Visualization 5: Alerts by Agent.*

**Analytical finding.** The three-agent split confirms that the architecture provides simultaneous visibility at both the network perimeter (Router/Suricata) and the endpoint level (Wazuh agents on Goku-mak and Krillin-mak). The Krillin-mak slice specifically validates that the lateral-movement target was reporting throughout the RDP pivot.

---

## Visualization 6 — PowerShell & Attack Activity (Data Table)

**Type:** Data Table · **Field:** `rule.description` (Terms, size 10) · **Filter:** `rule.description: "INTERLOCK*" OR *PowerShell* OR *Bypass* OR rule.id: "100001"`

![Figure 62: Data table — RDP Pivot 1,590, PowerShell User-Agent 362, C2 Command Poll 314, custom rule 100001 19](../images/fig62-viz6-powershell-attack-activity.png)

*Figure 62: Visualization 6: PowerShell and Attack Activity.*

**Analytical finding.** The C2 Command Poll (314) to Command Result Upload (31) ratio is roughly 10:1, consistent with seven hands-on-keyboard commands queued in Step 9 across two attack sessions — most beacon polls returned `NONE` because the operator had not queued a new command. The PowerShell Script Download count (18) aligns with multiple attack re-executions during testing and IPS validation.

---

## Visualization 7 — RDP & Logon Activity (Data Table, Dual Split)

**Type:** Data Table with dual split rows · **Fields:** `rule.description` (primary), `agent.name` (secondary) · **Filter:** `rule.description: *RDP* OR *Logon* OR rule.id: "60106" OR rule.id: "92657"`

![Figure 63: Dual-dimension table correlating logon events with agent names for lateral movement attribution](../images/fig63-viz7-rdp-logon-activity.png)

*Figure 63: Visualization 7: RDP and Logon Activity.*

**Analytical finding.** The agent-name correlation is the value of this view. Without it, a Type 3 logon on Krillin-mak could be dismissed as ordinary domain traffic. The combination of rule 92657 pass-the-hash warnings, the `CAPSULECORP\Gokuadm-mak` username, an explicit source IP of 10.0.10.200, and temporal correlation with the Suricata RDP Pivot alerts produces a high-confidence finding of attacker-initiated lateral movement from the DC.

---

## Visualization 8 — Alert Severity Distribution (Vertical Bar)

**Type:** Vertical Bar Chart · **Field:** `rule.level` (Terms, ascending, size 15) · **Filter:** None

![Figure 64: Level 3 dominates at 6,000+ events; custom INTERLOCK rules elevated at levels 10–14; IPS BLOCK at level 15](../images/fig64-viz8-alert-severity-distribution.png)

*Figure 64: Visualization 8: Alert Severity Distribution.*

**Analytical finding.** The pyramid validates rule-level assignment: the custom INTERLOCK rules at levels 10–14 are appropriately elevated above baseline informational events at level 3, ensuring they surface in an analyst's triage queue. A production deployment would filter `rule.level >= 10` to reduce 6,000+ events to a manageable investigation set.

---

## Visualization 9 — Suricata Signature Hits (Horizontal Bar)

**Type:** Horizontal Bar Chart · **Field:** `data.alert.signature` (Terms, size 10) · **Filter:** `rule.id: "86601"`

![Figure 65: All nine custom Suricata signatures fired — RDP Pivot leading at 1,590 hits with IPS BLOCK at the bottom](../images/fig65-viz9-suricata-signature-hits.png)

*Figure 65: Visualization 9: Suricata Signature Hits.*

**Analytical finding.** Every one of the nine custom Suricata signatures fired, confirming complete network-layer coverage of the kill chain. The presence of the IPS BLOCK signature alongside the alert-only signatures demonstrates the two-phase deployment strategy: alert-mode validation followed by IPS-mode blocking. Hit ratios are internally consistent — beacon (2) is much smaller than command poll (314) because the beacon fires once at RAT startup while the poll repeats every 30 seconds.

---

## Visualization 10 — Discovery & Enumeration Activity (Data Table)

**Type:** Data Table · **Field:** `rule.description` (Terms, size 15) · **Filter:** `rule.id: "92031" OR "92021" OR "92052" OR rule.description: *discovery*`

![Figure 66: PowerShell deletion 40, discovery executed 24, abnormal cmd 16, net.exe account discovery 3](../images/fig66-viz10-discovery-enumeration.png)

*Figure 66: Visualization 10: Discovery and Enumeration Activity.*

**Analytical finding.** The 16 "abnormal command prompt" alerts (rule 92052) are the most interesting line — Wazuh flagged the RAT's `cmd /c` command-execution mechanism as suspicious independent of the specific commands being run. That is behavior-based detection that would catch novel attacker commands not covered by signatures, and it pairs naturally with the signature-based 100004/100005/100006 rules.

---

## Dashboard Effectiveness Summary

| Kill Chain Phase | Dashboard Coverage | Visualizations |
|---|---|---|
| Delivery | PowerShell download, User-Agent detection | #1, #6, #9 |
| Exploitation / Execution | PowerShell Bypass, script execution | #1, #3, #6, #8 |
| C2 Communication | Beacon polling, command results, JSON exfil | #1, #2, #6, #9 |
| Discovery | systeminfo, AD enumeration, net user | #3, #10 |
| Lateral Movement | RDP pivot, logon events, pass-the-hash | #5, #7, #9 |
| Automated Response | IPS DROP blocking at Delivery | #4, #9 |

The dashboard confirms that all custom Suricata signatures (9 SIDs), all Zeek notice types (4), and all custom Wazuh rules (6) are generating actionable, indexable, visualizable alerts. The IPS Blocked-vs-Allowed visualization (#4) specifically demonstrates that automated response is operational end-to-end, satisfying the project's automated-detection-and-response objective.
