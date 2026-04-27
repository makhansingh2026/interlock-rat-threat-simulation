# Project Artifacts Manifest

This manifest lists every file extracted from the source documents, its origin, and a one-line description. The lab manual (`docs/Interlock_RAT_Lab_Manual.docx`) is the canonical source for all code; the project report (`docs/IndividualProjectReport.pdf`) supplied the figures and the analytical narrative. Where both contained a code block, the lab manual version was used because it is plain text rather than a screenshot.

## Detection Rules

| File | Source | Description |
|---|---|---|
| `detection-rules/suricata/custom.rules` | Lab Manual §5.1 + §11.1 / Report Fig. 17, 37 | Suricata custom ruleset — 9 ALERT signatures (SIDs 1000001–1000009, 1000013) plus 3 IPS DROP signatures (SIDs 1000010–1000012) covering the full Interlock kill chain. |
| `detection-rules/zeek/interlock-detect.zeek` | Lab Manual §5.3 / Report Fig. 18 | Zeek site script defining four custom `Notice::Type` values (`Interlock_C2_Beacon`, `Interlock_Data_Exfil`, `Interlock_PS_Download`, `Interlock_PowerShell_UA`). |
| `detection-rules/wazuh/local_rules.xml` | Lab Manual §5.5 / Report Fig. 19, 20 | Six custom Wazuh HIDS rules (100001–100006) with MITRE ATT&CK mappings for execution, ingress tool transfer, persistence, discovery, AD enumeration, and scheduled task abuse. |
| `detection-rules/wazuh/ossec.conf.snippet` | Lab Manual §11.2 / Report Fig. 40 | Active-response block: `firewall-drop` triggered by rules 100001 and 100003, 600 s timeout. |

## Attack Infrastructure

| File | Source | Description |
|---|---|---|
| `attack-infrastructure/c2_server.py` | Lab Manual §2.3 / Report Fig. 7, 8 | Flask C2 implementing `/beacon`, `/exfil`, `/cmd`, and `/result` endpoints. Loots into `/opt/c2/loot`; reads queued commands from `/opt/c2/commands/next_cmd.json`. |
| `attack-infrastructure/payload.ps1` | Lab Manual §4.1 / Report Fig. 14 | Dropper — deletes the `Updater` scheduled task, stages `%APPDATA%\php\wefs.cfg`, downloads `rat.ps1` from Apache (User-Agent: `PowerShell`), and executes it. |
| `attack-infrastructure/rat.ps1` | Lab Manual §4.2 / Report Fig. 15, 16 | Three-phase simulated RAT: automated discovery, Registry Run-key persistence (`InterlockSim`), and 30-second C2 beacon loop with `CMD`/`OFF`/`NONE` switch. |
| `attack-infrastructure/filefix-lure.html` | Lab Manual §3.2 / Report Fig. 12 | KongTuke FileFix lure page — clipboard-based PowerShell delivery with fake "verify you are human" social-engineering UI. |

## Automation

| File | Source | Description |
|---|---|---|
| `automation/alert_monitor.sh` | Lab Manual §11.3 / Report Fig. 41 | Real-time `eve.json` parser. Tails Suricata's only configured log output, filters `INTERLOCK` signatures, formats `[allowed]` vs `[blocked]`, and tees to `/var/log/interlock-alerts.log`. |

## Documentation

| File | Source | Description |
|---|---|---|
| `README.md` | Synthesized from PDF + DOCX | Portfolio README — executive summary, threat background, architecture, attack chain walkthrough, detection engineering, automated response, dashboard, coverage summary, key metrics, lessons learned, skills, tech stack, repo tree, disclaimer, author. |
| `ARTIFACTS.md` | This file | Full manifest of every extracted file with source citations. |
| `LICENSE` | MIT, Makhan Singh, 2026 | Permissive open-source license. |
| `dashboard/DASHBOARD.md` | Report Appendix A / Fig. 54–66 | Per-visualization breakdown of the Wazuh INTERLOCK Threat-Hunting Dashboard (10 visualizations). |
| `docs/IndividualProjectReport.pdf` | Source artifact | The 48-page polished project report. |
| `docs/Interlock_RAT_Lab_Manual.docx` | Source artifact | The operational build document — canonical source for every script, rule, and config in this repo. |

## Figures

All 66 figures from the project report are extracted to `images/figXX-<slug>.png`. Filenames track the report captions (Figure 1 → `fig01-network-topology.png` … Figure 66 → `fig66-viz10-discovery-enumeration.png`). The README and `dashboard/DASHBOARD.md` reference these figures by their relative paths.

## Sourcing rule

Every code file in this repository was pulled directly from the lab manual (DOCX), which is the authoritative source. No file required transcription from a PDF screenshot, so no file carries the `# Transcribed from project report Figure XX` verification header — every script, rule, and config in `detection-rules/`, `attack-infrastructure/`, and `automation/` is the canonical version as deployed in the lab.
