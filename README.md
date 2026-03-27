# Expand SOCRadar connector from 4 to 155 operations (v2.0.0)

Adds full coverage of the SOCRadar API across all modules:

Incident API V4: post comment, ask analyst, assignee management, severity, tags
Threat Analysis: result retrieval, triggered analysis list
IoC Enrichment: indicator details (JSON + STIX)
CTI Threat Hunting Rules: search, download
CTI ThreatHunting: query, content details, extended investigating
CTI Vulnerability Intelligence: CVE trends/details/tweets/dorks/news/IoCs, search v1+v2
CTI Rapid Reputation, Threat Actor Malware (4 ops)
ASM Vulnerabilities V2, ASM Digital Footprint (8 ops)
Brand Protection V2 (14 ops), Dark Web Monitoring V2 (11 ops)
Identity Access Intelligence (10 ops), Company Identity Management (10 ops)
Allowlist (4 ops), Company Pocket (4 ops), Takedown (5 ops)
VIP Protection V2, Surface Web Monitoring V2, DRP Fraud Protection V2
Ransomware News, Dark Web News, Source Code Leakage, Malware Analysis
Combolists (2), Advanced Fraud Detection (2), Premium Feeds (2)
Company Events, Audit Logs, IOC Feed, Supply Chain Reports
DRP Configuration (3), Referrer Logs, CTI Threat Feed (2)
Multi-Tenant Management (27 ops)
Adds Multi-Tenant ID as optional config field.
