# SOCRadar + FortiSIEM Fortinet Toolset

A collection of tools for Fortinet security operations — an expanded **FortiSOAR SOCRadar connector** (v2.0.0) and a **FortiSIEM log collection script**.

---

## 1. SOCRadar FortiSOAR Connector (v2.0.0)

An expanded community connector for [SOCRadar](https://socradar.io) that integrates with **FortiSOAR**.

The original connector (v1.0.0) covered only 4 actions. This version adds **155 operations** covering the full SOCRadar API surface.

### Coverage

| API Group | Operations |
|---|---|
| Incident API V4 | Get incidents, get incident, change status, post comment, ask analyst, get/change assignee, change severity, add/remove tag, get assignee options |
| Threat Analysis | Analyze entity, get result, get triggered list |
| IoC Enrichment | Get indicator details (JSON + STIX) |
| CTI Threat Hunting Rules | Search rules, download rules |
| CTI ThreatHunting | Query threat data, get content details, extended investigating |
| CTI Vulnerability Intelligence | Search CVEs (v1/v2), CVE trends, CVE details, tweets, dorks, news, IoCs |
| CTI Rapid Reputation | Get rapid reputation score |
| Threat Actor Malware | Get actors, actor detail, detailed content, param options |
| ASM Vulnerabilities V2 | Latest vulnerabilities, mobile app security |
| ASM Digital Footprint | Get assets (v1/v2), asset details, add assets, exclude, configure monitoring, uptime checks |
| Brand Protection V2 | Impersonating accounts/domains, rogue apps, bad reputation, social media findings + add/status ops |
| Dark Web Monitoring V2 | Botnet, black market, suspicious content, PII exposure, IM content + status updates + request obtain |
| Identity Access Intelligence | Info stealer search, credential/info file download, breach query, breach download, file tree, stealer logs on sale |
| Company Identity Management | List/create/enable/disable/delete users, add/remove roles, enable/disable SSO |
| Company Allowlist | Get, add, upload bulk, delete entities |
| Company Pocket | Get, add indicators, upload file, delete entities |
| Takedown | Submit phishing/rogue app/social media/source code takedowns, get progress |
| VIP Protection V2 | Get data, update status |
| Surface Web Monitoring V2 | Get records, add record, update status |
| DRP Fraud Protection V2 | Get data, update status |
| Ransomware News | Get ransomware victims |
| CTI Dark Web News | Search dark web news |
| CTI Source Code Leakage | Search source code leakage |
| Malware Analysis | Analyze malware file |
| Combolists | List combolists, get combolist details |
| Advanced Fraud Detection | Search fraud card, BIN lookup |
| Premium Feeds | List feeds, get feed content |
| Company Events | Get company events |
| Company User Audit Logs | Get audit logs |
| Collection Based IOC Feed | Get IOC feed by collection |
| Company Supply Chain Reports | Get supply chain report |
| DRP Configuration | Get assets, add asset, update monitoring status |
| Referrer Logs | Submit referrer logs |
| CTI Threat Feed | Get feed sources, get feed source details |
| Multi-Tenant Management | Create/list/archive/unarchive tenants, settings, service config, history, detail, ecosystems, templates, users, asset sizing (27 ops) |

### Configuration Fields

| Field | Required | Description |
|---|---|---|
| Server URL | Yes | Default: `https://platform.socradar.com/api` |
| Company ID | Yes | Your SOCRadar Company ID |
| Company API Key | Yes | Company API key from SOCRadar Settings → API Options |
| Threat Analysis API Key | No | Required for Threat Analysis and Malware Analysis operations |
| Multi-Tenant ID | No | Required for Multi-Tenant Management operations |
| Verify SSL | No | Default: true |

### Installation

1. Download or clone this repository
2. In FortiSOAR, go to **Automation > Connectors**
3. Click **Upload** and select the `soc-radar/` directory
4. Configure the connector with your SOCRadar credentials

---

## 2. FortiSIEM Log Collection Script

`collect_fsm_logs.sh` automates log collection from FortiSIEM nodes for Fortinet TAC support cases, based on **Fortinet KB Article 192568**.

### What it collects

| File | Source |
|---|---|
| `fsm-health.log` | `get-fsm-health.py --local` |
| `journlctl.log` | `journalctl -k` (kernel journal) |
| `interrupts.txt` | `/proc/interrupts` |
| `hosts.txt` | `/etc/hosts` |
| `root_env` | Root user environment variables |
| `admin_env` | Admin user environment variables |
| `pg_stat_activity.out` | PostgreSQL `pg_stat_activity` (Supervisor only) |
| `keeper_logs.tar.gz` | ClickHouseKeeper application logs |
| `keeper_conf.tar.gz` | ClickHouseKeeper configuration |
| `AOLogs.tar` (renamed) | Full FortiSIEM log archive via `phziplogs` |

All files are bundled into a single `.tar` archive named:
```
FortiSIEMLogs-<ticket>-<hostname>-<timestamp>.tar
```

### Requirements

- Must be run as **root**
- Must be executed on a **FortiSIEM Supervisor, Worker, or Collector** node
- `phziplogs` must be available in PATH

### Usage

```bash
chmod +x collect_fsm_logs.sh
sudo ./collect_fsm_logs.sh <ticket_number> <number_of_days>
```

**Example:**
```bash
sudo ./collect_fsm_logs.sh 1234567 3
```

| Argument | Description |
|---|---|
| `ticket_number` | Fortinet TAC ticket number (numeric) |
| `number_of_days` | Days of logs to collect (1–30) |

### Output

The final archive is saved to:
```
/tmp/<ticket_number>/FortiSIEMLogs-<ticket>-<hostname>-<timestamp>.tar
```

### Transferring the archive

**Linux / macOS:**
```bash
scp root@<FortiSIEM-IP>:/tmp/<ticket>/FortiSIEMLogs-*.tar .
```

**Windows:** Use WinSCP to pull the file from the path shown at the end of the script output.

Then upload to your Fortinet TAC ticket at [support.fortinet.com](https://support.fortinet.com).

> **Note:** Max upload size is 500 MB per attachment.

### Node behaviour

The script gracefully handles missing components (e.g., `get-fsm-health.py`, `psql`, ClickHouseKeeper directories) — it logs a warning and continues rather than failing.

---

## License

MIT — see [LICENSE](LICENSE)
