# Threat Intelligence (TI) Aggregator

A high-performance, deterministic (rules-based, no-AI/ML) Cyber Threat Intelligence Aggregator built in Python. Collects, refangs, validates, normalizes, and correlates Indicators of Compromise (IOCs) across heterogeneous internal and external feeds, generating ready-to-deploy defensive blocklists, webhook alerts, and visual threat intelligence dashboards.

---

## Key Features

- **Strictly Deterministic (No AI / Zero Hallucinations):** Completely auditable and explainable risk scores based on feed reliability weights and multi-source consensus.
- **Asynchronous Concurrent Ingestion (`asyncio` + `httpx`):** High-speed parallel fetching of dozens of remote HTTP/S feeds with timeout protection and offline cache fallbacks.
- **Automated TTL Aging & Expiry Management:**
  - Prevents perimeter firewall bloat by decaying indicator scores over a rolling retention window (e.g., 30 days).
  - Automatically retires stale indicators to `EXPIRED` status so they drop off active blocklists while remaining searchable in SQLite.
- **Webhook Alerting & SIEM Dispatch:**
  - Automated alert dispatchers for **Slack**, **Microsoft Teams**, and **Generic JSON Webhooks** whenever critical high-severity multi-source threats are detected.
- **FastAPI REST API & Interactive Web Dashboard:**
  - Responsive, dark-mode cybersecurity dashboard with doughnut charts, real-time metrics cards, search & filter tables, 1-click feed synchronization, and direct blocklist downloads.
- **5-Stage Defensive Filtering:**
  1. *Syntactic & Format Filter:* Defanging (`hxxp` $\to$ `http`, `[.]` $\to$ `.`, `[@]` $\to$ `@`) and regex validation.
  2. *Network Safety & Bogon Suppression:* Drops RFC 1918 private IPs (`10.0.0.0/8`, `192.168.0.0/16`), loopbacks (`127.0.0.1`), and whitelisted CDNs/resolvers (`8.8.8.8`, `1.1.1.1`, `google.com`).
  3. *Canonicalization & Deduplication:* Lowercases domains/hashes, strips redundant URL queries, and extracts child domain/IP indicators from URLs.
  4. *Cross-Feed Correlation:* Calculates multi-source overlap bonuses.
  5. *Destination Policy Filter:* Routes only vetted high-risk active threats to edge firewalls, keeping rule tables lean.
- **Embedded SQLite Persistence:** Zero-dependency relational database (`ti_aggregator.db`) with indexes and tracking across aggregation cycles.
- **Multi-System Blocklist Exporters:**
  - **Firewalls:** Plain-text IP drop list for iptables, Cisco, pfSense, Palo Alto.
  - **DNS Sinkhole:** Pi-hole, Bind RPZ, and Unbound hosts format (`0.0.0.0 evil.com`).
  - **Web Proxies:** Malicious URL list for Squid, BlueCoat, and SWG.
  - **EDR / AV:** CSV hash watchlist (MD5, SHA1, SHA256) for threat containment.
  - **SIEM / SOAR:** Comprehensive JSON feed with occurrence metrics and contextual tags.
- **Optional Gated External Enrichment:** Connectors for AbuseIPDB and VirusTotal with SQLite TTL caching to prevent rate-limit exhaustion.

---

## Project Structure

```text
Threat Intelligence Aggregator/
├── config/
│   ├── feeds.yaml             # Feed sources, URLs, types, and weights
│   ├── allowlist.yaml         # Bogon suppression rules & safe IPs/domains
│   └── settings.yaml          # Scoring, TTL retention, webhooks & API settings
├── data/
│   ├── ti_aggregator.db       # Embedded SQLite database (auto-created)
│   └── samples/               # Realistic threat feed fixtures (JSON, CSV, TXT)
├── exports/                   # Auto-generated defensive blocklists and reports
│   ├── blocklist_firewall.txt
│   ├── blocklist_dns.txt
│   ├── blocklist_proxy.txt
│   ├── blocklist_edr.csv
│   ├── threat_intel_full.json
│   └── threat_report.md
├── src/
│   ├── cli.py                 # Main CLI controller (run, stats, lookup, serve)
│   ├── api.py                 # FastAPI REST API & Single-Page Dashboard
│   ├── config_loader.py       # YAML configuration reader
│   ├── models.py              # Dataclasses & enumerations
│   ├── alerting/              # Slack, Teams, and generic JSON webhook dispatchers
│   ├── ingestion/             # Async concurrent fetcher, refanger, format parsers
│   ├── normalization/         # Regex classifiers, derived hosts, bogon filter
│   ├── storage/               # SQLite database initialization & repository
│   ├── correlation/           # Deterministic multi-source scoring & TTL decay
│   ├── enrichment/            # AbuseIPDB / VirusTotal connectors & TTL cache
│   └── exports/               # Blocklist exporters & Markdown report generator
└── tests/                     # 33 unit & integration tests
```

---

## Installation & Setup

1. **Activate Virtual Environment:**
   ```bash
   # Windows:
   .\.venv\Scripts\activate
   # Linux/macOS:
   source .venv/bin/activate
   ```

2. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

---

## Usage Guide (CLI & Web UI)

### 1. Launch the Interactive Web Dashboard & REST API
Start the local dashboard server:
```bash
python -m src.cli serve
```
Open your browser to: **`http://127.0.0.1:8000`**
* View real-time indicator statistics and doughnut distribution charts.
* Search and filter through threats by IP, domain, hash, severity, or status.
* Trigger feed synchronization with 1-click.
* Download Firewall, DNS, Proxy, and EDR blocklists directly.

### 2. Run the Full Aggregation Pipeline via CLI
Ingests feeds asynchronously, cleans indicators, drops bogons, calculates correlation scores with TTL decay, dispatches alerts, and updates blocklists:
```bash
python -m src.cli run
```

### 3. View Real-Time Database Statistics
Display high-level metrics, active vs expired breakdowns, and top recurring threats:
```bash
python -m src.cli stats
```

### 4. Inspect a Specific Indicator
Look up any IP, domain, URL, or hash to inspect its composite score, decayed score, status, and reporting feeds:
```bash
python -m src.cli lookup 185.220.101.5
```

---

## Running Tests

Execute the automated test suite covering refanging, regex extraction, bogon filtering, scoring formulas, aging decay, webhooks, async fetching, and API endpoints:
```bash
python -m unittest discover tests
```
