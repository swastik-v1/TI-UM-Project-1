# Threat Intelligence (TI) Aggregator

A high-performance, deterministic (rules-based, no-AI/ML) Cyber Threat Intelligence Aggregator built in Python. Collects, refangs, validates, normalizes, and correlates Indicators of Compromise (IOCs) across heterogeneous internal and external feeds, generating ready-to-deploy defensive blocklists and executive intelligence reports.

---

## Key Features

- **Strictly Deterministic (No AI / Zero Hallucinations):** Completely auditable and explainable risk scores based on feed reliability weights and multi-source consensus.
- **5-Stage Defensive Filtering:**
  1. *Syntactic & Format Filter:* Defanging (`hxxp` $\to$ `http`, `[.]` $\to$ `.`, `[@]` $\to$ `@`) and regex validation.
  2. *Network Safety & Bogon Suppression:* Drops RFC 1918 private IPs (`10.0.0.0/8`, `192.168.0.0/16`), loopbacks (`127.0.0.1`), and whitelisted CDNs/resolvers (`8.8.8.8`, `1.1.1.1`, `google.com`).
  3. *Canonicalization & Deduplication:* Lowercases domains/hashes, strips redundant URL queries, and extracts child domain/IP indicators from URLs.
  4. *Cross-Feed Correlation:* Calculates multi-source overlap bonuses.
  5. *Destination Policy Filter:* Routes only vetted high-risk threats to edge firewalls, keeping rule tables lean.
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
│   └── settings.yaml          # Scoring thresholds, TTL settings, export paths
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
│   ├── cli.py                 # Main CLI controller
│   ├── config_loader.py       # YAML configuration reader
│   ├── models.py              # Dataclasses & enumerations
│   ├── ingestion/             # Refanging, network fetching, format parsing
│   ├── normalization/         # IOC classification, derived hosts, bogon filter
│   ├── storage/               # SQLite database initialization & repository
│   ├── correlation/           # Deterministic multi-source scoring engine
│   ├── enrichment/            # AbuseIPDB / VirusTotal connectors & TTL cache
│   └── exports/               # Blocklist exporters & Markdown report generator
└── tests/                     # 19 unit & integration tests
```

---

## Installation & Setup

1. **Clone or Navigate to the Directory:**
   ```bash
   cd "Threat Intelligence Aggregator"
   ```

2. **Create and Activate Virtual Environment:**
   ```bash
   python -m venv .venv
   # Windows:
   .\.venv\Scripts\activate
   # Linux/macOS:
   source .venv/bin/activate
   ```

3. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

---

## Usage Guide (CLI)

### 1. Run the Full Aggregation Pipeline
Ingests all configured feeds, cleans indicators, drops bogons, calculates correlation scores, and generates blocklists and the intelligence report:
```bash
python -m src.cli run
```

### 2. View Database Statistics
Display high-level metrics, breakdown by IOC type and severity, and top recurring threats:
```bash
python -m src.cli stats
```

### 3. Inspect a Specific Indicator
Look up any IP, domain, URL, or hash to inspect its composite score, first/last seen timestamps, and reporting feeds:
```bash
python -m src.cli lookup 185.220.101.5
```

### 4. Optional External API Cross-Check (Enrichment)
To query external APIs (AbuseIPDB or VirusTotal) for an indicator, configure your `.env` file:
```env
ABUSEIPDB_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
```
Then pass the `--enrich` flag:
```bash
python -m src.cli lookup 185.220.101.5 --enrich
```

---

## Running Tests

Execute the automated test suite covering refanging, regex extraction, bogon filtering, scoring formulas, and end-to-end integration:
```bash
python -m unittest discover tests
```
