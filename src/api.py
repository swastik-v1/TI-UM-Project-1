"""FastAPI REST API and Web Dashboard for Threat Intelligence Aggregator."""

import logging
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, HTTPException, Query, BackgroundTasks
from fastapi.responses import HTMLResponse, PlainTextResponse, FileResponse
from pydantic import BaseModel

from src.config_loader import AppConfig, BASE_DIR
from src.storage.database import init_db
from src.storage.repository import IOCRepository
from src.models import IOCType, Severity, IndicatorStatus

logger = logging.getLogger("ti_aggregator.api")

app = FastAPI(
    title="Threat Intelligence Aggregator API",
    description="Deterministic rules-based threat intelligence platform and blocklist generator.",
    version="1.1.0",
)

config = AppConfig()
db_path = config.database_path
init_db(db_path)
repo = IOCRepository(db_path)


# ---------------------------------------------------------
# HTML Dashboard Template (Single Page Application)
# ---------------------------------------------------------
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Cyber Threat Intelligence Aggregator</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <style>
    body { background-color: #0d1117; color: #c9d1d9; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    .card { background-color: #161b22; border: 1px solid #30363d; }
  </style>
</head>
<body class="p-6">
  <div class="max-w-7xl mx-auto space-y-6">

    <!-- Header -->
    <header class="flex flex-col md:flex-row md:items-center md:justify-between pb-6 border-b border-gray-800 gap-4">
      <div>
        <h1 class="text-3xl font-bold text-white flex items-center gap-3">
          <i class="fa-solid fa-shield-halved text-red-500"></i> Threat Intelligence Aggregator
        </h1>
        <p class="text-sm text-gray-400 mt-1">Deterministic Rules-Based CTI Normalization, Consensus Scoring & Defensive Blocklists</p>
      </div>
      <div class="flex items-center gap-3">
        <button id="runBtn" onclick="runPipeline()" class="px-4 py-2 bg-red-600 hover:bg-red-700 text-white font-medium rounded-lg text-sm shadow transition flex items-center gap-2">
          <i class="fa-solid fa-rotate"></i> Sync Feeds & Correlate
        </button>
        <a href="/api/report" target="_blank" class="px-4 py-2 bg-gray-800 hover:bg-gray-700 text-gray-200 font-medium rounded-lg text-sm border border-gray-700 transition flex items-center gap-2">
          <i class="fa-solid fa-file-lines"></i> Report
        </a>
      </div>
    </header>

    <!-- Metrics Cards -->
    <div class="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4">
      <div class="card p-4 rounded-xl">
        <div class="text-xs uppercase font-semibold text-gray-400">Total Unique IOCs</div>
        <div id="statTotal" class="text-3xl font-extrabold text-white mt-1">--</div>
      </div>
      <div class="card p-4 rounded-xl border-l-4 border-l-red-500">
        <div class="text-xs uppercase font-semibold text-red-400">High Risk (Active)</div>
        <div id="statHigh" class="text-3xl font-extrabold text-red-500 mt-1">--</div>
      </div>
      <div class="card p-4 rounded-xl border-l-4 border-l-yellow-500">
        <div class="text-xs uppercase font-semibold text-yellow-400">Medium Risk</div>
        <div id="statMed" class="text-3xl font-extrabold text-yellow-500 mt-1">--</div>
      </div>
      <div class="card p-4 rounded-xl border-l-4 border-l-blue-500">
        <div class="text-xs uppercase font-semibold text-blue-400">Low Risk</div>
        <div id="statLow" class="text-3xl font-extrabold text-blue-400 mt-1">--</div>
      </div>
      <div class="card p-4 rounded-xl border-l-4 border-l-gray-600">
        <div class="text-xs uppercase font-semibold text-gray-400">Expired (TTL Decay)</div>
        <div id="statExpired" class="text-3xl font-extrabold text-gray-400 mt-1">--</div>
      </div>
    </div>

    <!-- Charts Section -->
    <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
      <div class="card p-5 rounded-xl">
        <h2 class="text-lg font-bold text-white mb-4 flex items-center gap-2">
          <i class="fa-solid fa-chart-pie text-blue-400"></i> Indicators by Type
        </h2>
        <div class="h-64 flex items-center justify-center">
          <canvas id="typeChart"></canvas>
        </div>
      </div>
      <div class="card p-5 rounded-xl">
        <h2 class="text-lg font-bold text-white mb-4 flex items-center gap-2">
          <i class="fa-solid fa-download text-emerald-400"></i> Ready Defensive Blocklists
        </h2>
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
          <a href="/api/blocklists/firewall" target="_blank" class="p-3 bg-gray-900 border border-gray-800 hover:border-red-500 rounded-lg flex items-center justify-between transition">
            <span><i class="fa-solid fa-network-wired text-red-400 mr-2"></i> Firewall IPs</span>
            <i class="fa-solid fa-arrow-up-right-from-square text-xs text-gray-500"></i>
          </a>
          <a href="/api/blocklists/dns" target="_blank" class="p-3 bg-gray-900 border border-gray-800 hover:border-yellow-500 rounded-lg flex items-center justify-between transition">
            <span><i class="fa-solid fa-globe text-yellow-400 mr-2"></i> DNS Sinkhole</span>
            <i class="fa-solid fa-arrow-up-right-from-square text-xs text-gray-500"></i>
          </a>
          <a href="/api/blocklists/proxy" target="_blank" class="p-3 bg-gray-900 border border-gray-800 hover:border-blue-500 rounded-lg flex items-center justify-between transition">
            <span><i class="fa-solid fa-link text-blue-400 mr-2"></i> Web Proxy URLs</span>
            <i class="fa-solid fa-arrow-up-right-from-square text-xs text-gray-500"></i>
          </a>
          <a href="/api/blocklists/edr" target="_blank" class="p-3 bg-gray-900 border border-gray-800 hover:border-purple-500 rounded-lg flex items-center justify-between transition">
            <span><i class="fa-solid fa-file-code text-purple-400 mr-2"></i> EDR File Hashes</span>
            <i class="fa-solid fa-arrow-up-right-from-square text-xs text-gray-500"></i>
          </a>
          <a href="/api/blocklists/json" target="_blank" class="p-3 bg-gray-900 border border-gray-800 hover:border-emerald-500 rounded-lg flex items-center justify-between col-span-1 sm:col-span-2 transition">
            <span><i class="fa-solid fa-database text-emerald-400 mr-2"></i> Complete SIEM JSON Dataset</span>
            <i class="fa-solid fa-arrow-up-right-from-square text-xs text-gray-500"></i>
          </a>
        </div>
      </div>
    </div>

    <!-- IOC Table & Search -->
    <div class="card p-5 rounded-xl">
      <div class="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-4">
        <h2 class="text-lg font-bold text-white flex items-center gap-2">
          <i class="fa-solid fa-list-check text-yellow-400"></i> Indicator Intelligence Table
        </h2>
        <div class="flex flex-wrap items-center gap-2">
          <input id="searchInput" type="text" placeholder="Search IP, Domain, Hash..." oninput="loadIOCs()"
                 class="px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:border-red-500">
          <select id="sevFilter" onchange="loadIOCs()" class="px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-sm text-gray-200 focus:outline-none">
            <option value="">All Severities</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
          <select id="statusFilter" onchange="loadIOCs()" class="px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-sm text-gray-200 focus:outline-none">
            <option value="ACTIVE">Active (Unexpired)</option>
            <option value="EXPIRED">Expired</option>
            <option value="ALL">All Statuses</option>
          </select>
        </div>
      </div>

      <div class="overflow-x-auto">
        <table class="w-full text-left text-sm border-collapse">
          <thead>
            <tr class="border-b border-gray-800 text-gray-400 font-semibold uppercase text-xs">
              <th class="py-3 px-3">Indicator Value</th>
              <th class="py-3 px-3">Type</th>
              <th class="py-3 px-3">Score</th>
              <th class="py-3 px-3">Decayed</th>
              <th class="py-3 px-3">Severity</th>
              <th class="py-3 px-3">Sources</th>
              <th class="py-3 px-3">Status</th>
            </tr>
          </thead>
          <tbody id="iocTableBody" class="divide-y divide-gray-800">
            <tr><td colspan="7" class="py-6 text-center text-gray-500">Loading indicators...</td></tr>
          </tbody>
        </table>
      </div>
    </div>

  </div>

  <script>
    let chartInstance = null;

    async function loadStats() {
      try {
        const res = await fetch('/api/stats');
        const data = await res.json();
        document.getElementById('statTotal').innerText = data.total_unique_iocs || 0;
        document.getElementById('statHigh').innerText = (data.breakdown_by_severity && data.breakdown_by_severity.HIGH) || 0;
        document.getElementById('statMed').innerText = (data.breakdown_by_severity && data.breakdown_by_severity.MEDIUM) || 0;
        document.getElementById('statLow').innerText = (data.breakdown_by_severity && data.breakdown_by_severity.LOW) || 0;
        document.getElementById('statExpired').innerText = (data.breakdown_by_status && data.breakdown_by_status.EXPIRED) || 0;

        // Render Chart
        const labels = Object.keys(data.breakdown_by_type || {});
        const values = Object.values(data.breakdown_by_type || {});
        const ctx = document.getElementById('typeChart').getContext('2d');
        if (chartInstance) chartInstance.destroy();
        chartInstance = new Chart(ctx, {
          type: 'doughnut',
          data: {
            labels: labels,
            datasets: [{
              data: values,
              backgroundColor: ['#ef4444', '#3b82f6', '#10b981', '#f59e0b', '#8b5cf6', '#ec4899'],
              borderWidth: 0
            }]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { position: 'right', labels: { color: '#9ca3af' } } }
          }
        });
      } catch (e) {
        console.error("Failed to load stats", e);
      }
    }

    async function loadIOCs() {
      const q = document.getElementById('searchInput').value;
      const sev = document.getElementById('sevFilter').value;
      const status = document.getElementById('statusFilter').value;
      const url = `/api/iocs?q=${encodeURIComponent(q)}&severity=${encodeURIComponent(sev)}&status=${encodeURIComponent(status)}&limit=50`;

      try {
        const res = await fetch(url);
        const data = await res.json();
        const tbody = document.getElementById('iocTableBody');
        if (!data || data.length === 0) {
          tbody.innerHTML = '<tr><td colspan="7" class="py-6 text-center text-gray-500">No matching indicators found.</td></tr>';
          return;
        }

        tbody.innerHTML = data.map(i => {
          let badge = '';
          if (i.severity === 'HIGH') badge = '<span class="px-2 py-0.5 rounded text-xs font-semibold bg-red-950 text-red-400 border border-red-800">HIGH</span>';
          else if (i.severity === 'MEDIUM') badge = '<span class="px-2 py-0.5 rounded text-xs font-semibold bg-yellow-950 text-yellow-400 border border-yellow-800">MEDIUM</span>';
          else badge = '<span class="px-2 py-0.5 rounded text-xs font-semibold bg-blue-950 text-blue-400 border border-blue-800">LOW</span>';

          const statusBadge = i.status === 'EXPIRED' 
            ? '<span class="px-2 py-0.5 rounded text-xs font-semibold bg-gray-800 text-gray-400">EXPIRED</span>'
            : '<span class="px-2 py-0.5 rounded text-xs font-semibold bg-emerald-950 text-emerald-400">ACTIVE</span>';

          const sources = (i.sources || []).map(s => `<span class="bg-gray-800 text-gray-300 text-xs px-1.5 py-0.5 rounded mr-1">${s}</span>`).join('');

          return `
            <tr class="hover:bg-gray-900 transition">
              <td class="py-3 px-3 font-mono text-white text-xs break-all">${i.value}</td>
              <td class="py-3 px-3 text-xs text-gray-300">${i.type}</td>
              <td class="py-3 px-3 font-semibold text-white">${i.score}</td>
              <td class="py-3 px-3 text-gray-400 text-xs">${i.decayed_score}</td>
              <td class="py-3 px-3">${badge}</td>
              <td class="py-3 px-3">${sources || '-'}</td>
              <td class="py-3 px-3">${statusBadge}</td>
            </tr>
          `;
        }).join('');
      } catch (e) {
        console.error("Failed to load IOCs", e);
      }
    }

    async function runPipeline() {
      const btn = document.getElementById('runBtn');
      btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Ingesting & Correlating...';
      btn.disabled = true;
      try {
        await fetch('/api/pipeline/run', { method: 'POST' });
        await loadStats();
        await loadIOCs();
      } catch (e) {
        alert("Pipeline error: " + e);
      } finally {
        btn.innerHTML = '<i class="fa-solid fa-rotate"></i> Sync Feeds & Correlate';
        btn.disabled = false;
      }
    }

    // Initial load
    loadStats();
    loadIOCs();
  </script>
</body>
</html>
"""


# ---------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
@app.get("/dashboard", response_class=HTMLResponse)
def get_dashboard():
    """Serves the single-page visual cybersecurity dashboard."""
    return DASHBOARD_HTML


@app.get("/api/stats")
def get_stats():
    """Returns real-time database intelligence metrics."""
    return repo.get_metrics()


@app.get("/api/iocs")
def get_indicators(
    q: Optional[str] = Query(None, description="Search indicator text"),
    severity: Optional[str] = Query(None, description="Filter by severity (HIGH, MEDIUM, LOW)"),
    type: Optional[str] = Query(None, description="Filter by IOC type"),
    status: Optional[str] = Query("ACTIVE", description="Filter by status (ACTIVE, EXPIRED, ALL)"),
    limit: int = Query(50, ge=1, le=500),
):
    """Retrieves scored indicators with filtering, search, and pagination."""
    ioc_type_enum = None
    if type:
        try:
            ioc_type_enum = IOCType(type.lower())
        except ValueError:
            pass

    all_iocs = repo.get_all_scored_indicators(
        min_severity=severity if severity else None,
        ioc_type=ioc_type_enum,
        status=status,
    )

    if q:
        query_lower = q.lower().strip()
        all_iocs = [i for i in all_iocs if query_lower in i.value.lower()]

    results = []
    for i in all_iocs[:limit]:
        results.append({
            "ioc_id": i.ioc_id,
            "value": i.value,
            "type": i.ioc_type.value,
            "score": i.calculated_score,
            "decayed_score": i.decayed_score,
            "severity": i.severity.value,
            "status": i.status.value,
            "occurrence_count": i.occurrence_count,
            "first_seen": i.first_seen,
            "last_seen": i.last_seen,
            "sources": i.sources,
            "contexts": i.contexts,
        })
    return results


@app.get("/api/iocs/{value}")
def get_single_indicator(value: str):
    """Fetches details and reporting history for a specific indicator."""
    ioc = repo.get_indicator_by_value(value)
    if not ioc:
        raise HTTPException(status_code=404, detail="Indicator not found in threat database")

    cached_enrichment = repo.get_cached_enrichment(value)
    return {
        "indicator": {
            "value": ioc.value,
            "type": ioc.ioc_type.value,
            "score": ioc.calculated_score,
            "decayed_score": ioc.decayed_score,
            "severity": ioc.severity.value,
            "status": ioc.status.value,
            "occurrence_count": ioc.occurrence_count,
            "first_seen": ioc.first_seen,
            "last_seen": ioc.last_seen,
            "sources": ioc.sources,
            "contexts": ioc.contexts,
        },
        "enrichment": cached_enrichment,
    }


@app.post("/api/pipeline/run")
def trigger_pipeline():
    """Runs the complete ingestion, correlation, and export cycle."""
    from src.cli import run_full_pipeline
    run_full_pipeline(config, enrich_high=False)
    return {"status": "SUCCESS", "message": "Threat intelligence aggregation cycle completed successfully."}


@app.get("/api/blocklists/{target}")
def get_blocklist(target: str):
    """Downloads formatted blocklists."""
    paths = config.export_paths
    target_lower = target.lower()

    if target_lower == "firewall":
        return FileResponse(paths["firewall_ips"], media_type="text/plain", filename="blocklist_firewall.txt")
    elif target_lower == "dns":
        return FileResponse(paths["dns_domains"], media_type="text/plain", filename="blocklist_dns.txt")
    elif target_lower == "proxy":
        return FileResponse(paths["proxy_urls"], media_type="text/plain", filename="blocklist_proxy.txt")
    elif target_lower == "edr":
        return FileResponse(paths["edr_hashes"], media_type="text/csv", filename="blocklist_edr.csv")
    elif target_lower == "json":
        return FileResponse(paths["all_json"], media_type="application/json", filename="threat_intel_full.json")
    else:
        raise HTTPException(status_code=400, detail="Unknown blocklist target. Use: firewall, dns, proxy, edr, or json")


@app.get("/api/report", response_class=PlainTextResponse)
def get_report():
    """Returns the executive markdown report."""
    report_path = config.export_paths["summary_report"]
    if report_path.is_file():
        with open(report_path, "r", encoding="utf-8") as f:
            return f.read()
    return "No report generated yet. Run pipeline first."
