"""FastAPI REST API and Web Dashboard for Threat Intelligence Aggregator.

Includes non-blocking pipeline execution, API authentication, feed/allowlist management,
inline live enrichment, dry-run diff preview, and audit logging.
"""

from datetime import datetime, timezone
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Header, Query, Depends, status
from fastapi.responses import HTMLResponse, PlainTextResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from src.config_loader import AppConfig, BASE_DIR
from src.storage.database import init_db
from src.storage.repository import IOCRepository
from src.models import IOCType, Severity, IndicatorStatus
from src.pipeline_job import pipeline_job_manager
from src.exports.blocklists import calculate_blocklist_diff
from src.enrichment.abuseipdb import AbuseIPDBProvider
from src.enrichment.virustotal import VirusTotalProvider
from src.enrichment.cache import EnrichmentManager

logger = logging.getLogger("ti_aggregator.api")

app = FastAPI(
    title="ThreatForge API",
    description="ThreatForge: Autonomous Cyber Threat Intelligence Platform, STIX 2.1 Engine & Defensive Blocklist Generator.",
    version="1.2.0",
)

assets_dir = BASE_DIR / "assets"
if assets_dir.is_dir():
    app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")


@app.get("/logo.png", include_in_schema=False)
def get_brand_logo():
    logo_file = assets_dir / "threatforge_logo.png"
    if logo_file.is_file():
        return FileResponse(logo_file, media_type="image/png")
    raise HTTPException(status_code=404, detail="Logo not found")

config = AppConfig()
db_path = config.database_path
init_db(db_path)
repo = IOCRepository(db_path)


# ---------------------------------------------------------
# Security & API Key Verification
# ---------------------------------------------------------
def verify_api_key(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    api_key_query: Optional[str] = Query(None, alias="api_key"),
) -> bool:
    """Verifies API key on write/admin endpoints if one is configured in settings."""
    configured_key = config.api_settings.get("api_key", "").strip()
    if not configured_key:
        return True  # Open development mode

    provided_key = x_api_key or api_key_query
    if not provided_key or provided_key != configured_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API Key. Pass 'X-API-Key' header or '?api_key=' parameter.",
        )
    return True


# ---------------------------------------------------------
# Pydantic Schemas
# ---------------------------------------------------------
class FeedUpdateModel(BaseModel):
    status: Optional[str] = None  # "ACTIVE", "DISABLED"
    weight: Optional[float] = None


class FeedCreateModel(BaseModel):
    id: str
    name: str
    source_type: str = "url"
    path_or_url: str
    format: str = "txt"
    weight: float = 3.0


class AllowlistCreateModel(BaseModel):
    type: str  # "ip" or "domain"
    value: str
    reason: Optional[str] = "Manual administrative whitelist"


# ---------------------------------------------------------
# HTML Dashboard Template (Single Page Application)
# ---------------------------------------------------------
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ThreatForge - Cyber Threat Intelligence Platform</title>
  <link rel="icon" type="image/png" href="/assets/threatforge_logo.png">
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <style>
    body { background-color: #0d1117; color: #c9d1d9; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    .card { background-color: #161b22; border: 1px solid #30363d; }
    .tab-btn.active { border-bottom: 2px solid #3b82f6; color: #ffffff; font-weight: 600; }
  </style>
</head>
<body class="p-6">
  <div class="max-w-7xl mx-auto space-y-6">

    <!-- Header -->
    <header class="flex flex-col md:flex-row md:items-center md:justify-between pb-6 border-b border-gray-800 gap-4">
      <div class="flex items-center gap-4">
        <img src="/assets/threatforge_logo.png" alt="ThreatForge Logo" class="w-14 h-14 rounded-xl border border-blue-500/30 shadow-lg shadow-blue-500/20 object-cover">
        <div>
          <div class="flex items-center gap-3">
            <h1 class="text-3xl font-extrabold tracking-tight text-white flex items-center gap-2">
              Threat<span class="text-blue-500">Forge</span>
            </h1>
            <span class="px-2.5 py-0.5 text-xs font-semibold uppercase tracking-wider bg-blue-950 text-blue-400 border border-blue-800 rounded-full">v1.2</span>
          </div>
          <p class="text-xs text-gray-400 mt-1">Autonomous Cyber Threat Intelligence Aggregator, STIX 2.1 & Defensive Blocklist Engine</p>
        </div>
      </div>
      <div class="flex flex-wrap items-center gap-3">
        <button id="runBtn" onclick="runPipelineNonBlocking()" class="px-4 py-2 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 text-white font-medium rounded-lg text-sm shadow transition flex items-center gap-2">
          <i class="fa-solid fa-rotate"></i> <span id="runBtnText">Sync Feeds (Non-Blocking)</span>
        </button>
        <button onclick="openDiffModal()" class="px-4 py-2 bg-gray-800 hover:bg-gray-700 text-gray-200 font-medium rounded-lg text-sm border border-gray-700 transition flex items-center gap-2">
          <i class="fa-solid fa-code-compare text-yellow-400"></i> Preview Diff
        </button>
        <a href="/api/report" target="_blank" class="px-4 py-2 bg-gray-800 hover:bg-gray-700 text-gray-200 font-medium rounded-lg text-sm border border-gray-700 transition flex items-center gap-2">
          <i class="fa-solid fa-file-lines text-blue-400"></i> Report
        </a>
      </div>
    </header>

    <!-- Navigation Tabs -->
    <div class="flex border-b border-gray-800 gap-6 text-sm text-gray-400">
      <button class="tab-btn active pb-3" onclick="switchTab('threatsTab', this)">
        <i class="fa-solid fa-list-check mr-2"></i> Threats & Blocklists
      </button>
      <button class="tab-btn pb-3" onclick="switchTab('feedsTab', this)">
        <i class="fa-solid fa-rss mr-2"></i> Feed Management
      </button>
      <button class="tab-btn pb-3" onclick="switchTab('allowlistTab', this)">
        <i class="fa-solid fa-shield-check mr-2"></i> Allowlist Controls
      </button>
      <button class="tab-btn pb-3" onclick="switchTab('auditTab', this)">
        <i class="fa-solid fa-clock-rotate-left mr-2"></i> Audit Trail
      </button>
    </div>

    <!-- ================= TAB 1: THREATS & BLOCKLISTS ================= -->
    <div id="threatsTab" class="space-y-6">
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

      <!-- Charts & Exporters -->
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
            <i class="fa-solid fa-download text-emerald-400"></i> Ready Defensive Blocklists & Feeds
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
            <a href="/api/blocklists/stix" target="_blank" class="p-3 bg-gray-900 border border-gray-800 hover:border-indigo-500 rounded-lg flex items-center justify-between transition">
              <span><i class="fa-solid fa-cubes text-indigo-400 mr-2"></i> OASIS STIX 2.1 Bundle</span>
              <i class="fa-solid fa-arrow-up-right-from-square text-xs text-gray-500"></i>
            </a>
            <a href="/api/blocklists/json" target="_blank" class="p-3 bg-gray-900 border border-gray-800 hover:border-emerald-500 rounded-lg flex items-center justify-between transition">
              <span><i class="fa-solid fa-database text-emerald-400 mr-2"></i> Complete SIEM JSON</span>
              <i class="fa-solid fa-arrow-up-right-from-square text-xs text-gray-500"></i>
            </a>
          </div>
        </div>
      </div>

      <!-- IOC Table & Search -->
      <div class="card p-5 rounded-xl">
        <div class="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-4">
          <div>
            <h2 class="text-lg font-bold text-white flex items-center gap-2">
              <i class="fa-solid fa-table-list text-yellow-400"></i> Indicator Intelligence Table
            </h2>
            <p class="text-xs text-gray-400">Click any row to inspect full context and trigger live API enrichment</p>
          </div>
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
              <option value="ACTIVE">Active</option>
              <option value="EXPIRED">Expired (TTL)</option>
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
            <tbody id="iocTableBody" class="divide-y divide-gray-800 cursor-pointer">
              <tr><td colspan="7" class="py-6 text-center text-gray-500">Loading indicators...</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- ================= TAB 2: FEED MANAGEMENT ================= -->
    <div id="feedsTab" class="hidden space-y-6">
      <div class="card p-5 rounded-xl">
        <h2 class="text-lg font-bold text-white mb-2 flex items-center gap-2">
          <i class="fa-solid fa-rss text-red-400"></i> Threat Feed Management & Source Weights
        </h2>
        <p class="text-sm text-gray-400 mb-4">Enable or disable threat feeds and calibrate source trust weights without touching disk files.</p>
        <div class="overflow-x-auto">
          <table class="w-full text-left text-sm border-collapse">
            <thead>
              <tr class="border-b border-gray-800 text-gray-400 font-semibold uppercase text-xs">
                <th class="py-3 px-3">Feed ID</th>
                <th class="py-3 px-3">Feed Name</th>
                <th class="py-3 px-3">Type</th>
                <th class="py-3 px-3">Format</th>
                <th class="py-3 px-3">Weight (1-5)</th>
                <th class="py-3 px-3">Status</th>
                <th class="py-3 px-3">Actions</th>
              </tr>
            </thead>
            <tbody id="feedTableBody" class="divide-y divide-gray-800">
              <tr><td colspan="7" class="py-6 text-center text-gray-500">Loading feeds...</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- ================= TAB 3: ALLOWLIST CONTROLS ================= -->
    <div id="allowlistTab" class="hidden space-y-6">
      <div class="card p-5 rounded-xl">
        <h2 class="text-lg font-bold text-white mb-2 flex items-center gap-2">
          <i class="fa-solid fa-shield-check text-emerald-400"></i> Dynamic False-Positive Allowlist
        </h2>
        <p class="text-sm text-gray-400 mb-4">Add or remove safe IP addresses and domains. Changes take effect on the next aggregation cycle.</p>

        <!-- Add Form -->
        <div class="flex flex-wrap gap-3 mb-6 bg-gray-900 p-4 rounded-lg border border-gray-800">
          <select id="allowType" class="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm text-gray-200">
            <option value="ip">IP Address</option>
            <option value="domain">Domain Name</option>
          </select>
          <input id="allowValue" type="text" placeholder="e.g. 1.1.1.1 or company.com" class="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm text-gray-200 flex-1">
          <input id="allowReason" type="text" placeholder="Reason (e.g. Internal gateway / CDN)" class="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm text-gray-200 flex-1">
          <button onclick="addAllowlistEntry()" class="px-4 py-2 bg-emerald-600 hover:bg-emerald-700 text-white rounded-lg text-sm font-semibold transition">
            <i class="fa-solid fa-plus mr-1"></i> Add to Allowlist
          </button>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div class="bg-gray-900 p-4 rounded-lg border border-gray-800">
            <h3 class="font-bold text-white mb-3 text-sm">Safe IP Addresses</h3>
            <ul id="allowIpList" class="space-y-2 text-sm text-gray-300 max-h-64 overflow-y-auto"></ul>
          </div>
          <div class="bg-gray-900 p-4 rounded-lg border border-gray-800">
            <h3 class="font-bold text-white mb-3 text-sm">Safe Domains</h3>
            <ul id="allowDomainList" class="space-y-2 text-sm text-gray-300 max-h-64 overflow-y-auto"></ul>
          </div>
        </div>
      </div>
    </div>

    <!-- ================= TAB 4: AUDIT TRAIL ================= -->
    <div id="auditTab" class="hidden space-y-6">
      <div class="card p-5 rounded-xl">
        <h2 class="text-lg font-bold text-white mb-4 flex items-center gap-2">
          <i class="fa-solid fa-clock-rotate-left text-purple-400"></i> Administrative Audit Trail
        </h2>
        <div class="overflow-x-auto">
          <table class="w-full text-left text-sm border-collapse">
            <thead>
              <tr class="border-b border-gray-800 text-gray-400 font-semibold uppercase text-xs">
                <th class="py-3 px-3">Timestamp (UTC)</th>
                <th class="py-3 px-3">Action</th>
                <th class="py-3 px-3">Target</th>
                <th class="py-3 px-3">User</th>
                <th class="py-3 px-3">Details</th>
              </tr>
            </thead>
            <tbody id="auditTableBody" class="divide-y divide-gray-800 font-mono text-xs">
              <tr><td colspan="5" class="py-6 text-center text-gray-500">Loading audit trail...</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

  </div>

  <!-- IOC Inspector Modal -->
  <div id="iocModal" class="hidden fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50">
    <div class="card p-6 rounded-2xl max-w-2xl w-full space-y-4 max-h-[90vh] overflow-y-auto border border-gray-700 shadow-2xl">
      <div class="flex items-center justify-between pb-3 border-b border-gray-800">
        <h3 id="modalIocValue" class="text-lg font-bold text-white font-mono break-all"></h3>
        <button onclick="closeModal()" class="text-gray-400 hover:text-white text-lg"><i class="fa-solid fa-xmark"></i></button>
      </div>

      <div class="grid grid-cols-2 gap-3 text-sm">
        <div><span class="text-gray-400 text-xs">Type:</span> <div id="modalIocType" class="text-white font-semibold"></div></div>
        <div><span class="text-gray-400 text-xs">Severity:</span> <div id="modalIocSeverity"></div></div>
        <div><span class="text-gray-400 text-xs">Base Score:</span> <div id="modalIocScore" class="text-white font-semibold"></div></div>
        <div><span class="text-gray-400 text-xs">Decayed Score:</span> <div id="modalIocDecayed" class="text-white font-semibold"></div></div>
        <div><span class="text-gray-400 text-xs">Status:</span> <div id="modalIocStatus"></div></div>
        <div><span class="text-gray-400 text-xs">Reporting Sources:</span> <div id="modalIocSources" class="text-white"></div></div>
      </div>

      <div>
        <span class="text-gray-400 text-xs font-semibold uppercase">Feed Contexts / Tags:</span>
        <div id="modalIocContext" class="p-3 bg-gray-900 border border-gray-800 rounded-lg text-xs font-mono text-gray-300 mt-1 break-words"></div>
      </div>

      <!-- Live Enrichment Section -->
      <div class="p-4 bg-gray-900 border border-gray-800 rounded-xl space-y-3">
        <div class="flex items-center justify-between">
          <span class="font-bold text-white text-sm flex items-center gap-2">
            <i class="fa-solid fa-satellite-dish text-indigo-400"></i> External Reputation Cross-Check
          </span>
          <button id="modalEnrichBtn" onclick="enrichCurrentIOC()" class="px-3 py-1 bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-semibold rounded-md transition flex items-center gap-1">
            <i class="fa-solid fa-bolt"></i> Enrich Live
          </button>
        </div>
        <div id="modalEnrichContent" class="text-xs text-gray-400">No enrichment data cached. Click "Enrich Live" to query AbuseIPDB / VirusTotal.</div>
      </div>

      <div class="text-right">
        <button onclick="closeModal()" class="px-4 py-2 bg-gray-800 hover:bg-gray-700 text-gray-200 text-sm font-semibold rounded-lg transition">Close</button>
      </div>
    </div>
  </div>

  <!-- Diff Preview Modal -->
  <div id="diffModal" class="hidden fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50">
    <div class="card p-6 rounded-2xl max-w-3xl w-full space-y-4 max-h-[90vh] overflow-y-auto border border-gray-700 shadow-2xl">
      <div class="flex items-center justify-between pb-3 border-b border-gray-800">
        <h3 class="text-lg font-bold text-white flex items-center gap-2">
          <i class="fa-solid fa-code-compare text-yellow-400"></i> Blocklist Diff Preview (Dry-Run)
        </h3>
        <button onclick="closeDiffModal()" class="text-gray-400 hover:text-white text-lg"><i class="fa-solid fa-xmark"></i></button>
      </div>
      <p class="text-xs text-gray-400">Compares current active indicators with the most recent exported blocklist snapshot.</p>
      
      <div id="diffSummaryCards" class="grid grid-cols-3 gap-3 text-center text-sm"></div>

      <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div class="bg-gray-900 p-3 rounded-lg border border-gray-800">
          <h4 class="text-xs uppercase font-bold text-emerald-400 mb-2">Newly Added Threats</h4>
          <ul id="diffAddedList" class="space-y-1 text-xs text-gray-300 max-h-48 overflow-y-auto font-mono"></ul>
        </div>
        <div class="bg-gray-900 p-3 rounded-lg border border-gray-800">
          <h4 class="text-xs uppercase font-bold text-red-400 mb-2">Expired / Removed Threats</h4>
          <ul id="diffRemovedList" class="space-y-1 text-xs text-gray-300 max-h-48 overflow-y-auto font-mono"></ul>
        </div>
      </div>

      <div class="text-right">
        <button onclick="closeDiffModal()" class="px-4 py-2 bg-gray-800 hover:bg-gray-700 text-gray-200 text-sm font-semibold rounded-lg transition">Close</button>
      </div>
    </div>
  </div>

  <script>
    let chartInstance = null;
    let selectedIOC = null;
    let isPolling = false;

    function switchTab(tabId, btn) {
      ['threatsTab', 'feedsTab', 'allowlistTab', 'auditTab'].forEach(id => {
        document.getElementById(id).classList.add('hidden');
      });
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.getElementById(tabId).classList.remove('hidden');
      btn.classList.add('active');

      if (tabId === 'feedsTab') loadFeeds();
      if (tabId === 'allowlistTab') loadAllowlist();
      if (tabId === 'auditTab') loadAuditTrail();
    }

    async function loadStats() {
      try {
        const res = await fetch('/api/stats');
        const data = await res.json();
        document.getElementById('statTotal').innerText = data.total_unique_iocs || 0;
        document.getElementById('statHigh').innerText = (data.breakdown_by_severity && data.breakdown_by_severity.HIGH) || 0;
        document.getElementById('statMed').innerText = (data.breakdown_by_severity && data.breakdown_by_severity.MEDIUM) || 0;
        document.getElementById('statLow').innerText = (data.breakdown_by_severity && data.breakdown_by_severity.LOW) || 0;
        document.getElementById('statExpired').innerText = (data.breakdown_by_status && data.breakdown_by_status.EXPIRED) || 0;

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
            <tr class="hover:bg-gray-900 transition" onclick='inspectIOC(${JSON.stringify(i).replace(/'/g, "&#39;")})'>
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

    async function inspectIOC(ioc) {
      selectedIOC = ioc;
      document.getElementById('modalIocValue').innerText = ioc.value;
      document.getElementById('modalIocType').innerText = ioc.type;
      document.getElementById('modalIocSeverity').innerText = ioc.severity;
      document.getElementById('modalIocScore').innerText = ioc.score;
      document.getElementById('modalIocDecayed').innerText = ioc.decayed_score;
      document.getElementById('modalIocStatus').innerText = ioc.status;
      document.getElementById('modalIocSources').innerText = (ioc.sources || []).join(', ') || 'N/A';
      document.getElementById('modalIocContext').innerText = (ioc.contexts || []).join('\\n') || 'None recorded.';

      // Fetch cached enrichment
      const enrichDiv = document.getElementById('modalEnrichContent');
      enrichDiv.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Checking enrichment cache...';
      try {
        const res = await fetch(`/api/iocs/${encodeURIComponent(ioc.value)}`);
        const data = await res.json();
        if (data.enrichment) {
          enrichDiv.innerHTML = `
            <div class="text-white font-semibold">Provider: ${data.enrichment.provider}</div>
            <div>Score: <span class="font-bold text-yellow-400">${data.enrichment.reputation_score}%</span></div>
            <div>Summary: ${data.enrichment.raw_payload ? JSON.stringify(data.enrichment.raw_payload).slice(0, 150) + '...' : 'Available'}</div>
            <div class="text-gray-500 text-[10px]">Cached: ${data.enrichment.cached_at}</div>
          `;
        } else {
          enrichDiv.innerHTML = 'No cached reputation data. Click "Enrich Live" to query external APIs.';
        }
      } catch (e) {
        enrichDiv.innerText = 'Error loading enrichment.';
      }

      document.getElementById('iocModal').classList.remove('hidden');
    }

    function closeModal() {
      document.getElementById('iocModal').classList.add('hidden');
    }

    async function enrichCurrentIOC() {
      if (!selectedIOC) return;
      const enrichDiv = document.getElementById('modalEnrichContent');
      const btn = document.getElementById('modalEnrichBtn');
      btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Querying...';
      btn.disabled = true;

      try {
        const res = await fetch(`/api/iocs/${encodeURIComponent(selectedIOC.value)}/enrich`, { method: 'POST' });
        const data = await res.json();
        if (data.result) {
          enrichDiv.innerHTML = `
            <div class="text-white font-semibold">Provider: ${data.result.provider}</div>
            <div>Score: <span class="font-bold text-yellow-400">${data.result.reputation_score}%</span></div>
            <div>Summary: ${data.result.summary}</div>
            <div class="text-emerald-400 text-xs mt-1">Live query completed and cached!</div>
          `;
        } else {
          enrichDiv.innerHTML = '<span class="text-yellow-400">No external provider returned data (check API keys in .env).</span>';
        }
      } catch (e) {
        enrichDiv.innerText = 'Enrichment failed: ' + e;
      } finally {
        btn.innerHTML = '<i class="fa-solid fa-bolt"></i> Enrich Live';
        btn.disabled = false;
      }
    }

    // ================= NON-BLOCKING PIPELINE EXECUTION =================
    async function runPipelineNonBlocking() {
      const btn = document.getElementById('runBtn');
      const btnText = document.getElementById('runBtnText');
      btnText.innerText = 'Starting...';
      btn.disabled = true;

      try {
        const res = await fetch('/api/pipeline/run', { method: 'POST' });
        const data = await res.json();
        if (data.status === 'RUNNING' || data.status === 'STARTED' || data.status === 'ALREADY_RUNNING') {
          pollPipelineStatus();
        }
      } catch (e) {
        alert("Failed to start pipeline: " + e);
        btnText.innerText = 'Sync Feeds (Non-Blocking)';
        btn.disabled = false;
      }
    }

    async function pollPipelineStatus() {
      const btn = document.getElementById('runBtn');
      const btnText = document.getElementById('runBtnText');

      const interval = setInterval(async () => {
        try {
          const res = await fetch('/api/pipeline/status');
          const status = await res.json();

          if (status.status === 'RUNNING') {
            btnText.innerHTML = '<i class="fa-solid fa-spinner fa-spin mr-1"></i> Syncing (' + (status.job_id || '') + ')...';
          } else {
            clearInterval(interval);
            btnText.innerText = 'Sync Feeds (Non-Blocking)';
            btn.disabled = false;
            await loadStats();
            await loadIOCs();
          }
        } catch (e) {
          clearInterval(interval);
          btnText.innerText = 'Sync Feeds (Non-Blocking)';
          btn.disabled = false;
        }
      }, 1500);
    }

    // ================= FEEDS TAB =================
    async function loadFeeds() {
      try {
        const res = await fetch('/api/feeds');
        const feeds = await res.json();
        const tbody = document.getElementById('feedTableBody');
        tbody.innerHTML = feeds.map(f => {
          const isActive = f.status === 'ACTIVE';
          const toggleBtn = isActive
            ? `<button onclick="updateFeed('${f.feed_id}', 'DISABLED', ${f.weight})" class="px-2 py-1 bg-red-900/60 hover:bg-red-800 text-red-300 rounded text-xs">Disable</button>`
            : `<button onclick="updateFeed('${f.feed_id}', 'ACTIVE', ${f.weight})" class="px-2 py-1 bg-emerald-900/60 hover:bg-emerald-800 text-emerald-300 rounded text-xs">Enable</button>`;

          return `
            <tr class="hover:bg-gray-900">
              <td class="py-3 px-3 font-mono text-xs text-white">${f.feed_id}</td>
              <td class="py-3 px-3 text-xs text-gray-200">${f.name}</td>
              <td class="py-3 px-3 text-xs text-gray-400">${f.source_type}</td>
              <td class="py-3 px-3 text-xs text-gray-400">${f.format}</td>
              <td class="py-3 px-3 text-xs text-white font-semibold">
                <input type="number" step="0.5" min="1" max="5" value="${f.weight}" onchange="updateFeed('${f.feed_id}', '${f.status}', this.value)" class="w-16 px-1 py-0.5 bg-gray-900 border border-gray-700 rounded text-center">
              </td>
              <td class="py-3 px-3 text-xs font-semibold ${isActive ? 'text-emerald-400' : 'text-gray-500'}">${f.status}</td>
              <td class="py-3 px-3 text-xs">${toggleBtn}</td>
            </tr>
          `;
        }).join('');
      } catch (e) {
        console.error("Failed to load feeds", e);
      }
    }

    async function updateFeed(feedId, status, weight) {
      try {
        await fetch(`/api/feeds/${encodeURIComponent(feedId)}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ status: status, weight: parseFloat(weight) })
        });
        await loadFeeds();
      } catch (e) {
        alert("Failed to update feed: " + e);
      }
    }

    // ================= ALLOWLIST TAB =================
    async function loadAllowlist() {
      try {
        const res = await fetch('/api/allowlist');
        const data = await res.json();
        
        const ipList = document.getElementById('allowIpList');
        ipList.innerHTML = (data.ips || []).map(ip => `
          <li class="flex items-center justify-between p-2 bg-gray-800/60 rounded">
            <span class="font-mono text-xs text-white">${ip}</span>
            <button onclick="removeAllowlistEntry('${ip}')" class="text-red-400 hover:text-red-300 text-xs"><i class="fa-solid fa-trash"></i></button>
          </li>
        `).join('');

        const domainList = document.getElementById('allowDomainList');
        domainList.innerHTML = (data.domains || []).map(dom => `
          <li class="flex items-center justify-between p-2 bg-gray-800/60 rounded">
            <span class="font-mono text-xs text-white">${dom}</span>
            <button onclick="removeAllowlistEntry('${dom}')" class="text-red-400 hover:text-red-300 text-xs"><i class="fa-solid fa-trash"></i></button>
          </li>
        `).join('');
      } catch (e) {
        console.error("Failed to load allowlist", e);
      }
    }

    async function addAllowlistEntry() {
      const type = document.getElementById('allowType').value;
      const value = document.getElementById('allowValue').value.trim();
      const reason = document.getElementById('allowReason').value.trim();
      if (!value) return;

      try {
        await fetch('/api/allowlist', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ type: type, value: value, reason: reason })
        });
        document.getElementById('allowValue').value = '';
        document.getElementById('allowReason').value = '';
        await loadAllowlist();
      } catch (e) {
        alert("Failed to add allowlist entry: " + e);
      }
    }

    async function removeAllowlistEntry(val) {
      try {
        await fetch(`/api/allowlist/${encodeURIComponent(val)}`, { method: 'DELETE' });
        await loadAllowlist();
      } catch (e) {
        alert("Failed to delete allowlist entry: " + e);
      }
    }

    // ================= DIFF MODAL =================
    async function openDiffModal() {
      document.getElementById('diffModal').classList.remove('hidden');
      const cards = document.getElementById('diffSummaryCards');
      cards.innerHTML = '<div class="col-span-3 text-gray-400"><i class="fa-solid fa-spinner fa-spin"></i> Calculating diff...</div>';

      try {
        const res = await fetch('/api/blocklists/diff');
        const diff = await res.json();

        cards.innerHTML = `
          <div class="card p-3 rounded-lg"><div class="text-gray-400 text-xs">Active Indicators</div><div class="text-xl font-bold text-white">${diff.total_active}</div></div>
          <div class="card p-3 rounded-lg border-l-2 border-l-emerald-500"><div class="text-emerald-400 text-xs">Newly Added</div><div class="text-xl font-bold text-emerald-400">+${diff.added_count}</div></div>
          <div class="card p-3 rounded-lg border-l-2 border-l-red-500"><div class="text-red-400 text-xs">Expired / Dropped</div><div class="text-xl font-bold text-red-400">-${diff.removed_or_expired_count}</div></div>
        `;

        const addList = document.getElementById('diffAddedList');
        addList.innerHTML = (diff.added || []).map(a => `<li>+ ${a.value} (${a.type})</li>`).join('') || '<li class="text-gray-500">None</li>';

        const remList = document.getElementById('diffRemovedList');
        remList.innerHTML = (diff.removed_or_expired || []).map(r => `<li>- ${r}</li>`).join('') || '<li class="text-gray-500">None</li>';
      } catch (e) {
        cards.innerHTML = '<div class="col-span-3 text-red-400">Failed to calculate diff.</div>';
      }
    }

    function closeDiffModal() {
      document.getElementById('diffModal').classList.add('hidden');
    }

    // ================= AUDIT TRAIL =================
    async function loadAuditTrail() {
      try {
        const res = await fetch('/api/audit');
        const logs = await res.json();
        const tbody = document.getElementById('auditTableBody');
        tbody.innerHTML = logs.map(l => `
          <tr class="hover:bg-gray-900">
            <td class="py-2 px-3 text-gray-400">${l.timestamp}</td>
            <td class="py-2 px-3 text-white font-semibold">${l.action}</td>
            <td class="py-2 px-3 text-yellow-400">${l.target}</td>
            <td class="py-2 px-3 text-gray-300">${l.user}</td>
            <td class="py-2 px-3 text-gray-400">${l.details || '-'}</td>
          </tr>
        `).join('');
      } catch (e) {
        console.error("Failed to load audit trail", e);
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


@app.post("/api/iocs/{value}/enrich")
def enrich_single_indicator(value: str, auth: bool = Depends(verify_api_key)):
    """Triggers live external API enrichment for a single indicator."""
    ioc = repo.get_indicator_by_value(value)
    if not ioc:
        raise HTTPException(status_code=404, detail="Indicator not found in threat database")

    enrich_mgr = EnrichmentManager(
        repository=repo,
        providers=[AbuseIPDBProvider(), VirusTotalProvider()],
        ttl_days_map=config.cache_ttl_days,
    )
    result = enrich_mgr.enrich_indicator(ioc.value, ioc.ioc_type)
    repo.record_audit_log("LIVE_ENRICH", ioc.value, f"Result: {bool(result)}")
    return {"ioc": ioc.value, "result": result.__dict__ if result else None}


# ---------------------------------------------------------
# Non-Blocking Pipeline Execution
# ---------------------------------------------------------
@app.post("/api/pipeline/run", status_code=status.HTTP_202_ACCEPTED)
def trigger_pipeline_async(auth: bool = Depends(verify_api_key)):
    """Triggers the pipeline as an asynchronous background job."""
    started, job_id = pipeline_job_manager.start_job(config, enrich_high=False)
    if not started:
        return {"status": "ALREADY_RUNNING", "message": job_id}
    repo.record_audit_log("TRIGGER_PIPELINE", job_id, "Non-blocking background run initiated")
    return {"status": "STARTED", "job_id": job_id, "message": "Aggregation pipeline is running in background."}


@app.get("/api/pipeline/status")
def get_pipeline_job_status():
    """Polls the status of the current or most recent pipeline execution."""
    return pipeline_job_manager.get_status()


# ---------------------------------------------------------
# Feed Management Endpoints
# ---------------------------------------------------------
@app.get("/api/feeds")
def list_feeds():
    """Lists all configured threat feeds and their live statuses."""
    return repo.get_all_feeds()


@app.put("/api/feeds/{feed_id}")
def update_feed(feed_id: str, payload: FeedUpdateModel, auth: bool = Depends(verify_api_key)):
    """Enables/disables a feed or updates its source weight."""
    success = repo.update_feed_config(feed_id, status=payload.status, weight=payload.weight)
    if not success:
        raise HTTPException(status_code=404, detail="Feed ID not found")
    repo.record_audit_log("UPDATE_FEED", feed_id, f"status={payload.status}, weight={payload.weight}")
    return {"status": "SUCCESS", "feed_id": feed_id}


# ---------------------------------------------------------
# Allowlist Endpoints
# ---------------------------------------------------------
@app.get("/api/allowlist")
def get_allowlist():
    """Returns static and dynamic safe IPs and domains."""
    dynamic = repo.get_dynamic_allowlist()
    return {
        "ips": sorted(list(config.safe_ips | dynamic.get("ips", set()))),
        "domains": sorted(list(config.safe_domains | dynamic.get("domains", set()))),
    }


@app.post("/api/allowlist")
def add_allowlist_entry(payload: AllowlistCreateModel, auth: bool = Depends(verify_api_key)):
    """Adds an entry to the dynamic allowlist."""
    success = repo.add_dynamic_allowlist(payload.type, payload.value, payload.reason or "")
    if not success:
        raise HTTPException(status_code=400, detail="Failed to add allowlist entry")
    repo.record_audit_log("ADD_ALLOWLIST", payload.value, f"type={payload.type}, reason={payload.reason}")
    return {"status": "SUCCESS", "entry": payload.value}


@app.delete("/api/allowlist/{value}")
def delete_allowlist_entry(value: str, auth: bool = Depends(verify_api_key)):
    """Removes an entry from the dynamic allowlist."""
    success = repo.remove_dynamic_allowlist(value)
    repo.record_audit_log("REMOVE_ALLOWLIST", value, "Entry removed by analyst")
    return {"status": "SUCCESS", "deleted": success, "value": value}


# ---------------------------------------------------------
# Blocklist Exporters & Diff Preview
# ---------------------------------------------------------
@app.get("/api/blocklists/diff")
def get_blocklist_diff():
    """Calculates dry-run diff between current active indicators and the previous export snapshot."""
    active_iocs = repo.get_all_scored_indicators(status="ACTIVE")
    previous_snapshot = repo.get_latest_blocklist_snapshot()
    return calculate_blocklist_diff(active_iocs, previous_snapshot)


@app.get("/api/blocklists/{target}")
def get_blocklist(target: str):
    """Downloads formatted blocklists."""
    paths = config.export_paths
    target_lower = target.lower()

    target_map = {
        "firewall": (paths["firewall_ips"], "text/plain", "blocklist_firewall.txt"),
        "dns": (paths["dns_domains"], "text/plain", "blocklist_dns.txt"),
        "proxy": (paths["proxy_urls"], "text/plain", "blocklist_proxy.txt"),
        "edr": (paths["edr_hashes"], "text/csv", "blocklist_edr.csv"),
        "json": (paths["all_json"], "application/json", "threat_intel_full.json"),
        "stix": (paths["stix_bundle"], "application/json", "threat_intel_stix2.json"),
        "stix2": (paths["stix_bundle"], "application/json", "threat_intel_stix2.json"),
    }

    if target_lower not in target_map:
        raise HTTPException(
            status_code=400,
            detail="Unknown blocklist target. Use: firewall, dns, proxy, edr, json, or stix",
        )

    file_path, media_type, filename = target_map[target_lower]
    if not file_path.is_file():
        raise HTTPException(
            status_code=404,
            detail=f"Blocklist file for '{target}' has not been generated yet. Run pipeline first.",
        )

    return FileResponse(file_path, media_type=media_type, filename=filename)


@app.get("/api/report", response_class=PlainTextResponse)
def get_report():
    """Returns the executive markdown report."""
    report_path = config.export_paths["summary_report"]
    if report_path.is_file():
        with open(report_path, "r", encoding="utf-8") as f:
            return f.read()
    return "No report generated yet. Run pipeline first."


@app.get("/api/audit")
def get_audit_trail(limit: int = 50):
    """Returns recent administrative audit log entries."""
    return repo.get_audit_logs(limit=limit)
