/**
 * TelemetryLab - Detection Engineering & Telemetry Playground Frontend
 */

// Global State
let editorInstance = null;
let cachedTables = [];
let cachedRules = [];
let lastQueryResults = null;
let streamPollInterval = null;

// Built-in SQL Snippets
const SQL_SNIPPETS = {
  "snippet-powershell": `-- T1059.001: Malicious PowerShell Download Cradle via Office Process
SELECT id, timestamp, host_name, user_name, process_name, parent_process_name, command_line
FROM endpoint_process
WHERE LOWER(parent_process_name) IN ('winword.exe', 'excel.exe', 'outlook.exe')
  AND LOWER(process_name) IN ('powershell.exe', 'cmd.exe')
  AND (command_line REGEXP '(?i)(downloadstring|iex|invoke-expression|-enc)');`,

  "snippet-lsass": `-- T1003.001: OS Credential Dumping via LSASS Memory Dump
SELECT id, timestamp, host_name, user_name, process_name, command_line
FROM endpoint_process
WHERE (command_line REGEXP '(?i)(procdump.*-ma.*lsass|comsvcs.*minidump)')
   OR (LOWER(command_line) LIKE '%lsass.dmp%');`,

  "snippet-spray": `-- T1110.003: Password Spraying across multiple accounts
SELECT src_ip, COUNT(DISTINCT user_name) AS targeted_users, COUNT(*) AS failure_count, 
       GROUP_CONCAT(DISTINCT user_name) AS users, MIN(timestamp) AS start_time, MAX(timestamp) AS end_time
FROM identity_auth
WHERE auth_status = 'FAILURE'
GROUP BY src_ip
HAVING COUNT(DISTINCT user_name) >= 4;`,

  "snippet-entropy": `-- T1071.004: DNS Tunneling / DGA via High Shannon Entropy Queries
SELECT id, timestamp, host_name, src_ip, query, query_length, ENTROPY(query) AS entropy_score
FROM network_dns
WHERE query_length > 25
  AND ENTROPY(query) > 3.6
  AND query NOT LIKE '%.corp.local';`,

  "snippet-exfil": `-- T1048: Massive Outbound Network Flow Exfiltration (> 1GB)
SELECT id, timestamp, src_ip, dest_ip, dest_port, protocol, bytes_sent,
       ROUND(bytes_sent / 1073741824.0, 2) AS gb_sent
FROM network_flow
WHERE bytes_sent > 1000000000
  AND IP_IN_CIDR(src_ip, '10.0.0.0/8')
  AND NOT IP_IN_CIDR(dest_ip, '10.0.0.0/8');`,

  "snippet-cte": `-- Advanced SQL: Recursive CTE for Process Lineage & Ancestry
WITH RECURSIVE ProcessTree AS (
    SELECT id, timestamp, host_name, user_name, process_name, process_id, parent_process_id,
           parent_process_name, command_line, 0 AS depth, process_name AS tree_path
    FROM endpoint_process
    WHERE process_name IN ('powershell.exe', 'cmd.exe', 'procdump64.exe')
    
    UNION ALL
    
    SELECT p.id, p.timestamp, p.host_name, p.user_name, p.process_name, p.process_id,
           p.parent_process_id, p.parent_process_name, p.command_line, pt.depth + 1,
           p.process_name || ' -> ' || pt.tree_path
    FROM endpoint_process p
    JOIN ProcessTree pt ON p.process_id = pt.parent_process_id AND p.host_name = pt.host_name
    WHERE pt.depth < 5
)
SELECT host_name, user_name, process_id, process_name, parent_process_name, command_line, depth, tree_path
FROM ProcessTree
ORDER BY host_name, depth DESC;`,

  "snippet-baseline-proc": `-- Baseline: Process Execution Frequency by User
SELECT user_name, process_name, COUNT(*) AS execution_count
FROM endpoint_process
GROUP BY user_name, process_name
ORDER BY execution_count DESC;`,

  "snippet-baseline-net": `-- Baseline: External Outbound Ports Breakdown
SELECT dest_port, app_proto, COUNT(*) AS session_count, SUM(bytes_sent) AS total_outbound_bytes
FROM network_flow
WHERE NOT IP_IN_CIDR(dest_ip, '10.0.0.0/8')
GROUP BY dest_port, app_proto
ORDER BY session_count DESC;`
};

// Initialize on DOM Ready
document.addEventListener("DOMContentLoaded", () => {
  initEditor();
  initTabs();
  initEventListeners();
  loadTables();
  loadRules();
  loadMitre();
  checkStreamStatus();
});

// Setup Code Editor (CodeMirror with Fallback)
function initEditor() {
  const textarea = document.getElementById("sql-editor");
  if (window.CodeMirror) {
    editorInstance = CodeMirror.fromTextArea(textarea, {
      mode: "text/x-sql",
      theme: "dracula",
      lineNumbers: true,
      indentWithTabs: false,
      smartIndent: true,
      matchBrackets: true,
      autofocus: true,
      extraKeys: {
        "Cmd-Enter": () => runQuery(),
        "Ctrl-Enter": () => runQuery(),
        "Ctrl-Space": "autocomplete"
      }
    });
  } else {
    // Fallback: keyboard handler on native textarea
    textarea.addEventListener("keydown", (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
        e.preventDefault();
        runQuery();
      }
    });
  }
}

function getQueryText() {
  return editorInstance ? editorInstance.getValue() : document.getElementById("sql-editor").value;
}

function setQueryText(text) {
  if (editorInstance) {
    editorInstance.setValue(text);
  } else {
    document.getElementById("sql-editor").value = text;
  }
}

// Navigation Tabs
function initTabs() {
  const tabs = document.querySelectorAll(".nav-tab");
  tabs.forEach(tab => {
    tab.addEventListener("click", () => {
      tabs.forEach(t => t.classList.remove("active"));
      document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));
      tab.classList.add("active");
      const targetId = tab.dataset.tab;
      document.getElementById(targetId).classList.add("active");
      if (targetId === "tab-query" && editorInstance) {
        editorInstance.refresh();
      }
    });
  });
}

function switchTab(tabId) {
  const tabBtn = document.querySelector(`.nav-tab[data-tab="${tabId}"]`);
  if (tabBtn) tabBtn.click();
}

// Event Listeners
function initEventListeners() {
  document.getElementById("btn-run-query").addEventListener("click", runQuery);
  document.getElementById("btn-clear-query").addEventListener("click", () => setQueryText(""));
  document.getElementById("btn-refresh-tables").addEventListener("click", loadTables);
  document.getElementById("btn-run-all-rules").addEventListener("click", runAllRules);
  document.getElementById("btn-export-csv").addEventListener("click", exportResultsCSV);
  document.getElementById("btn-export-json").addEventListener("click", exportResultsJSON);
  document.getElementById("btn-export-dump").addEventListener("click", exportGitDump);

  // Snippets dropdown
  document.getElementById("select-query-snippet").addEventListener("change", (e) => {
    const key = e.target.value;
    if (key && SQL_SNIPPETS[key]) {
      setQueryText(SQL_SNIPPETS[key]);
      switchTab("tab-query");
    }
  });

  // Table filter search
  document.getElementById("table-search-input").addEventListener("input", (e) => {
    const term = e.target.value.toLowerCase();
    document.querySelectorAll(".table-item").forEach(item => {
      const name = item.dataset.tableName.toLowerCase();
      item.style.display = name.includes(term) ? "flex" : "none";
    });
  });

  // Results search
  document.getElementById("results-filter-input").addEventListener("input", filterResultsTable);

  // Schema Pattern Buttons
  document.getElementById("btn-pattern-preview").addEventListener("click", () => runPatternRename(true));
  document.getElementById("btn-pattern-apply").addEventListener("click", () => runPatternRename(false));
  document.getElementById("btn-apply-col-rename").addEventListener("click", runSingleColumnRename);

  // Ingest & Seeding
  document.getElementById("btn-seed-telemetry").addEventListener("click", seedTelemetry);
  document.getElementById("btn-reset-db").addEventListener("click", resetDatabase);
  document.getElementById("btn-stream-toggle").addEventListener("click", toggleLiveStream);
  document.getElementById("btn-toggle-stream-card").addEventListener("click", toggleLiveStream);
  document.getElementById("btn-submit-ingest").addEventListener("click", submitIngest);

  // Rule Filters
  document.getElementById("filter-rule-severity").addEventListener("change", filterRulesList);
  document.getElementById("filter-rule-tactic").addEventListener("change", filterRulesList);

  // Rename table selection change
  document.getElementById("rename-table-select").addEventListener("change", updateColumnOptions);
}

// -----------------------------------------------------------------------------
// API CALLS & DATA HANDLING
// -----------------------------------------------------------------------------

async function loadTables() {
  try {
    const res = await fetch("/api/tables");
    const data = await res.json();
    if (!data.success) return;

    cachedTables = data.tables;
    const list = document.getElementById("tables-list");
    list.innerHTML = "";

    let totalEvents = 0;
    const renameTableSelect = document.getElementById("rename-table-select");
    renameTableSelect.innerHTML = "";

    data.tables.forEach(t => {
      totalEvents += t.row_count;

      const li = document.createElement("li");
      li.className = "table-item";
      li.dataset.tableName = t.name;
      li.innerHTML = `
        <span class="table-name">${t.name}</span>
        <span class="table-count-badge">${t.row_count.toLocaleString()}</span>
      `;
      li.addEventListener("click", () => {
        setQueryText(`SELECT * FROM ${t.name} LIMIT 50;`);
        switchTab("tab-query");
        runQuery();
      });
      list.appendChild(li);

      // Populate schema selector
      const opt = document.createElement("option");
      opt.value = t.name;
      opt.textContent = `${t.name} (${t.column_count} cols)`;
      renameTableSelect.appendChild(opt);
    });

    document.getElementById("stat-tables-count").textContent = data.tables.length;
    document.getElementById("stat-events-count").textContent = totalEvents.toLocaleString();
    updateColumnOptions();
  } catch (err) {
    console.error("Failed to load tables:", err);
  }
}

function updateColumnOptions() {
  const selectedTable = document.getElementById("rename-table-select").value;
  const colSelect = document.getElementById("rename-col-select");
  colSelect.innerHTML = "";

  const tableMeta = cachedTables.find(t => t.name === selectedTable);
  if (tableMeta && tableMeta.columns) {
    tableMeta.columns.forEach(c => {
      const opt = document.createElement("option");
      opt.value = c.name;
      opt.textContent = `${c.name} (${c.type})`;
      colSelect.appendChild(opt);
    });
  }
}

async function runQuery() {
  const sql = getQueryText().trim();
  if (!sql) return;

  const badge = document.getElementById("query-meta-badge");
  badge.textContent = "Executing...";
  badge.style.color = "var(--color-amber)";

  const limit = parseInt(document.getElementById("select-row-limit").value) || 500;

  try {
    const res = await fetch("/api/query", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: jsonStringifySafe({ sql, limit })
    });
    const result = await res.json();

    if (!result.success) {
      badge.textContent = "Error";
      badge.style.color = "var(--color-rose)";
      renderError(result.error);
      return;
    }

    badge.textContent = `${result.execution_time_ms} ms`;
    badge.style.color = "var(--color-emerald)";

    if (result.is_select) {
      lastQueryResults = result;
      renderTable(result.columns, result.rows, result.execution_time_ms);
    } else {
      lastQueryResults = null;
      renderNonSelect(result.rows_affected, result.execution_time_ms);
      loadTables();
    }
  } catch (err) {
    badge.textContent = "Network Error";
    badge.style.color = "var(--color-rose)";
    renderError(err.message);
  }
}

function renderTable(columns, rows, executionTime) {
  const thead = document.getElementById("results-thead");
  const tbody = document.getElementById("results-tbody");
  const countText = document.getElementById("results-count-text");
  const timingText = document.getElementById("results-timing-text");

  countText.textContent = `${rows.length.toLocaleString()} rows`;
  timingText.textContent = `(${executionTime} ms)`;

  thead.innerHTML = "";
  tbody.innerHTML = "";

  if (columns.length === 0 || rows.length === 0) {
    thead.innerHTML = "<th>Result</th>";
    tbody.innerHTML = "<tr><td class='empty-state'>No rows matched the query.</td></tr>";
    return;
  }

  columns.forEach(col => {
    const th = document.createElement("th");
    th.textContent = col;
    thead.appendChild(th);
  });

  rows.forEach(row => {
    const tr = document.createElement("tr");
    columns.forEach(col => {
      const td = document.createElement("td");
      const val = row[col];
      td.textContent = val !== null && val !== undefined ? String(val) : "NULL";
      if (val === null || val === undefined) td.style.color = "var(--text-muted)";
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  });
}

function renderNonSelect(affected, executionTime) {
  const thead = document.getElementById("results-thead");
  const tbody = document.getElementById("results-tbody");
  thead.innerHTML = "<th>Status</th><th>Rows Affected</th><th>Time</th>";
  tbody.innerHTML = `<tr>
    <td style="color: var(--color-emerald)">SUCCESS</td>
    <td>${affected !== undefined ? affected : "0"}</td>
    <td>${executionTime} ms</td>
  </tr>`;
  document.getElementById("results-count-text").textContent = "Statement executed";
  document.getElementById("results-timing-text").textContent = `(${executionTime} ms)`;
}

function renderError(errorMsg) {
  const thead = document.getElementById("results-thead");
  const tbody = document.getElementById("results-tbody");
  thead.innerHTML = "<th style='color: var(--color-rose)'>Query Error</th>";
  tbody.innerHTML = `<tr><td style='color: var(--color-rose); padding: 20px; font-family: var(--font-mono);'>${escapeHtml(errorMsg)}</td></tr>`;
  document.getElementById("results-count-text").textContent = "Failed";
  document.getElementById("results-timing-text").textContent = "";
}

function filterResultsTable() {
  const term = document.getElementById("results-filter-input").value.toLowerCase();
  const rows = document.querySelectorAll("#results-tbody tr");
  rows.forEach(tr => {
    const text = tr.textContent.toLowerCase();
    tr.style.display = text.includes(term) ? "" : "none";
  });
}

function exportResultsCSV() {
  if (!lastQueryResults || !lastQueryResults.rows || lastQueryResults.rows.length === 0) {
    alert("No query results to export.");
    return;
  }
  const cols = lastQueryResults.columns;
  const csvRows = [cols.join(",")];
  lastQueryResults.rows.forEach(row => {
    const vals = cols.map(c => {
      const v = row[c] === null || row[c] === undefined ? "" : String(row[c]);
      return `"${v.replace(/"/g, '""')}"`;
    });
    csvRows.push(vals.join(","));
  });
  downloadBlob(csvRows.join("\n"), "telemetry_query_results.csv", "text/csv");
}

function exportResultsJSON() {
  if (!lastQueryResults || !lastQueryResults.rows) {
    alert("No query results to export.");
    return;
  }
  const jsonStr = JSON.stringify(lastQueryResults.rows, null, 2);
  downloadBlob(jsonStr, "telemetry_query_results.json", "application/json");
}

async function exportGitDump() {
  try {
    const res = await fetch("/api/export/dump");
    const data = await res.json();
    if (data.success) {
      alert(`Git dump exported successfully.\nFile: ${data.dump.dump_file}\nSize: ${data.dump.size_kb} KB`);
    }
  } catch (err) {
    alert("Failed to export dump: " + err.message);
  }
}

// -----------------------------------------------------------------------------
// DETECTION RULES LOGIC
// -----------------------------------------------------------------------------

async function loadRules() {
  try {
    const res = await fetch("/api/rules");
    const data = await res.json();
    if (!data.success) return;

    cachedRules = data.rules;
    document.getElementById("tab-rules-count").textContent = cachedRules.length;
    renderRulesGrid(cachedRules);

    // Populate tactics filter
    const tactics = [...new Set(cachedRules.map(r => r.mitre_tactic).filter(Boolean))];
    const tacticSelect = document.getElementById("filter-rule-tactic");
    tacticSelect.innerHTML = '<option value="ALL">All Tactics</option>';
    tactics.forEach(t => {
      const opt = document.createElement("option");
      opt.value = t;
      opt.textContent = t;
      tacticSelect.appendChild(opt);
    });
  } catch (err) {
    console.error("Failed to load rules:", err);
  }
}

function renderRulesGrid(rules) {
  const grid = document.getElementById("rules-grid");
  grid.innerHTML = "";

  rules.forEach(r => {
    const card = document.createElement("div");
    card.className = "rule-card";
    const sevClass = `badge-sev-${(r.severity || 'low').toLowerCase()}`;

    card.innerHTML = `
      <div class="rule-card-header">
        <div>
          <span style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--color-cyan); font-weight: 600;">[${r.rule_id}]</span>
          <div class="rule-title">${escapeHtml(r.name)}</div>
        </div>
        <div class="rule-badges">
          <span class="${sevClass}">${r.severity}</span>
        </div>
      </div>
      <div class="rule-desc">${escapeHtml(r.description || '')}</div>
      <div class="rule-mitre-meta">
        <span>${r.mitre_attack_id || 'ATT&CK'}</span>
        <span>${r.mitre_tactic || 'General'}</span>
        <span>${r.lifecycle_stage || 'Active'}</span>
      </div>
      <div class="rule-actions">
        <button class="btn btn-sm btn-primary" onclick="executeRule('${r.rule_id}')">Run</button>
        <button class="btn btn-sm btn-outline" onclick="benchmarkRule('${r.rule_id}')">Tune</button>
        <button class="btn btn-sm btn-outline-cyan" onclick="openRuleInEditor('${r.rule_id}')">SQL</button>
      </div>
    `;
    grid.appendChild(card);
  });
}

function filterRulesList() {
  const sev = document.getElementById("filter-rule-severity").value;
  const tactic = document.getElementById("filter-rule-tactic").value;

  const filtered = cachedRules.filter(r => {
    const matchSev = sev === "ALL" || r.severity === sev;
    const matchTactic = tactic === "ALL" || r.mitre_tactic === tactic;
    return matchSev && matchTactic;
  });
  renderRulesGrid(filtered);
}

async function executeRule(ruleId) {
  try {
    const res = await fetch("/api/rules/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ rule_id: ruleId })
    });
    const data = await res.json();
    if (data.success) {
      alert(`[${data.rule_id}] ${data.rule_name}\n\nMatches: ${data.alert_count}\nExecution Time: ${data.execution_time_ms} ms\nAlerts recorded to 'detection_alerts' table.`);
      loadTables();
    } else {
      alert("Error running rule: " + data.error);
    }
  } catch (err) {
    alert("Execution error: " + err.message);
  }
}

async function benchmarkRule(ruleId) {
  try {
    const res = await fetch("/api/rules/benchmark", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ rule_id: ruleId })
    });
    const data = await res.json();
    if (data.rule_name) {
      alert(`Rule Tuning Benchmark: [${data.rule_id}]\n${data.rule_name}\n\nRaw Alerts: ${data.raw_alert_count}\nTuned Alerts: ${data.tuned_alert_count}\nSuppressed: ${data.alerts_suppressed}\nNoise Reduction: ${data.noise_reduction_percentage}%\n\nFilter:\n${data.tune_exclusions || 'None'}`);
    }
  } catch (err) {
    alert("Benchmark error: " + err.message);
  }
}

function openRuleInEditor(ruleId) {
  const rule = cachedRules.find(r => r.rule_id === ruleId);
  if (rule) {
    setQueryText(rule.sql_query);
    switchTab("tab-query");
  }
}

async function runAllRules() {
  const statusBadge = document.getElementById("batch-run-status");
  statusBadge.textContent = "Running batch suite...";
  statusBadge.style.color = "var(--color-amber)";

  try {
    const res = await fetch("/api/rules/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({})
    });
    const data = await res.json();
    statusBadge.textContent = `${data.total_rules_evaluated} rules evaluated: ${data.total_alerts_produced} alerts (${data.total_execution_time_ms} ms)`;
    statusBadge.style.color = "var(--color-emerald)";
    loadTables();
  } catch (err) {
    statusBadge.textContent = "Batch failed: " + err.message;
    statusBadge.style.color = "var(--color-rose)";
  }
}

// -----------------------------------------------------------------------------
// SCHEMA TRANSFORMER LOGIC
// -----------------------------------------------------------------------------

async function runPreset(presetName, isDryRun) {
  const output = document.getElementById("schema-diff-output");
  output.textContent = `Processing ${presetName} (${isDryRun ? "Dry-Run" : "Apply"})...`;

  try {
    const res = await fetch("/api/schema/preset", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ preset: presetName, dry_run: isDryRun })
    });
    const data = await res.json();
    output.textContent = JSON.stringify(data, null, 2);
    if (!isDryRun) loadTables();
  } catch (err) {
    output.textContent = "Error: " + err.message;
  }
}

async function runPatternRename(isDryRun) {
  const pattern = document.getElementById("pattern-input").value;
  const replacement = document.getElementById("replacement-input").value;
  const scope = document.getElementById("pattern-scope").value;
  const output = document.getElementById("schema-diff-output");

  output.textContent = "Computing regex pattern changes...";

  try {
    const res = await fetch("/api/schema/pattern", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ pattern, replacement, scope, dry_run: isDryRun })
    });
    const data = await res.json();
    output.textContent = JSON.stringify(data, null, 2);
    if (!isDryRun) loadTables();
  } catch (err) {
    output.textContent = "Error: " + err.message;
  }
}

async function runSingleColumnRename() {
  const table = document.getElementById("rename-table-select").value;
  const old_col = document.getElementById("rename-col-select").value;
  const new_col = document.getElementById("rename-new-col-input").value.trim();
  const output = document.getElementById("schema-diff-output");

  if (!new_col) {
    alert("Please provide a new column name.");
    return;
  }

  try {
    const res = await fetch("/api/schema/rename-column", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ table, old_col, new_col })
    });
    const data = await res.json();
    output.textContent = JSON.stringify(data, null, 2);
    loadTables();
  } catch (err) {
    output.textContent = "Error: " + err.message;
  }
}

// -----------------------------------------------------------------------------
// INGEST & SIMULATOR LOGIC
// -----------------------------------------------------------------------------

async function seedTelemetry() {
  const count = parseInt(document.getElementById("seed-count-select").value) || 500;
  const injectAttacks = document.getElementById("seed-inject-attacks").checked;
  const btn = document.getElementById("btn-seed-telemetry");

  btn.textContent = "Generating...";
  btn.disabled = true;

  try {
    const res = await fetch("/api/generator/seed", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ count, inject_attacks: injectAttacks })
    });
    const data = await res.json();
    alert(`Telemetry generated.\nTotal events: ${data.total_events}\nAttacks injected: ${data.attacks_injected}`);
    loadTables();
  } catch (err) {
    alert("Seeding error: " + err.message);
  } finally {
    btn.textContent = "Generate Telemetry";
    btn.disabled = false;
  }
}

async function resetDatabase() {
  if (!confirm("Are you sure you want to reset the database to a clean empty schema?")) return;

  try {
    const res = await fetch("/api/db/reset", { method: "POST" });
    const data = await res.json();
    alert("Database schema reset successfully.");
    loadTables();
    loadRules();
  } catch (err) {
    alert("Reset error: " + err.message);
  }
}

async function checkStreamStatus() {
  try {
    const res = await fetch("/api/stream/status");
    const data = await res.json();
    if (!data.success) return;

    const running = data.status.running;
    const dot = document.getElementById("stream-indicator");
    const headerBtn = document.getElementById("stream-btn-text");
    const cardBtn = document.getElementById("btn-toggle-stream-card");
    const liveStatus = document.getElementById("stream-live-status");
    const liveEvents = document.getElementById("stream-live-events");

    liveEvents.textContent = data.status.events_produced;

    if (running) {
      dot.classList.add("active");
      headerBtn.textContent = "Live Stream: ON";
      cardBtn.textContent = "Stop Live Feed";
      cardBtn.className = "btn btn-danger";
      liveStatus.textContent = "STREAMING (Active)";
      liveStatus.style.color = "var(--color-emerald)";
      if (!streamPollInterval) {
        streamPollInterval = setInterval(checkStreamStatus, 2500);
      }
    } else {
      dot.classList.remove("active");
      headerBtn.textContent = "Live Stream: OFF";
      cardBtn.textContent = "Start Live Feed";
      cardBtn.className = "btn btn-success";
      liveStatus.textContent = "STOPPED";
      liveStatus.style.color = "var(--text-muted)";
      if (streamPollInterval) {
        clearInterval(streamPollInterval);
        streamPollInterval = null;
      }
    }
  } catch (err) {
    console.error("Stream status check failed:", err);
  }
}

async function toggleLiveStream() {
  try {
    const interval = parseFloat(document.getElementById("stream-interval-select").value) || 3.0;
    const res = await fetch("/api/stream/toggle", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "toggle", interval })
    });
    await checkStreamStatus();
    loadTables();
  } catch (err) {
    alert("Failed to toggle stream: " + err.message);
  }
}

async function submitIngest() {
  const table = document.getElementById("ingest-target-table").value.trim();
  const format = document.getElementById("ingest-format-select").value;
  const content = document.getElementById("ingest-content-input").value.trim();
  const badge = document.getElementById("ingest-status-text");

  if (!content) {
    alert("Please provide CSV or JSON data.");
    return;
  }

  badge.style.display = "inline-block";
  badge.textContent = "Ingesting...";
  badge.style.color = "var(--color-amber)";

  try {
    const res = await fetch("/api/ingest/raw", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ table, type: format, content })
    });
    const data = await res.json();
    if (data.success) {
      badge.textContent = `Success: ${data.rows_inserted} rows inserted into ${data.table}`;
      badge.style.color = "var(--color-emerald)";
      loadTables();
    } else {
      badge.textContent = "Error: " + data.error;
      badge.style.color = "var(--color-rose)";
    }
  } catch (err) {
    badge.textContent = "Failed: " + err.message;
    badge.style.color = "var(--color-rose)";
  }
}

// -----------------------------------------------------------------------------
// MITRE ATT&CK MATRIX LOGIC
// -----------------------------------------------------------------------------

async function loadMitre() {
  try {
    const res = await fetch("/api/mitre");
    const data = await res.json();
    if (!data.success) return;

    const container = document.getElementById("mitre-tactics-container");
    container.innerHTML = "";

    const cov = data.data.coverage;
    for (const [tactic, rulesList] of Object.entries(cov)) {
      const col = document.createElement("div");
      col.className = "mitre-tactic-col";

      col.innerHTML = `
        <div class="mitre-tactic-head">
          <span>${tactic}</span>
          <span class="table-count-badge">${rulesList.length}</span>
        </div>
      `;

      rulesList.forEach(r => {
        const item = document.createElement("div");
        item.className = "mitre-item-card";
        item.innerHTML = `
          <div><span class="mitre-item-id">${r.technique_id}</span>${escapeHtml(r.name)}</div>
        `;
        item.addEventListener("click", () => {
          openRuleInEditor(r.rule_id);
        });
        col.appendChild(item);
      });

      container.appendChild(col);
    }
  } catch (err) {
    console.error("Failed to load MITRE:", err);
  }
}

// -----------------------------------------------------------------------------
// HELPERS
// -----------------------------------------------------------------------------

function escapeHtml(str) {
  if (!str) return "";
  return str.replace(/[&<>'"]/g, tag => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;'
  }[tag] || tag));
}

function jsonStringifySafe(obj) {
  return JSON.stringify(obj, (key, value) => typeof value === "bigint" ? value.toString() : value);
}

function downloadBlob(content, filename, contentType) {
  const blob = new Blob([content], { type: contentType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
