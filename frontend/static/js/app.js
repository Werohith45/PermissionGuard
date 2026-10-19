// State Management
const state = {
  token: localStorage.getItem("pg_token") || null,
  user: JSON.parse(localStorage.getItem("pg_user") || "null"),
  currentView: "dashboard",
  charts: {}
};

// API Helper
async function api(endpoint, options = {}) {
  const headers = options.headers || {};
  if (state.token) {
    headers["Authorization"] = `Bearer ${state.token}`;
  }
  if (options.body && !(options.body instanceof FormData)) {
    headers["Content-Type"] = "application/json";
  }

  const res = await fetch(`/api${endpoint}`, {
    ...options,
    headers
  });

  if (res.status === 401) {
    logout();
    throw new Error("Session expired. Please log in again.");
  }

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Request failed" }));
    throw new Error(err.detail || "Request failed");
  }

  const contentType = res.headers.get("content-type");
  if (contentType && contentType.includes("application/json")) {
    return await res.json();
  }
  return res;
}

// Helpers
function formatRiskBadge(level, score) {
  const lvl = (level || "LOW").toUpperCase();
  const cls = `badge-risk-${lvl.toLowerCase()}`;
  return `<span class="badge ${cls}">${lvl} ${score !== undefined ? `(${score})` : ''}</span>`;
}

function formatStatusBadge(status) {
  const st = (status || "ACTIVE").toUpperCase();
  const cls = `badge-status-${st.toLowerCase()}`;
  return `<span class="badge ${cls}">${st}</span>`;
}

function formatSensitivityBadge(sens) {
  const s = (sens || "INTERNAL").toUpperCase();
  const cls = `badge-sensitivity-${s.toLowerCase()}`;
  return `<span class="badge ${cls}">${s}</span>`;
}

function fillLogin(username) {
  document.getElementById("login-username").value = username;
  document.getElementById("login-password").value = "DemoPassword123!";
}

// Global Modal helper
function showModal(title, bodyHtml, footerButtons = []) {
  const container = document.getElementById("modal-container");
  const buttonsHtml = footerButtons.map((btn, idx) => `
    <button class="btn ${btn.className || 'btn-secondary'}" id="modal-btn-${idx}">${btn.label}</button>
  `).join("");

  container.innerHTML = `
    <div class="modal-overlay" id="active-modal-overlay">
      <div class="modal-dialog">
        <div class="modal-header">
          <div class="modal-title">${title}</div>
          <button class="modal-close" onclick="closeModal()">✕</button>
        </div>
        <div class="modal-body">${bodyHtml}</div>
        <div class="modal-footer">${buttonsHtml}</div>
      </div>
    </div>
  `;

  footerButtons.forEach((btn, idx) => {
    const el = document.getElementById(`modal-btn-${idx}`);
    if (el && btn.onClick) {
      el.addEventListener("click", () => btn.onClick(closeModal));
    }
  });
}

function closeModal() {
  const container = document.getElementById("modal-container");
  container.innerHTML = "";
}

// Notifications badge refresh
async function refreshNavBadges() {
  if (!state.user) return;
  try {
    const notifs = await api("/notifications");
    const unread = notifs.filter(n => !n.is_read).length;
    
    // Also fetch pending requests count for admin/managers
    if (["System Administrator", "Department Manager"].includes(state.user.role_name)) {
      const reqs = await api("/requests?status=PENDING");
      const badge = document.getElementById("nav-pending-badge");
      if (badge) {
        if (reqs.length > 0) {
          badge.textContent = reqs.length;
          badge.style.display = "inline-block";
        } else {
          badge.style.display = "none";
        }
      }
    }
  } catch (e) {
    console.error("Nav badge refresh error", e);
  }
}

// Router & View Switcher
function navigate(view, param = null) {
  state.currentView = view;
  window.location.hash = param ? `#/${view}/${param}` : `#/${view}`;

  document.querySelectorAll(".nav-item").forEach(item => {
    if (item.dataset.view === view) {
      item.classList.add("active");
    } else {
      item.classList.remove("active");
    }
  });

  const content = document.getElementById("main-content");
  content.innerHTML = `<div style="padding: 24px; color: #64748b;">Loading view...</div>`;

  if (view === "dashboard") renderDashboardView();
  else if (view === "requests") renderRequestsView();
  else if (view === "permissions") renderPermissionsView();
  else if (view === "reviews") renderAccessReviewsView();
  else if (view === "findings") renderFindingsView();
  else if (view === "users") renderUsersView(param);
  else if (view === "resources") renderResourcesView(param);
  else if (view === "audit") renderAuditLogsView();
  else if (view === "reports") renderReportsView();
  else if (view === "settings") renderSettingsView();
  else renderDashboardView();

  refreshNavBadges();
}

// ----------------- VIEW 1: DASHBOARD -----------------
async function renderDashboardView() {
  document.getElementById("page-heading").textContent = "Security Governance & Creep Dashboard";
  document.getElementById("page-subheading").textContent = "Continuous visibility into permission accumulation, dormant access, and policy exceptions";

  try {
    const data = await api("/dashboard");
    const { summary, charts, recent_findings } = data;

    const content = document.getElementById("main-content");
    content.innerHTML = `
      <div class="stats-grid">
        <div class="stat-card">
          <div class="stat-label">Total Users</div>
          <div class="stat-value">${summary.total_users}</div>
          <div class="stat-sub">Active identities monitored</div>
        </div>
        <div class="stat-card accent">
          <div class="stat-label">Active Permissions</div>
          <div class="stat-value">${summary.active_permissions}</div>
          <div class="stat-sub">Across all resources</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Pending Requests</div>
          <div class="stat-value">${summary.pending_requests}</div>
          <div class="stat-sub">Awaiting review</div>
        </div>
        <div class="stat-card risk-warn">
          <div class="stat-label">Inactive Permissions</div>
          <div class="stat-value">${summary.inactive_permissions}</div>
          <div class="stat-sub">> 60 days no usage detected</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Expiring Soon</div>
          <div class="stat-value">${summary.expiring_soon}</div>
          <div class="stat-sub">Within next 7 days</div>
        </div>
        <div class="stat-card risk-high">
          <div class="stat-label">High/Critical Findings</div>
          <div class="stat-value">${summary.high_risk_findings}</div>
          <div class="stat-sub">Require immediate remediation</div>
        </div>
      </div>

      <!-- Charts Grid -->
      <div class="charts-grid">
        <div class="chart-card">
          <div class="chart-header">
            <span>Permissions by Department</span>
            <span style="font-size: 11px; color: #64748b;">RBAC Scope Distribution</span>
          </div>
          <div class="chart-canvas-container">
            <canvas id="chart-dept"></canvas>
          </div>
        </div>

        <div class="chart-card">
          <div class="chart-header">
            <span>Permission Lifecycle Status</span>
            <span style="font-size: 11px; color: #64748b;">Active vs Expired vs Inactive</span>
          </div>
          <div class="chart-canvas-container">
            <canvas id="chart-status"></canvas>
          </div>
        </div>

        <div class="chart-card">
          <div class="chart-header">
            <span>Creep Risk Severity</span>
            <span style="font-size: 11px; color: #64748b;">Low to Critical Breakdown</span>
          </div>
          <div class="chart-canvas-container">
            <canvas id="chart-risk"></canvas>
          </div>
        </div>

        <div class="chart-card">
          <div class="chart-header">
            <span>Audit & Access Activity</span>
            <span style="font-size: 11px; color: #64748b;">Events Recorded Over Time</span>
          </div>
          <div class="chart-canvas-container">
            <canvas id="chart-events"></canvas>
          </div>
        </div>
      </div>

      <!-- Priority Findings & Top Risky Resources Row -->
      <div style="display: grid; grid-template-columns: 2fr 1fr; gap: 20px;">
        <div class="card">
          <div class="card-header">
            <div class="card-title">🚨 Priority Security Findings (Creep & Role Exceptions)</div>
            <a href="#/findings" class="btn btn-secondary btn-sm">View All Findings</a>
          </div>
          <div class="table-responsive">
            <table class="data-table">
              <thead>
                <tr>
                  <th>Code</th>
                  <th>Identity</th>
                  <th>Resource</th>
                  <th>Risk</th>
                  <th>What Happened</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                ${recent_findings.map(f => `
                  <tr>
                    <td><strong>${f.finding_code}</strong></td>
                    <td>${f.full_name} (${f.username})</td>
                    <td><strong>${f.resource_name}</strong></td>
                    <td>${formatRiskBadge(f.risk_level, f.risk_score)}</td>
                    <td style="max-width: 260px; font-size: 12px;">${f.what_happened}</td>
                    <td>
                      <button class="btn btn-secondary btn-sm" onclick="showFindingModal('${f.id}')">Inspect</button>
                    </td>
                  </tr>
                `).join("")}
              </tbody>
            </table>
          </div>
        </div>

        <div class="card">
          <div class="card-header">
            <div class="card-title">📁 Resources with Highest Access Sprawl</div>
          </div>
          <div class="table-responsive">
            <table class="data-table">
              <thead>
                <tr>
                  <th>Resource</th>
                  <th>Sensitivity</th>
                  <th>Grants</th>
                </tr>
              </thead>
              <tbody>
                ${charts.top_resources.map(r => `
                  <tr>
                    <td><a href="#/resources/${r.id}" style="color: #0284c7; text-decoration: none; font-weight: 600;">${r.name}</a></td>
                    <td>${formatSensitivityBadge(r.sensitivity)}</td>
                    <td><strong>${r.perm_count}</strong></td>
                  </tr>
                `).join("")}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    `;

    // Render Actual Canvas Charts
    renderCharts(charts);

  } catch (err) {
    document.getElementById("main-content").innerHTML = `<div style="color: #dc2626; padding: 20px;">Error loading dashboard: ${err.message}</div>`;
  }
}

function renderCharts(charts) {
  // Chart 1: Dept
  const ctxDept = document.getElementById("chart-dept");
  if (ctxDept) {
    new Chart(ctxDept, {
      type: "bar",
      data: {
        labels: charts.permissions_by_department.map(d => d.department),
        datasets: [{
          label: "Permissions",
          data: charts.permissions_by_department.map(d => d.count),
          backgroundColor: "#0284c7"
        }]
      },
      options: { responsive: true, maintainAspectRatio: false }
    });
  }

  // Chart 2: Status
  const ctxStatus = document.getElementById("chart-status");
  if (ctxStatus) {
    const keys = Object.keys(charts.status_breakdown);
    new Chart(ctxStatus, {
      type: "doughnut",
      data: {
        labels: keys,
        datasets: [{
          data: Object.values(charts.status_breakdown),
          backgroundColor: ["#16a34a", "#d97706", "#64748b", "#dc2626", "#2563eb"]
        }]
      },
      options: { responsive: true, maintainAspectRatio: false }
    });
  }

  // Chart 3: Risk
  const ctxRisk = document.getElementById("chart-risk");
  if (ctxRisk) {
    const rkeys = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
    new Chart(ctxRisk, {
      type: "bar",
      data: {
        labels: rkeys,
        datasets: [{
          label: "Open Findings",
          data: rkeys.map(k => charts.risk_distribution[k] || 0),
          backgroundColor: ["#059669", "#d97706", "#ea580c", "#dc2626"]
        }]
      },
      options: { responsive: true, maintainAspectRatio: false }
    });
  }

  // Chart 4: Events Timeline
  const ctxEvents = document.getElementById("chart-events");
  if (ctxEvents) {
    new Chart(ctxEvents, {
      type: "line",
      data: {
        labels: charts.events_timeline.map(e => e.day.slice(5)),
        datasets: [{
          label: "Audit Logs",
          data: charts.events_timeline.map(e => e.count),
          borderColor: "#2563eb",
          backgroundColor: "rgba(37, 99, 235, 0.1)",
          fill: true,
          tension: 0.3
        }]
      },
      options: { responsive: true, maintainAspectRatio: false }
    });
  }
}

// ----------------- VIEW 2: ACCESS REQUESTS -----------------
async function renderRequestsView() {
  document.getElementById("page-heading").textContent = "Access Request Workflow";
  document.getElementById("page-subheading").textContent = "Least-privilege necessity review, duration limits, and automated approval provisioning";

  const isReviewer = ["System Administrator", "Department Manager"].includes(state.user.role_name);
  const data = await api("/requests");

  const content = document.getElementById("main-content");
  content.innerHTML = `
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
      <div style="font-weight: 600; color: #334155;">Access Requests Lifecycle (${data.length} Total)</div>
      <button class="btn btn-primary" onclick="showNewRequestModal()">+ Create Access Request</button>
    </div>

    <div class="card">
      <div class="table-responsive">
        <table class="data-table">
          <thead>
            <tr>
              <th>Request Code</th>
              <th>Requester & Role</th>
              <th>Target Resource</th>
              <th>Perm Type</th>
              <th>Duration</th>
              <th>Business Justification</th>
              <th>Status</th>
              <th>Reviewer Details</th>
              ${isReviewer ? '<th>Governance Actions</th>' : ''}
            </tr>
          </thead>
          <tbody>
            ${data.map(r => `
              <tr>
                <td><strong>${r.request_code}</strong></td>
                <td>${r.requester_name}<br/><span style="color:#64748b; font-size:11px;">${r.requester_role} (${r.requester_dept})</span></td>
                <td><strong>${r.resource_name}</strong><br/>${formatSensitivityBadge(r.resource_sensitivity)}</td>
                <td><span class="badge" style="background:#e0f2fe; color:#0369a1;">${r.permission_type}</span></td>
                <td>${r.duration_days} days</td>
                <td style="max-width: 250px; font-size: 12px;">${r.reason}</td>
                <td>${formatStatusBadge(r.status)}</td>
                <td style="font-size: 11.5px; color:#475569;">
                  ${r.reviewer_name ? `Reviewed by: <b>${r.reviewer_name}</b><br/>${r.review_comments || ''}` : '<span style="color:#94a3b8;">Pending Review</span>'}
                </td>
                ${isReviewer ? `
                  <td>
                    ${r.status === 'PENDING' ? `
                      <button class="btn btn-success btn-sm" onclick="approveRequest('${r.id}')">Approve</button>
                      <button class="btn btn-danger btn-sm" onclick="rejectRequest('${r.id}')">Reject</button>
                    ` : '<span style="color:#64748b; font-size:11px;">Completed</span>'}
                  </td>
                ` : ''}
              </tr>
            `).join("")}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

async function approveRequest(reqId) {
  const comments = prompt("Enter approval remarks (or leave default):", "Approved in line with project authorization.");
  if (comments === null) return;
  try {
    const res = await api(`/requests/${reqId}/approve`, {
      method: "POST",
      body: JSON.stringify({ comments })
    });
    alert(res.message);
    renderRequestsView();
  } catch (err) {
    alert("Error: " + err.message);
  }
}

async function rejectRequest(reqId) {
  const comments = prompt("Enter justification for rejection:", "Does not meet least-privilege necessity criteria.");
  if (comments === null) return;
  try {
    const res = await api(`/requests/${reqId}/reject`, {
      method: "POST",
      body: JSON.stringify({ comments })
    });
    alert(res.message);
    renderRequestsView();
  } catch (err) {
    alert("Error: " + err.message);
  }
}

// ----------------- VIEW 3: PERMISSIONS -----------------
async function renderPermissionsView() {
  document.getElementById("page-heading").textContent = "Active & Historical Permissions";
  document.getElementById("page-subheading").textContent = "Five Core Questions: Who, What, Why, How Long, and When Last Used";

  const isReviewer = ["System Administrator", "Department Manager"].includes(state.user.role_name);
  const data = await api("/permissions");

  const content = document.getElementById("main-content");
  content.innerHTML = `
    <div class="filter-bar">
      <input type="text" id="perm-search" class="form-control filter-input" placeholder="Search user, resource, or reason..." onkeyup="filterPermissionsTable()">
      <select id="perm-status-filter" class="form-control filter-select" onchange="filterPermissionsTable()">
        <option value="">All Statuses</option>
        <option value="ACTIVE">ACTIVE</option>
        <option value="INACTIVE">INACTIVE</option>
        <option value="REVALIDATED">REVALIDATED</option>
        <option value="EXPIRED">EXPIRED</option>
        <option value="REVOKED">REVOKED</option>
      </select>
      <select id="perm-risk-filter" class="form-control filter-select" onchange="filterPermissionsTable()">
        <option value="">All Risks</option>
        <option value="CRITICAL">CRITICAL</option>
        <option value="HIGH">HIGH</option>
        <option value="MEDIUM">MEDIUM</option>
        <option value="LOW">LOW</option>
      </select>
    </div>

    <div class="card">
      <div class="table-responsive">
        <table class="data-table" id="permissions-table">
          <thead>
            <tr>
              <th>Identity (Who)</th>
              <th>Resource (What)</th>
              <th>Permission</th>
              <th>Reason (Why)</th>
              <th>Granted & Expiry (How Long)</th>
              <th>Last Used (When)</th>
              <th>Status</th>
              <th>Risk</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody id="permissions-table-body">
            ${data.map(p => `
              <tr data-status="${p.status}" data-risk="${p.risk_level}" data-text="${p.full_name} ${p.resource_name} ${p.reason}">
                <td>
                  <a href="#/users/${p.user_id}" style="font-weight:600; color:#0284c7; text-decoration:none;">${p.full_name}</a><br/>
                  <span style="font-size:11px; color:#64748b;">${p.role_name}</span>
                </td>
                <td>
                  <a href="#/resources/${p.resource_id}" style="font-weight:600; color:#1e293b; text-decoration:none;">${p.resource_name}</a><br/>
                  ${formatSensitivityBadge(p.sensitivity)}
                </td>
                <td><span class="badge" style="background:#e0f2fe; color:#0369a1;">${p.permission_type}</span></td>
                <td style="max-width: 220px; font-size: 11.5px;">${p.reason}</td>
                <td style="font-size: 11.5px;">
                  <b>${p.start_date}</b> to <b>${p.expiry_date}</b>
                  ${p.extension_count > 0 ? `<br/><span style="color:#d97706; font-size:10px;">(Extended ${p.extension_count}x)</span>` : ''}
                </td>
                <td style="font-size: 11.5px; font-family: var(--font-mono);">
                  ${p.last_used_at ? p.last_used_at.slice(0, 16) : '<span style="color:#94a3b8;">Never</span>'}
                </td>
                <td>${formatStatusBadge(p.status)}</td>
                <td>${formatRiskBadge(p.risk_level, p.risk_score)}</td>
                <td>
                  <button class="btn btn-secondary btn-sm" onclick="showPermissionDetailModal('${p.id}')">Timeline</button>
                  ${isReviewer && p.status === 'ACTIVE' ? `
                    <button class="btn btn-danger btn-sm" onclick="revokePermissionDirect('${p.id}')">Revoke</button>
                  ` : ''}
                </td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

function filterPermissionsTable() {
  const search = document.getElementById("perm-search").value.toLowerCase();
  const status = document.getElementById("perm-status-filter").value;
  const risk = document.getElementById("perm-risk-filter").value;

  const rows = document.querySelectorAll("#permissions-table-body tr");
  rows.forEach(r => {
    const textMatch = !search || r.dataset.text.toLowerCase().includes(search);
    const statusMatch = !status || r.dataset.status === status;
    const riskMatch = !risk || r.dataset.risk === risk;
    if (textMatch && statusMatch && riskMatch) {
      r.style.display = "";
    } else {
      r.style.display = "none";
    }
  });
}

async function showPermissionDetailModal(permId) {
  const res = await api(`/permissions/${permId}`);
  const { permission: p, timeline } = res;

  const html = `
    <div style="margin-bottom: 16px;">
      <div style="font-size: 14px; margin-bottom: 6px;"><b>Identity:</b> ${p.full_name} (${p.role_name})</div>
      <div style="font-size: 14px; margin-bottom: 6px;"><b>Resource:</b> ${p.resource_name} [${p.sensitivity}]</div>
      <div style="font-size: 13px; margin-bottom: 6px;"><b>Granted Window:</b> ${p.start_date} to ${p.expiry_date} | Status: ${formatStatusBadge(p.status)}</div>
      <div style="font-size: 13px; color: #475569;"><b>Business Reason:</b> ${p.reason}</div>
    </div>

    <div style="font-weight: 600; margin-bottom: 10px; color: #1e293b;">Audit & Lifecycle Timeline</div>
    <div class="timeline">
      ${timeline.map(t => `
        <div class="timeline-item">
          <div class="timeline-dot ${t.event_type === 'REVOKED' || t.event_type === 'EXPIRED' ? 'danger' : 'success'}"></div>
          <div class="timeline-time">${t.created_at} (${t.event_type})</div>
          <div class="timeline-content">${t.details} ${t.performer_name ? `— <i>by ${t.performer_name}</i>` : ''}</div>
        </div>
      `).join("")}
    </div>
  `;

  showModal(`Permission Lifecycle Audit — ${p.resource_name}`, html, [
    { label: "Close", onClick: (close) => close() }
  ]);
}

async function revokePermissionDirect(permId) {
  const reason = prompt("Enter justification for revoking this permission:", "Revoked by administrator during regular security hygiene check.");
  if (!reason) return;
  try {
    const res = await api(`/permissions/${permId}/revoke`, {
      method: "POST",
      body: JSON.stringify({ reason })
    });
    alert(res.message);
    renderPermissionsView();
  } catch (err) {
    alert("Error: " + err.message);
  }
}

// ----------------- VIEW 4: ACCESS REVIEWS (Dormancy Review) -----------------
async function renderAccessReviewsView() {
  document.getElementById("page-heading").textContent = "Access Reviews & Inactivity Governance";
  document.getElementById("page-subheading").textContent = "Targeted review of 60-day dormant access, expiring permissions, and role mismatch exceptions";

  const data = await api("/access-reviews");

  const content = document.getElementById("main-content");
  content.innerHTML = `
    <div class="explain-box">
      <div class="explain-title">🛡️ Principle of Inactivity Governance (60-Day Dormancy Rule)</div>
      <div class="explain-body">
        The system does <b>NOT</b> abruptly delete accounts or silently drop permissions without operational context.
        Instead, permissions with no file activity for over 60 days enter the <b>INACTIVE</b> review queue.
        Administrators and department managers must explicitly <b>Revalidate</b> continued operational need, <b>Revoke</b> excessive access, or <b>Extend</b> valid allocations.
      </div>
    </div>

    <div class="card">
      <div class="card-header">
        <div class="card-title">Pending Governance Reviews (${data.length} Items Flagged)</div>
      </div>
      <div class="table-responsive">
        <table class="data-table">
          <thead>
            <tr>
              <th>Identity & Role</th>
              <th>Resource</th>
              <th>Current Perm</th>
              <th>Reason Granted</th>
              <th>Last Used</th>
              <th>Risk Level</th>
              <th>Recommended Action</th>
              <th>Governance Decision</th>
            </tr>
          </thead>
          <tbody>
            ${data.map(item => `
              <tr>
                <td><strong>${item.full_name}</strong><br/><span style="color:#64748b; font-size:11px;">${item.role_name}</span></td>
                <td><strong>${item.resource_name}</strong><br/>${formatSensitivityBadge(item.sensitivity)}</td>
                <td><span class="badge" style="background:#e0f2fe; color:#0369a1;">${item.permission_type}</span></td>
                <td style="max-width: 180px; font-size: 11.5px;">${item.reason}</td>
                <td style="font-size: 11.5px; font-family: var(--font-mono);">
                  ${item.last_used_at ? item.last_used_at.slice(0, 10) : 'Never'}
                  ${item.status === 'INACTIVE' ? '<br/><span style="color:#dc2626; font-weight:600;">>60d Inactive</span>' : ''}
                </td>
                <td>${formatRiskBadge(item.risk_level, item.risk_score)}</td>
                <td style="font-size: 11.5px; max-width: 220px; color:#475569;">${item.recommended_action || 'Review business necessity.'}</td>
                <td>
                  <button class="btn btn-primary btn-sm" onclick="showRevalidateModal('${item.id}', '${item.full_name}', '${item.resource_name}')">Revalidate</button>
                  <button class="btn btn-danger btn-sm" onclick="revokePermissionDirect('${item.id}')">Revoke</button>
                </td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

function showRevalidateModal(permId, userName, resName) {
  const html = `
    <div style="font-size: 13px; margin-bottom: 12px; color: #334155;">
      Revalidating permission for <b>${userName}</b> on <b>${resName}</b>.
      Please state the ongoing business rationale:
    </div>
    <div class="form-group">
      <label class="form-label">Continued Business Justification</label>
      <textarea id="reval-reason" class="form-control" placeholder="e.g. Still required for monthly financial reconciliation and reporting..."></textarea>
    </div>
  `;

  showModal("Revalidate Inactive Permission", html, [
    { label: "Cancel", onClick: (close) => close() },
    {
      label: "Confirm Revalidation",
      className: "btn-primary",
      onClick: async (close) => {
        const reason = document.getElementById("reval-reason").value.trim();
        if (!reason || reason.length < 5) {
          alert("Please provide a valid explanation of at least 5 characters.");
          return;
        }
        try {
          const res = await api(`/permissions/${permId}/revalidate`, {
            method: "POST",
            body: JSON.stringify({ reason })
          });
          alert(res.message);
          close();
          renderAccessReviewsView();
        } catch (e) {
          alert("Error: " + e.message);
        }
      }
    }
  ]);
}

// ----------------- VIEW 5: SECURITY FINDINGS (Creep Detection) -----------------
async function renderFindingsView() {
  document.getElementById("page-heading").textContent = "Explainable Risk Findings";
  document.getElementById("page-subheading").textContent = "Transparent rules-based permission creep evaluation without blackbox heuristics";

  const data = await api("/findings");

  const content = document.getElementById("main-content");
  content.innerHTML = `
    <div class="card">
      <div class="card-header">
        <div class="card-title">Active Security Findings (${data.length} Open Issues)</div>
      </div>
      <div class="table-responsive">
        <table class="data-table">
          <thead>
            <tr>
              <th>Finding Code</th>
              <th>Identity & Role</th>
              <th>Resource & Sensitivity</th>
              <th>Risk Severity</th>
              <th>Score Breakdown</th>
              <th>What Happened</th>
              <th>Recommended Action</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            ${data.map(f => `
              <tr>
                <td><strong>${f.finding_code}</strong></td>
                <td>${f.full_name}<br/><span style="color:#64748b; font-size:11px;">${f.role_name}</span></td>
                <td><strong>${f.resource_name}</strong><br/>${formatSensitivityBadge(f.sensitivity)}</td>
                <td>${formatRiskBadge(f.risk_level, f.risk_score)}</td>
                <td style="font-size: 11.5px; max-width: 180px; color:#9a3412; font-family: var(--font-mono);">
                  ${f.why_risky.replace("Factors identified: ", "<br/>")}
                </td>
                <td style="font-size: 12px; max-width: 220px;">${f.what_happened}</td>
                <td style="font-size: 12px; max-width: 200px; color:#475569;">${f.recommended_action}</td>
                <td>
                  <button class="btn btn-secondary btn-sm" onclick="showFindingModal('${f.id}')">Inspect</button>
                </td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

async function showFindingModal(findingId) {
  const allFindings = await api("/findings");
  const f = allFindings.find(item => item.id === findingId);
  if (!f) return;

  const ev = f.evidence_data || {};
  const html = `
    <div class="explain-box">
      <div class="explain-title">Finding ${f.finding_code}: ${f.risk_level} Risk (Score: ${f.risk_score}/100)</div>
      <div class="explain-body">
        <b>What happened:</b> ${f.what_happened}<br/><br/>
        <b>Why it is risky:</b> ${f.why_risky}
      </div>
    </div>

    <div style="font-size: 13px; margin-bottom: 12px;">
      <b>Target Identity:</b> ${f.full_name} (${f.role_name})<br/>
      <b>Target Resource:</b> ${f.resource_name} (${f.sensitivity})<br/>
      <b>Permission Granted:</b> ${f.permission_type || 'N/A'}<br/>
      <b>Days Inactive:</b> ${ev.days_inactive !== undefined ? ev.days_inactive + ' days' : 'N/A'}<br/>
      <b>Extensions:</b> ${ev.extension_count || 0} times
    </div>

    <div style="font-size: 13px; color: #334155; margin-bottom: 12px;">
      <b>Recommended Remediation:</b><br/>
      ${f.recommended_action}
    </div>
  `;

  showModal(`Security Finding ${f.finding_code}`, html, [
    { label: "Close", onClick: (close) => close() },
    {
      label: "Revoke Access",
      className: "btn-danger",
      onClick: async (close) => {
        const notes = prompt("Enter resolution notes:", "Revoked based on high-risk security finding.");
        if (!notes) return;
        await api(`/findings/${f.id}/resolve`, {
          method: "POST",
          body: JSON.stringify({ action: "REVOKE", notes })
        });
        alert("Access revoked and finding resolved.");
        close();
        renderFindingsView();
      }
    },
    {
      label: "Dismiss Finding",
      className: "btn-secondary",
      onClick: async (close) => {
        const notes = prompt("Enter operational justification for dismissal:", "Accepted risk / authorized business exception.");
        if (!notes) return;
        await api(`/findings/${f.id}/resolve`, {
          method: "POST",
          body: JSON.stringify({ action: "DISMISS", notes })
        });
        alert("Finding dismissed.");
        close();
        renderFindingsView();
      }
    }
  ]);
}

// ----------------- VIEW 6: USERS -----------------
async function renderUsersView(userId = null) {
  if (userId) {
    return renderUserDetailView(userId);
  }

  document.getElementById("page-heading").textContent = "Identity & Role Directory";
  document.getElementById("page-subheading").textContent = "Enterprise user accounts, role baseline scope, and accumulated permission posture";

  const data = await api("/users");

  const content = document.getElementById("main-content");
  content.innerHTML = `
    <div class="card">
      <div class="table-responsive">
        <table class="data-table">
          <thead>
            <tr>
              <th>Full Name & Username</th>
              <th>Department</th>
              <th>Assigned Role</th>
              <th>Active Permissions</th>
              <th>Inactive (Dormant)</th>
              <th>Open Findings</th>
              <th>Highest Risk</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            ${data.map(u => `
              <tr>
                <td><strong>${u.full_name}</strong><br/><span style="color:#64748b; font-size:11px;">${u.email}</span></td>
                <td>${u.department_name}</td>
                <td><span class="badge" style="background:#f1f5f9; color:#334155;">${u.role_name}</span></td>
                <td><strong>${u.active_perms}</strong></td>
                <td>${u.inactive_perms > 0 ? `<span style="color:#d97706; font-weight:600;">${u.inactive_perms}</span>` : '0'}</td>
                <td>${u.open_findings > 0 ? `<span style="color:#dc2626; font-weight:600;">${u.open_findings}</span>` : '0'}</td>
                <td>${formatRiskBadge(u.max_risk_score >= 75 ? 'CRITICAL' : u.max_risk_score >= 50 ? 'HIGH' : u.max_risk_score >= 25 ? 'MEDIUM' : 'LOW', u.max_risk_score)}</td>
                <td>
                  <a href="#/users/${u.id}" class="btn btn-secondary btn-sm">Inspect Profile</a>
                </td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

async function renderUserDetailView(userId) {
  const res = await api(`/users/${userId}`);
  const { profile, permissions, requests, activity, findings, audit_trail } = res;

  document.getElementById("page-heading").textContent = `User Profile: ${profile.full_name}`;
  document.getElementById("page-subheading").textContent = `Detailed permission inventory, creep risk analysis, and file activity audit`;

  const content = document.getElementById("main-content");
  content.innerHTML = `
    <div style="margin-bottom: 14px;">
      <a href="#/users" class="btn btn-secondary btn-sm">← Back to Users Directory</a>
    </div>

    <!-- Identity Summary Card -->
    <div class="card">
      <div class="card-header">
        <div class="card-title">Identity Overview: ${profile.full_name}</div>
        <div>${formatStatusBadge(profile.status)}</div>
      </div>
      <div class="card-body" style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px;">
        <div><span style="color:#64748b; font-size:11px;">USERNAME</span><br/><strong>${profile.username}</strong></div>
        <div><span style="color:#64748b; font-size:11px;">EMAIL</span><br/><strong>${profile.email}</strong></div>
        <div><span style="color:#64748b; font-size:11px;">ROLE</span><br/><strong>${profile.role_name}</strong></div>
        <div><span style="color:#64748b; font-size:11px;">DEPARTMENT</span><br/><strong>${profile.department_name}</strong></div>
      </div>
    </div>

    <!-- User Permissions Inventory -->
    <div class="card">
      <div class="card-header">
        <div class="card-title">Permissions Held (${permissions.length})</div>
      </div>
      <div class="table-responsive">
        <table class="data-table">
          <thead>
            <tr>
              <th>Resource</th>
              <th>Sensitivity</th>
              <th>Type</th>
              <th>Granted</th>
              <th>Expires</th>
              <th>Last Used</th>
              <th>Status</th>
              <th>Risk</th>
              <th>Timeline</th>
            </tr>
          </thead>
          <tbody>
            ${permissions.map(p => `
              <tr>
                <td><strong>${p.resource_name}</strong></td>
                <td>${formatSensitivityBadge(p.sensitivity)}</td>
                <td><span class="badge" style="background:#e0f2fe; color:#0369a1;">${p.permission_type}</span></td>
                <td>${p.start_date}</td>
                <td>${p.expiry_date}</td>
                <td style="font-family: var(--font-mono); font-size: 11.5px;">${p.last_used_at ? p.last_used_at.slice(0, 10) : 'Never'}</td>
                <td>${formatStatusBadge(p.status)}</td>
                <td>${formatRiskBadge(p.risk_level, p.risk_score)}</td>
                <td><button class="btn btn-secondary btn-sm" onclick="showPermissionDetailModal('${p.id}')">View</button></td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      </div>
    </div>

    <!-- Recent File Activity Events -->
    <div class="card">
      <div class="card-header">
        <div class="card-title">Recorded File Activity Events (Synthetic Access Telemetry)</div>
      </div>
      <div class="table-responsive">
        <table class="data-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Resource</th>
              <th>Operation</th>
              <th>IP Address</th>
              <th>Device</th>
              <th>Result</th>
            </tr>
          </thead>
          <tbody>
            ${activity.slice(0, 8).map(a => `
              <tr>
                <td style="font-family: var(--font-mono); font-size: 11.5px;">${a.created_at}</td>
                <td><strong>${a.resource_name}</strong></td>
                <td><span class="badge" style="background:#f1f5f9; color:#1e293b;">${a.action}</span></td>
                <td style="font-family: var(--font-mono); font-size: 11.5px;">${a.ip_address}</td>
                <td>${a.device}</td>
                <td><span style="color: ${a.result === 'SUCCESS' ? '#16a34a' : '#dc2626'}; font-weight:600;">${a.result}</span></td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

// ----------------- VIEW 7: RESOURCES & VERSION HISTORY -----------------
async function renderResourcesView(resourceId = null) {
  if (resourceId) {
    return renderResourceDetailView(resourceId);
  }

  document.getElementById("page-heading").textContent = "Resource & File Repository";
  document.getElementById("page-subheading").textContent = "Protected assets, access lists, sensitivity classifications, and version change logs";

  const data = await api("/resources");

  const content = document.getElementById("main-content");
  content.innerHTML = `
    <div class="card">
      <div class="table-responsive">
        <table class="data-table">
          <thead>
            <tr>
              <th>Resource Name</th>
              <th>Type</th>
              <th>Department</th>
              <th>Owner</th>
              <th>Sensitivity</th>
              <th>Current Version</th>
              <th>Active Grants</th>
              <th>Dormant Grants</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            ${data.map(r => `
              <tr>
                <td><strong>${r.name}</strong></td>
                <td><span class="badge" style="background:#f8fafc; color:#475569;">${r.type}</span></td>
                <td>${r.department_name}</td>
                <td>${r.owner_name}</td>
                <td>${formatSensitivityBadge(r.sensitivity)}</td>
                <td><span class="badge" style="background:#eff6ff; color:#1d4ed8; font-weight:700;">${r.current_version}</span></td>
                <td><strong>${r.active_grants}</strong></td>
                <td>${r.inactive_grants > 0 ? `<span style="color:#d97706; font-weight:600;">${r.inactive_grants}</span>` : '0'}</td>
                <td>
                  <a href="#/resources/${r.id}" class="btn btn-secondary btn-sm">Inspect Access & History</a>
                </td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

async function renderResourceDetailView(resourceId) {
  const res = await api(`/resources/${resourceId}`);
  const { resource: r, access_list, versions, activity, findings } = res;

  document.getElementById("page-heading").textContent = `Resource: ${r.name}`;
  document.getElementById("page-subheading").textContent = `Sensitivity: ${r.sensitivity} | Owner: ${r.owner_name} (${r.owner_email})`;

  const content = document.getElementById("main-content");
  content.innerHTML = `
    <div style="margin-bottom: 14px; display:flex; justify-content:space-between;">
      <a href="#/resources" class="btn btn-secondary btn-sm">← Back to Resources</a>
      <button class="btn btn-primary btn-sm" onclick="showNewVersionModal('${r.id}', '${r.current_version}')">+ Publish New Version</button>
    </div>

    <!-- Who can access it? -->
    <div class="card">
      <div class="card-header">
        <div class="card-title">Who Has Access to this Resource? (${access_list.length} Grants)</div>
      </div>
      <div class="table-responsive">
        <table class="data-table">
          <thead>
            <tr>
              <th>User</th>
              <th>Role & Dept</th>
              <th>Permission</th>
              <th>Status</th>
              <th>Granted</th>
              <th>Expires</th>
              <th>Last Used</th>
              <th>Approver</th>
            </tr>
          </thead>
          <tbody>
            ${access_list.map(a => `
              <tr>
                <td><a href="#/users/${a.user_id}" style="font-weight:600; color:#0284c7; text-decoration:none;">${a.full_name}</a></td>
                <td>${a.role_name} (${a.user_department})</td>
                <td><span class="badge" style="background:#e0f2fe; color:#0369a1;">${a.permission_type}</span></td>
                <td>${formatStatusBadge(a.status)}</td>
                <td>${a.start_date}</td>
                <td>${a.expiry_date}</td>
                <td style="font-family: var(--font-mono); font-size: 11.5px;">${a.last_used_at ? a.last_used_at.slice(0, 10) : 'Never'}</td>
                <td>${a.approver_name || 'System / Auto'}</td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      </div>
    </div>

    <!-- Version Change History -->
    <div class="card">
      <div class="card-header">
        <div class="card-title">Version History & Modification Audit Trail</div>
      </div>
      <div class="table-responsive">
        <table class="data-table">
          <thead>
            <tr>
              <th>Version</th>
              <th>Modified By</th>
              <th>Action</th>
              <th>Timestamp</th>
              <th>Change Summary</th>
            </tr>
          </thead>
          <tbody>
            ${versions.map(v => `
              <tr>
                <td><span class="badge" style="background:#eff6ff; color:#1d4ed8; font-weight:700;">${v.version_number}</span></td>
                <td>${v.modifier_name}</td>
                <td>${v.action}</td>
                <td style="font-family: var(--font-mono); font-size: 11.5px;">${v.created_at}</td>
                <td style="font-size: 12.5px;">${v.change_summary}</td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

function showNewVersionModal(resId, currVer) {
  const html = `
    <div style="font-size: 13px; margin-bottom: 12px; color: #334155;">
      Current active version: <b>${currVer}</b>. Committing a new version will log an immutable audit entry and increment version number.
    </div>
    <div class="form-group">
      <label class="form-label">Change Summary</label>
      <textarea id="version-summary" class="form-control" placeholder="e.g. Added zero-trust network encryption spec and IAM matrix..."></textarea>
    </div>
  `;

  showModal("Commit Resource Version Update", html, [
    { label: "Cancel", onClick: (close) => close() },
    {
      label: "Commit Version",
      className: "btn-primary",
      onClick: async (close) => {
        const summary = document.getElementById("version-summary").value.trim();
        if (!summary) {
          alert("Please describe the version change.");
          return;
        }
        try {
          const res = await api(`/resources/${resId}/version`, {
            method: "POST",
            body: JSON.stringify({ change_summary: summary })
          });
          alert(res.message);
          close();
          renderResourceDetailView(resId);
        } catch (e) {
          alert("Error: " + e.message);
        }
      }
    }
  ]);
}

// ----------------- VIEW 8: AUDIT LOGS -----------------
async function renderAuditLogsView() {
  document.getElementById("page-heading").textContent = "Enterprise Audit Trail";
  document.getElementById("page-subheading").textContent = "Immutable chronological record of logins, access grants, revalidations, and file operations";

  const data = await api("/audit-logs");

  const content = document.getElementById("main-content");
  content.innerHTML = `
    <div class="card">
      <div class="card-header">
        <div class="card-title">System Audit Log (${data.length} Records)</div>
      </div>
      <div class="table-responsive">
        <table class="data-table">
          <thead>
            <tr>
              <th>Timestamp (UTC)</th>
              <th>Action</th>
              <th>Subject / User</th>
              <th>Resource</th>
              <th>Result</th>
              <th>Reason & Reference</th>
              <th>Performed By</th>
              <th>IP Address</th>
            </tr>
          </thead>
          <tbody>
            ${data.map(l => `
              <tr>
                <td style="font-family: var(--font-mono); font-size: 11px;">${l.timestamp}</td>
                <td><span class="badge" style="background:#f1f5f9; color:#0f172a; font-size:10px;">${l.action}</span></td>
                <td>${l.user_full_name || 'System / None'}</td>
                <td>${l.resource_name || '-'}</td>
                <td><span style="color: ${l.result === 'SUCCESS' ? '#16a34a' : '#dc2626'}; font-weight:600; font-size:11px;">${l.result}</span></td>
                <td style="font-size: 11.5px; max-width: 250px;">${l.reason || ''} ${l.reference_id ? `<br/><span style="color:#64748b; font-size:10px;">[${l.reference_id}]</span>` : ''}</td>
                <td>${l.performer_full_name || l.performed_by}</td>
                <td style="font-family: var(--font-mono); font-size: 11px;">${l.ip_address || '-'}</td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

// ----------------- VIEW 9: AUDIT REPORTS -----------------
async function renderReportsView() {
  document.getElementById("page-heading").textContent = "Security Audit Reports";
  document.getElementById("page-subheading").textContent = "Automated executive summary generation, dormancy statistics, and PDF export";

  const data = await api("/reports/summary");
  const { meta, findings, inactive_list } = data;

  const content = document.getElementById("main-content");
  content.innerHTML = `
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
      <div style="font-size: 13px; color: #64748b;">Report Evaluation Snapshot: <b>${meta.generated_at}</b></div>
      <button class="btn btn-primary" onclick="downloadPdfReport()">📥 Download Formal Audit PDF</button>
    </div>

    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-label">Monitored Users</div>
        <div class="stat-value">${meta.total_users}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Protected Assets</div>
        <div class="stat-value">${meta.total_resources}</div>
      </div>
      <div class="stat-card accent">
        <div class="stat-label">Active Permissions</div>
        <div class="stat-value">${meta.active_permissions}</div>
      </div>
      <div class="stat-card risk-warn">
        <div class="stat-label">Dormant Permissions</div>
        <div class="stat-value">${meta.inactive_permissions}</div>
      </div>
      <div class="stat-card risk-high">
        <div class="stat-label">Critical / High Issues</div>
        <div class="stat-value">${meta.critical_findings}</div>
      </div>
    </div>

    <div class="card">
      <div class="card-header">
        <div class="card-title">Prioritized Recommendations & Remediation Summary</div>
      </div>
      <div class="card-body">
        <ul style="padding-left: 20px; font-size: 13px; line-height: 1.8;">
          <li><b>Revoke High-Impact Intern Privileges:</b> Disallow EDIT access on RESTRICTED human resources payroll assets.</li>
          <li><b>Process Inactivity Backlog:</b> Revalidate or revoke ${meta.inactive_permissions} permissions that have been unused for >60 days.</li>
          <li><b>Cross-Department Access Quarantine:</b> Review identities holding access across 3 or more unrelated organizational units.</li>
          <li><b>Repeated Extension Safeguards:</b> Escalate permissions extended 3 or more times for formal committee re-authorization.</li>
        </ul>
      </div>
    </div>
  `;
}

async function downloadPdfReport() {
  const token = state.token;
  window.open(`/api/reports/download-pdf?token=${token}`, "_blank");
}

// ----------------- VIEW 10: SETTINGS -----------------
async function renderSettingsView() {
  document.getElementById("page-heading").textContent = "Governance Settings & Demo Console";
  document.getElementById("page-subheading").textContent = "Threshold calibration, inactivity rules, and presentation database reset";

  const settings = await api("/settings");

  const content = document.getElementById("main-content");
  content.innerHTML = `
    <div style="display: grid; grid-template-columns: 2fr 1fr; gap: 24px;">
      <div class="card">
        <div class="card-header">
          <div class="card-title">Governance Engine Thresholds</div>
        </div>
        <div class="card-body">
          <form id="settings-form">
            <div class="form-group">
              <label class="form-label">Inactivity Threshold (Days)</label>
              <input type="number" id="cfg-inactivity" class="form-control" value="${settings.inactivity_threshold_days || 60}">
              <span style="font-size:11px; color:#64748b;">Days of zero file usage before an active permission is flagged as INACTIVE.</span>
            </div>

            <div class="form-group">
              <label class="form-label">Default Permission Grant Duration (Days)</label>
              <input type="number" id="cfg-duration" class="form-control" value="${settings.default_permission_days || 90}">
              <span style="font-size:11px; color:#64748b;">Default duration assigned during request approvals.</span>
            </div>

            <div class="form-group">
              <label class="form-label">Expiring Soon Warning Window (Days)</label>
              <input type="number" id="cfg-expiring" class="form-control" value="${settings.expiring_soon_days || 7}">
            </div>

            <button type="submit" class="btn btn-primary">Save Governance Configuration</button>
          </form>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <div class="card-title">Presentation Demo Reset</div>
        </div>
        <div class="card-body">
          <p style="font-size: 12.5px; color: #475569; margin-bottom: 14px;">
            Reset the synthetic database back to the canonical demonstration state. Recreates all 18 users, 22 resources, 65+ permissions, and test scenarios.
          </p>
          <button class="btn btn-danger" onclick="resetDemoData()">Reset All Demo Data</button>
        </div>
      </div>
    </div>
  `;

  document.getElementById("settings-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      const payload = {
        inactivity_threshold_days: parseInt(document.getElementById("cfg-inactivity").value),
        default_permission_days: parseInt(document.getElementById("cfg-duration").value),
        expiring_soon_days: parseInt(document.getElementById("cfg-expiring").value),
        low_risk_threshold: 24,
        medium_risk_threshold: 49,
        high_risk_threshold: 74,
        critical_risk_threshold: 100
      };
      const res = await api("/settings", {
        method: "PUT",
        body: JSON.stringify(payload)
      });
      alert(res.message);
    } catch (err) {
      alert("Error: " + err.message);
    }
  });
}

async function resetDemoData() {
  if (!confirm("Are you sure you want to reset all demo data? This will restore the initial demonstration state.")) return;
  try {
    const res = await api("/admin/reset-demo-data", { method: "POST" });
    alert(res.message);
    navigate("dashboard");
  } catch (e) {
    alert("Error: " + e.message);
  }
}

// ----------------- MODAL: CREATE ACCESS REQUEST -----------------
async function showNewRequestModal() {
  const resources = await api("/resources");
  const html = `
    <form id="new-req-form">
      <div class="form-group">
        <label class="form-label">Target Resource / File</label>
        <select id="req-resource-id" class="form-control" required>
          ${resources.map(r => `<option value="${r.id}">${r.name} [${r.sensitivity}] (${r.department_name})</option>`).join("")}
        </select>
      </div>

      <div class="form-group">
        <label class="form-label">Permission Type</label>
        <select id="req-perm-type" class="form-control">
          <option value="READ">READ (View / Inspect)</option>
          <option value="EDIT">EDIT (Modify / Update)</option>
          <option value="WRITE">WRITE (Create / Append)</option>
          <option value="DOWNLOAD">DOWNLOAD (Export Copy)</option>
          <option value="SHARE">SHARE (Grant Outward)</option>
        </select>
      </div>

      <div class="form-group">
        <label class="form-label">Required Duration (Days)</label>
        <input type="number" id="req-duration" class="form-control" min="1" max="180" value="30" required>
      </div>

      <div class="form-group">
        <label class="form-label">Business Justification / Purpose</label>
        <textarea id="req-reason" class="form-control" placeholder="Specific project or business task requiring this access..." required></textarea>
      </div>
    </form>
  `;

  showModal("Submit Access Request", html, [
    { label: "Cancel", onClick: (close) => close() },
    {
      label: "Submit Request",
      className: "btn-primary",
      onClick: async (close) => {
        const resId = document.getElementById("req-resource-id").value;
        const pType = document.getElementById("req-perm-type").value;
        const dur = parseInt(document.getElementById("req-duration").value);
        const reason = document.getElementById("req-reason").value.trim();

        if (!reason || reason.length < 5) {
          alert("Please provide a legitimate business justification.");
          return;
        }

        try {
          const res = await api("/requests", {
            method: "POST",
            body: JSON.stringify({
              resource_id: resId,
              permission_type: pType,
              duration_days: dur,
              reason: reason
            })
          });
          alert(res.message);
          close();
          navigate("requests");
        } catch (e) {
          alert("Error: " + e.message);
        }
      }
    }
  ]);
}

// ----------------- MODAL: SIMULATE FILE OP -----------------
async function showSimulateActivityModal() {
  const resources = await api("/resources");
  const html = `
    <div style="font-size: 13px; color: #475569; margin-bottom: 12px;">
      Simulate an interactive file operation as <b>${state.user.full_name} (${state.user.role_name})</b>.
      This verifies whether the user holds active permissions, logs file telemetry, updates the <b>last_used</b> timestamp, and resets dormancy if appropriate.
    </div>

    <div class="form-group">
      <label class="form-label">Target Resource</label>
      <select id="sim-resource-id" class="form-control">
        ${resources.map(r => `<option value="${r.id}">${r.name} [${r.sensitivity}]</option>`).join("")}
      </select>
    </div>

    <div class="form-group">
      <label class="form-label">Simulated Action</label>
      <select id="sim-action" class="form-control">
        <option value="READ">READ (View content)</option>
        <option value="OPEN">OPEN (Access metadata)</option>
        <option value="EDIT">EDIT (Save changes)</option>
        <option value="DOWNLOAD">DOWNLOAD (Fetch bytes)</option>
      </select>
    </div>
  `;

  showModal("Simulate File Operation", html, [
    { label: "Cancel", onClick: (close) => close() },
    {
      label: "Execute Operation",
      className: "btn-primary",
      onClick: async (close) => {
        const resId = document.getElementById("sim-resource-id").value;
        const action = document.getElementById("sim-action").value;

        try {
          const res = await api("/activity/simulate", {
            method: "POST",
            body: JSON.stringify({ resource_id: resId, action: action })
          });
          alert(`${res.message} at ${res.timestamp}`);
          close();
          navigate(state.currentView);
        } catch (e) {
          alert("Error: " + e.message);
        }
      }
    }
  ]);
}

// ----------------- AUTH LOGIC -----------------
async function handleLogin(e) {
  e.preventDefault();
  const u = document.getElementById("login-username").value.trim();
  const p = document.getElementById("login-password").value;
  const errEl = document.getElementById("login-error");

  try {
    const data = await api("/auth/login", {
      method: "POST",
      body: JSON.stringify({ username: u, password: p })
    });

    state.token = data.access_token;
    state.user = data.user;
    localStorage.setItem("pg_token", data.access_token);
    localStorage.setItem("pg_user", JSON.stringify(data.user));

    errEl.style.display = "none";
    initApp();
  } catch (err) {
    errEl.textContent = err.message;
    errEl.style.display = "block";
  }
}

function logout() {
  state.token = null;
  state.user = null;
  localStorage.removeItem("pg_token");
  localStorage.removeItem("pg_user");
  document.getElementById("sidebar").style.display = "none";
  document.getElementById("main-wrapper").style.display = "none";
  document.getElementById("login-modal").style.display = "flex";
}

function initApp() {
  if (!state.token || !state.user) {
    document.getElementById("login-modal").style.display = "flex";
    document.getElementById("sidebar").style.display = "none";
    document.getElementById("main-wrapper").style.display = "none";
    return;
  }

  document.getElementById("login-modal").style.display = "none";
  document.getElementById("sidebar").style.display = "flex";
  document.getElementById("main-wrapper").style.display = "flex";

  // Set user profile in sidebar
  document.getElementById("sidebar-user-name").textContent = state.user.full_name;
  document.getElementById("sidebar-user-role").textContent = state.user.role_name;
  document.getElementById("sidebar-user-avatar").textContent = state.user.full_name.split(" ").map(n => n[0]).join("").slice(0, 2);

  // Role visibility restrictions for sidebar
  const isAdmin = state.user.role_name === "System Administrator";
  const isManager = state.user.role_name === "Department Manager";
  const isPrivileged = isAdmin || isManager;

  document.getElementById("nav-reviews-item").style.display = isPrivileged ? "block" : "none";
  document.getElementById("nav-audit-item").style.display = isPrivileged ? "block" : "none";
  document.getElementById("nav-reports-item").style.display = isPrivileged ? "block" : "none";
  document.getElementById("nav-settings-item").style.display = isAdmin ? "block" : "none";

  // Parse hash route
  const hash = window.location.hash.replace("#/", "");
  const parts = hash.split("/");
  navigate(parts[0] || "dashboard", parts[1] || null);
}

// Global Event Listeners
document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("login-form").addEventListener("submit", handleLogin);
  document.getElementById("btn-logout-trigger").addEventListener("click", logout);
  document.getElementById("btn-quick-request").addEventListener("click", showNewRequestModal);
  document.getElementById("btn-quick-simulate").addEventListener("click", showSimulateActivityModal);
  
  document.getElementById("btn-quick-run-detector").addEventListener("click", async () => {
    try {
      const res = await api("/dashboard");
      alert("Permission Creep Detection scan finished. Findings and risk scores updated.");
      navigate(state.currentView);
    } catch (e) {
      alert("Error running detector: " + e.message);
    }
  });

  window.addEventListener("hashchange", () => {
    const hash = window.location.hash.replace("#/", "");
    const parts = hash.split("/");
    navigate(parts[0] || "dashboard", parts[1] || null);
  });

  initApp();
});
