/**
 * ProcTrace Web Studio // Frontend Application
 * Real-time WebSocket streaming, DevTools waterfall rendering, anomaly triage,
 * process hierarchy tree, and security risk auditing.
 */

(function () {
  'use strict';

  // State
  let events = [];
  let isPaused = false;
  let activeCategory = 'ALL';
  let errorsOnly = false;
  let searchQuery = '';
  let viewMode = 'waterfall';
  let ws = null;
  let baseTimestamp = null;
  let maxTimestamp = null;

  // DOM Elements
  const elRows = document.getElementById('waterfall-rows');
  const elLiveBeacon = document.getElementById('live-beacon');
  const elLiveStatusText = document.getElementById('live-status-text');
  const elBtnPause = document.getElementById('btn-pause');
  const elBtnClear = document.getElementById('btn-clear');
  const elBtnTriage = document.getElementById('btn-triage');
  const elBtnSecurity = document.getElementById('btn-security');
  const elBtnTree = document.getElementById('btn-tree');
  const elFilterSearch = document.getElementById('filter-search');
  const elFilterErrors = document.getElementById('filter-errors');
  const elSelectViewMode = document.getElementById('select-view-mode');
  const elPills = document.querySelectorAll('.category-pills .pill');
  
  // KPI Elements
  const kpiTotal = document.getElementById('kpi-total');
  const kpiErrors = document.getElementById('kpi-errors');
  const kpiRate = document.getElementById('kpi-rate');
  const kpiPaths = document.getElementById('kpi-paths');
  const kpiPids = document.getElementById('kpi-pids');
  const kpiLatency = document.getElementById('kpi-latency');

  // Drawer & Modal Elements
  const elDrawer = document.getElementById('event-drawer');
  const elDrawerOverlay = document.getElementById('drawer-overlay');
  const elDrawerClose = document.getElementById('drawer-close');
  const elDrawerBody = document.getElementById('drawer-body');
  
  const elTriageModal = document.getElementById('triage-modal-overlay');
  const elTriageClose = document.getElementById('triage-close');
  const elTriageBody = document.getElementById('triage-modal-body');

  const elSecurityModal = document.getElementById('security-modal-overlay');
  const elSecurityClose = document.getElementById('security-close');
  const elSecurityBody = document.getElementById('security-modal-body');

  const elTreeModal = document.getElementById('tree-modal-overlay');
  const elTreeClose = document.getElementById('tree-close');
  const elTreeBody = document.getElementById('tree-modal-body');

  // Initialize
  function init() {
    setupEventListeners();
    connectWebSocket();
    fetchInitialData();
  }

  function setupEventListeners() {
    elBtnPause.addEventListener('click', togglePause);
    elBtnClear.addEventListener('click', clearBuffer);
    
    // Triage modal
    elBtnTriage.addEventListener('click', openTriageModal);
    elTriageClose.addEventListener('click', closeTriageModal);
    elTriageModal.addEventListener('click', (e) => {
      if (e.target === elTriageModal) closeTriageModal();
    });

    // Security modal
    if (elBtnSecurity) {
      elBtnSecurity.addEventListener('click', openSecurityModal);
      elSecurityClose.addEventListener('click', closeSecurityModal);
      elSecurityModal.addEventListener('click', (e) => {
        if (e.target === elSecurityModal) closeSecurityModal();
      });
    }

    // Process Tree modal
    if (elBtnTree) {
      elBtnTree.addEventListener('click', openTreeModal);
      elTreeClose.addEventListener('click', closeTreeModal);
      elTreeModal.addEventListener('click', (e) => {
        if (e.target === elTreeModal) closeTreeModal();
      });
    }

    elDrawerClose.addEventListener('click', closeDrawer);
    elDrawerOverlay.addEventListener('click', closeDrawer);

    elFilterSearch.addEventListener('input', (e) => {
      searchQuery = e.target.value.toLowerCase().trim();
      renderWaterfall();
    });

    elFilterErrors.addEventListener('change', (e) => {
      errorsOnly = e.target.checked;
      renderWaterfall();
    });

    elSelectViewMode.addEventListener('change', (e) => {
      viewMode = e.target.value;
      renderWaterfall();
    });

    elPills.forEach((pill) => {
      pill.addEventListener('click', () => {
        elPills.forEach((p) => p.classList.remove('active'));
        pill.classList.add('active');
        activeCategory = pill.dataset.cat;
        renderWaterfall();
      });
    });

    // Keyboard shortcuts
    window.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        closeDrawer();
        closeTriageModal();
        closeSecurityModal();
        closeTreeModal();
      } else if (e.key === ' ' && e.target.tagName !== 'INPUT') {
        e.preventDefault();
        togglePause();
      } else if (e.key === '/' && e.target.tagName !== 'INPUT') {
        e.preventDefault();
        elFilterSearch.focus();
      }
    });
  }

  function connectWebSocket() {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${proto}//${window.location.host}/ws/live`;

    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      elLiveBeacon.classList.remove('paused');
      elLiveStatusText.textContent = 'LIVE (20 FPS)';
    };

    ws.onmessage = (msg) => {
      if (isPaused) return;
      try {
        const data = JSON.parse(msg.data);
        if (data.type === 'batch' && data.events) {
          appendEvents(data.events);
          if (data.stats) updateStats(data.stats);
        }
      } catch (err) {
        console.error('Error parsing live payload', err);
      }
    };

    ws.onclose = () => {
      elLiveBeacon.classList.add('paused');
      elLiveStatusText.textContent = 'DISCONNECTED (RETRYING)';
      setTimeout(connectWebSocket, 2000);
    };

    ws.onerror = () => {
      ws.close();
    };
  }

  function fetchInitialData() {
    fetch('/api/events?limit=500')
      .then((r) => r.json())
      .then((res) => {
        if (res.events && res.events.length > 0) {
          events = res.events;
          updateTimelineBounds();
          renderWaterfall();
        }
      })
      .catch((err) => console.error(err));

    fetch('/api/stats')
      .then((r) => r.json())
      .then(updateStats)
      .catch((err) => console.error(err));
  }

  function appendEvents(newEvents) {
    if (!newEvents.length) return;

    for (const ev of newEvents) {
      events.push(ev);
    }

    if (events.length > 2500) {
      events = events.slice(events.length - 2500);
    }

    updateTimelineBounds();
    renderWaterfall();
  }

  function updateTimelineBounds() {
    if (!events.length) return;
    baseTimestamp = events[0].timestamp;
    maxTimestamp = events[events.length - 1].timestamp;
    if (maxTimestamp <= baseTimestamp) {
      maxTimestamp = baseTimestamp + 0.001;
    }
  }

  function updateStats(stats) {
    if (!stats) return;
    kpiTotal.textContent = Number(stats.total_ingested || 0).toLocaleString();
    kpiErrors.textContent = Number(stats.total_errors || 0).toLocaleString();
    kpiRate.innerHTML = `${Math.round(stats.events_per_sec || 0)} <small>evt/s</small>`;
    kpiPaths.textContent = Number(stats.unique_paths || 0).toLocaleString();
    kpiPids.textContent = Number(stats.unique_pids || 0).toLocaleString();
    kpiLatency.innerHTML = `${Math.round(stats.max_duration_us || 0)} <small>µs</small>`;
  }

  function togglePause() {
    isPaused = !isPaused;
    elBtnPause.textContent = isPaused ? 'Resume' : 'Pause';
    if (isPaused) {
      elLiveBeacon.classList.add('paused');
      elLiveStatusText.textContent = 'PAUSED';
    } else {
      elLiveBeacon.classList.remove('paused');
      elLiveStatusText.textContent = 'LIVE (20 FPS)';
    }
  }

  function clearBuffer() {
    fetch('/api/clear', { method: 'POST' })
      .then(() => {
        events = [];
        baseTimestamp = null;
        maxTimestamp = null;
        renderWaterfall();
        fetch('/api/stats').then((r) => r.json()).then(updateStats);
      })
      .catch((err) => console.error(err));
  }

  function renderRowHtml(ev, spanSeconds) {
    const isErr = ev.is_error;
    const rowClass = isErr ? 'waterfall-row error-row' : 'waterfall-row';
    const badgeClass = getBadgeClass(ev.category, isErr);
    const barColorClass = isErr ? 'bar-err' : getBarColorClass(ev.category);

    let leftPct = 0;
    let widthPct = 2;

    if (viewMode !== 'stream' && baseTimestamp && maxTimestamp) {
      const offset = Math.max(0, ev.timestamp - baseTimestamp);
      leftPct = Math.min(95, (offset / spanSeconds) * 100);
      const durSec = (ev.duration_us || 0) / 1_000_000;
      widthPct = Math.max(0.8, Math.min(100 - leftPct, (durSec / spanSeconds) * 100));
    }

    const formattedDur = formatDuration(ev.duration_us);
    const targetDisplay = escapeHtml(ev.target_path || ev.operation);

    return `
      <div class="${rowClass}" data-id="${ev.id}">
        <div class="row-meta">
          <span class="op-badge ${badgeClass}">${ev.operation}</span>
          <span style="color: #8b949e; width: 45px;">${ev.pid}</span>
          <span class="target-text ${isErr ? 'error-text' : ''}" title="${targetDisplay}">
            ${targetDisplay}
          </span>
        </div>
        <div class="row-timeline">
          <div class="waterfall-bar ${barColorClass}" style="left: ${leftPct.toFixed(2)}%; width: ${widthPct.toFixed(2)}%;">
            <span class="bar-duration-label">${formattedDur}</span>
          </div>
        </div>
      </div>
    `;
  }

  function renderWaterfall() {
    const filtered = events.filter((ev) => {
      if (errorsOnly && !ev.is_error) return false;
      if (activeCategory !== 'ALL' && ev.category !== activeCategory) return false;
      if (searchQuery) {
        const target = (ev.target_path || '').toLowerCase();
        const op = (ev.operation || '').toLowerCase();
        const name = (ev.process_name || '').toLowerCase();
        const pid = String(ev.pid);
        if (!target.includes(searchQuery) && !op.includes(searchQuery) && !name.includes(searchQuery) && !pid.includes(searchQuery)) {
          return false;
        }
      }
      return true;
    });

    if (!filtered.length) {
      elRows.innerHTML = `
        <div class="empty-state">
          <p>No system calls match current filter criteria.</p>
        </div>
      `;
      return;
    }

    const windowSlice = filtered.slice(-200);
    const spanSeconds = Math.max(0.001, (maxTimestamp || 0) - (baseTimestamp || 0));

    let html = '';
    if (viewMode === 'swimlanes') {
      const groups = {};
      for (const ev of windowSlice) {
        if (!groups[ev.pid]) {
          groups[ev.pid] = { name: ev.process_name, events: [] };
        }
        groups[ev.pid].events.push(ev);
      }
      for (const [pid, grp] of Object.entries(groups)) {
        html += `<div class="swimlane-header">Process: <strong>${escapeHtml(grp.name)}</strong> (PID: ${pid}) &mdash; ${grp.events.length} syscalls</div>`;
        for (const ev of grp.events) {
          html += renderRowHtml(ev, spanSeconds);
        }
      }
    } else {
      for (const ev of windowSlice) {
        html += renderRowHtml(ev, spanSeconds);
      }
    }

    elRows.innerHTML = html;

    elRows.querySelectorAll('.waterfall-row').forEach((row) => {
      row.addEventListener('click', () => {
        const id = row.dataset.id;
        const matched = events.find((e) => e.id === id);
        if (matched) openDrawer(matched);
      });
    });
  }

  function getBadgeClass(cat, isErr) {
    if (isErr) return 'badge-err';
    switch (cat) {
      case 'FILESYSTEM': return 'badge-fs';
      case 'NETWORK': return 'badge-net';
      case 'PROCESS': return 'badge-proc';
      case 'ENVIRONMENT': return 'badge-env';
      default: return 'badge-fs';
    }
  }

  function getBarColorClass(cat) {
    switch (cat) {
      case 'FILESYSTEM': return 'bar-fs';
      case 'NETWORK': return 'bar-net';
      case 'PROCESS': return 'bar-proc';
      case 'ENVIRONMENT': return 'bar-env';
      default: return 'bar-fs';
    }
  }

  function formatDuration(us) {
    if (!us || us < 1) return '<1 µs';
    if (us < 1000) return `${us.toFixed(0)} µs`;
    if (us < 1_000_000) return `${(us / 1000).toFixed(1)} ms`;
    return `${(us / 1_000_000).toFixed(2)} s`;
  }

  function openDrawer(ev) {
    const isErr = ev.is_error;
    const statusColor = isErr ? '#f85149' : '#3fb950';

    let detailsHtml = '';
    if (ev.details && Object.keys(ev.details).length > 0) {
      detailsHtml = `
        <tr>
          <td class="prop-name">Extra Details</td>
          <td class="prop-value"><pre style="font-size:11px;">${escapeHtml(JSON.stringify(ev.details, null, 2))}</pre></td>
        </tr>
      `;
    }

    elDrawerBody.innerHTML = `
      <table class="detail-table">
        <tbody>
          <tr><td class="prop-name">Event ID</td><td class="prop-value">${ev.id}</td></tr>
          <tr><td class="prop-name">Timestamp</td><td class="prop-value">${ev.timestamp.toFixed(6)} (Epoch)</td></tr>
          <tr><td class="prop-name">Process</td><td class="prop-value">${escapeHtml(ev.process_name)} (PID: ${ev.pid}${ev.ppid ? ', PPID: ' + ev.ppid : ''})</td></tr>
          <tr><td class="prop-name">Category</td><td class="prop-value">${ev.category}</td></tr>
          <tr><td class="prop-name">Operation</td><td class="prop-value">${ev.operation}</td></tr>
          <tr><td class="prop-name">Target Path</td><td class="prop-value" style="color:#58a6ff;">${escapeHtml(ev.target_path)}</td></tr>
          <tr><td class="prop-name">Result</td><td class="prop-value" style="color:${statusColor}; font-weight:bold;">${ev.result}</td></tr>
          <tr><td class="prop-name">Return Code</td><td class="prop-value">${ev.return_code !== null ? ev.return_code : 'N/A'}</td></tr>
          <tr><td class="prop-name">Errno / Name</td><td class="prop-value">${ev.errno_name || 'None'}</td></tr>
          <tr><td class="prop-name">Latency</td><td class="prop-value">${formatDuration(ev.duration_us)} (${ev.duration_us} µs)</td></tr>
          ${detailsHtml}
        </tbody>
      </table>
      <div style="margin-top: 20px; display: flex; gap: 10px;">
        <button class="btn btn-outline" id="btn-copy-json">Copy JSON</button>
      </div>
    `;

    document.getElementById('btn-copy-json').addEventListener('click', () => {
      navigator.clipboard.writeText(JSON.stringify(ev, null, 2));
      alert('Event JSON copied to clipboard.');
    });

    elDrawer.classList.add('open');
    elDrawerOverlay.classList.add('open');
  }

  function closeDrawer() {
    elDrawer.classList.remove('open');
    elDrawerOverlay.classList.remove('open');
  }

  function openTriageModal() {
    elTriageModal.classList.add('open');
    elTriageBody.innerHTML = '<p>Computing root-cause diagnosis and anomaly correlation...</p>';

    Promise.all([
      fetch('/api/anomalies').then((r) => r.json()),
      fetch('/api/explanations').then((r) => r.json()).catch(() => [])
    ])
      .then(([rep, explanations]) => {
        let html = '';

        // 1. Actionable Remediation Guidance
        if (explanations && explanations.length > 0) {
          html += `<div class="triage-section">
            <h4 style="color:#3fb950;">Actionable Remediation Guidance (${explanations.length})</h4>
            <div class="remediation-cards">`;
          for (const ex of explanations) {
            html += `
              <div class="remediation-card">
                <div class="rem-title">${escapeHtml(ex.title)}</div>
                <div class="rem-cause">${escapeHtml(ex.root_cause)}</div>
                <div class="rem-steps">
                  <strong>Recommended Steps:</strong>
                  <ul>
                    ${ex.remediation_steps.map((s) => `<li><code>${escapeHtml(s)}</code></li>`).join('')}
                  </ul>
                </div>
              </div>
            `;
          }
          html += '</div></div>';
        }

        // 2. Missing Files
        html += `<div class="triage-section">
          <h4>Missing Files / Broken Paths (${rep.missing_files.length})</h4>`;
        if (rep.missing_files.length) {
          html += '<ul class="triage-list">';
          for (const item of rep.missing_files) {
            html += `<li>
              <span>${escapeHtml(item.target)}</span>
              <span class="triage-badge">${item.count} attempts</span>
            </li>`;
          }
          html += '</ul>';
        } else {
          html += '<p style="color:#8b949e;">No ENOENT missing file lookups detected.</p>';
        }
        html += '</div>';

        // 3. Access Denied
        html += `<div class="triage-section">
          <h4>Permission Denials (${rep.access_denied.length})</h4>`;
        if (rep.access_denied.length) {
          html += '<ul class="triage-list">';
          for (const item of rep.access_denied) {
            html += `<li>
              <span>${escapeHtml(item.target)}</span>
              <span class="triage-badge">${item.count} attempts</span>
            </li>`;
          }
          html += '</ul>';
        } else {
          html += '<p style="color:#8b949e;">No permission denials detected.</p>';
        }
        html += '</div>';

        // 4. Failed Connections
        html += `<div class="triage-section">
          <h4>Failed Socket Connections (${rep.failed_connections.length})</h4>`;
        if (rep.failed_connections.length) {
          html += '<ul class="triage-list">';
          for (const item of rep.failed_connections) {
            html += `<li>
              <span>${escapeHtml(item.target)}</span>
              <span class="triage-badge">${item.count} refused</span>
            </li>`;
          }
          html += '</ul>';
        } else {
          html += '<p style="color:#8b949e;">No socket connection failures detected.</p>';
        }
        html += '</div>';

        elTriageBody.innerHTML = html;
      })
      .catch((err) => {
        elTriageBody.innerHTML = `<p style="color:#f85149;">Error loading anomalies: ${err.message}</p>`;
      });
  }

  function closeTriageModal() {
    elTriageModal.classList.remove('open');
  }

  function openSecurityModal() {
    if (!elSecurityModal) return;
    elSecurityModal.classList.add('open');
    elSecurityBody.innerHTML = '<p>Auditing trace for sensitive credential access and exfiltration...</p>';

    fetch('/api/security')
      .then((r) => r.json())
      .then((rep) => {
        const sevColor = rep.risk_level === 'CLEAN' ? '#3fb950' : (rep.risk_level === 'LOW' || rep.risk_level === 'MEDIUM' ? '#d29922' : '#f85149');
        let html = `
          <div class="security-banner" style="border-left: 4px solid ${sevColor}; padding: 12px; background: rgba(22, 27, 34, 0.8); margin-bottom: 20px;">
            <div style="font-size: 16px; font-weight: 700; color: ${sevColor};">Risk Assessment: ${rep.risk_level} (${rep.risk_score} / 100)</div>
            <div style="color: #8b949e; margin-top: 4px;">Detected ${rep.total_findings} security finding(s) and ${rep.exfiltration_suspects.length} potential exfiltration chain(s).</div>
          </div>
        `;

        if (rep.exfiltration_suspects.length > 0) {
          html += `<div class="triage-section">
            <h4 style="color:#f85149;">Data Exfiltration Suspects (${rep.exfiltration_suspects.length})</h4>
            <ul class="triage-list">`;
          for (const s of rep.exfiltration_suspects) {
            html += `<li>
              <span><strong>PID ${s.pid}</strong> (${escapeHtml(s.process_name)}) read <code>${escapeHtml(s.sensitive_file)}</code> &rarr; connected to <code>${escapeHtml(s.remote_endpoint)}</code></span>
              <span class="triage-badge" style="background:#b62324; color:#fff;">+${s.time_delta_seconds}s</span>
            </li>`;
          }
          html += `</ul></div>`;
        }

        if (rep.findings.length > 0) {
          html += `<div class="triage-section">
            <h4>Sensitive Credential Access (${rep.findings.length})</h4>
            <ul class="triage-list">`;
          for (const f of rep.findings) {
            html += `<li>
              <span>[${f.severity}] <strong>${escapeHtml(f.title)}</strong>: <code>${escapeHtml(f.target)}</code></span>
              <span class="triage-badge">${f.severity}</span>
            </li>`;
          }
          html += `</ul></div>`;
        } else {
          html += `<p style="color: #3fb950;">No credential access or unauthorized paths detected in trace.</p>`;
        }

        elSecurityBody.innerHTML = html;
      })
      .catch((err) => {
        elSecurityBody.innerHTML = `<p style="color:#f85149;">Error loading security audit: ${err.message}</p>`;
      });
  }

  function closeSecurityModal() {
    if (elSecurityModal) elSecurityModal.classList.remove('open');
  }

  function openTreeModal() {
    if (!elTreeModal) return;
    elTreeModal.classList.add('open');
    elTreeBody.innerHTML = '<p>Reconstructing process hierarchy tree...</p>';

    fetch('/api/tree')
      .then((r) => r.json())
      .then((tree) => {
        if (!tree.length) {
          elTreeBody.innerHTML = '<p style="color: #8b949e;">No process hierarchy recorded.</p>';
          return;
        }

        function renderNode(node) {
          let cHtml = '';
          if (node.children && node.children.length) {
            cHtml = `<ul class="tree-children">${node.children.map(renderNode).join('')}</ul>`;
          }
          return `
            <li class="tree-node">
              <div class="tree-item">
                <span class="tree-name">${escapeHtml(node.name)}</span>
                <span class="tree-badge">PID ${node.pid}</span>
                <span class="tree-events">${node.event_count} events</span>
                ${node.error_count > 0 ? `<span class="triage-badge">${node.error_count} errors</span>` : ''}
              </div>
              ${cHtml}
            </li>
          `;
        }

        elTreeBody.innerHTML = `<ul class="tree-root">${tree.map(renderNode).join('')}</ul>`;
      })
      .catch((err) => {
        elTreeBody.innerHTML = `<p style="color:#f85149;">Error loading process tree: ${err.message}</p>`;
      });
  }

  function closeTreeModal() {
    if (elTreeModal) elTreeModal.classList.remove('open');
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  document.addEventListener('DOMContentLoaded', init);
})();
