/**
 * ProcTrace Web Studio // Frontend Application
 * Real-time WebSocket streaming, DevTools waterfall rendering, and anomaly triage.
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

  // Initialize
  function init() {
    setupEventListeners();
    connectWebSocket();
    fetchInitialData();
  }

  function setupEventListeners() {
    elBtnPause.addEventListener('click', togglePause);
    elBtnClear.addEventListener('click', clearBuffer);
    elBtnTriage.addEventListener('click', openTriageModal);
    elTriageClose.addEventListener('click', closeTriageModal);
    elTriageModal.addEventListener('click', (e) => {
      if (e.target === elTriageModal) closeTriageModal();
    });

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

    // Keep memory bounded to latest 2000 events in browser
    if (events.length > 2000) {
      events = events.slice(events.length - 2000);
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

    // Limit DOM rendering to latest 200 events for smooth 60fps scrolling
    const windowSlice = filtered.slice(-200);
    const spanSeconds = Math.max(0.001, (maxTimestamp || 0) - (baseTimestamp || 0));

    let html = '';
    for (const ev of windowSlice) {
      const isErr = ev.is_error;
      const rowClass = isErr ? 'waterfall-row error-row' : 'waterfall-row';
      const badgeClass = getBadgeClass(ev.category, isErr);
      const barColorClass = isErr ? 'bar-err' : getBarColorClass(ev.category);

      let leftPct = 0;
      let widthPct = 2;

      if (viewMode === 'waterfall' && baseTimestamp && maxTimestamp) {
        const offset = Math.max(0, ev.timestamp - baseTimestamp);
        leftPct = Math.min(95, (offset / spanSeconds) * 100);
        const durSec = (ev.duration_us || 0) / 1_000_000;
        widthPct = Math.max(0.8, Math.min(100 - leftPct, (durSec / spanSeconds) * 100));
      }

      const formattedDur = formatDuration(ev.duration_us);
      const targetDisplay = escapeHtml(ev.target_path || ev.operation);

      html += `
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

    elRows.innerHTML = html;

    // Attach row click listeners for detail inspection
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
    elTriageBody.innerHTML = '<p>Computing anomaly correlation...</p>';

    fetch('/api/anomalies')
      .then((r) => r.json())
      .then((rep) => {
        let html = '';

        // Missing Files
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

        // Access Denied
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

        // Failed Connections
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
