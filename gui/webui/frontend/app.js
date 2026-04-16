// API base URL
const API_BASE_URL = '/api';

// Global state
let autoRefreshEnabled = true;
let refreshInterval = 1000;
let refreshTimer = null;

// Previous data for rate calculation
let lastStatsData = null;
let lastStatsTime = null;

// QoS achievement history data (for calculating achievement within time window)
let qosHistory = {
  samples : [],
  maxSamples : 60 // Keep 60 samples (1 minute @ 1 second interval)
};

// Chart object
let trafficChart = null;
let chartData = {labels : [], datasets : []};

// ==================== Utility Functions ====================

/**
 * Format bytes
 */
function formatBytes(bytes) {
  if (bytes === 0)
    return '0 B';
  const k = 1024;
  const sizes = [ 'B', 'KB', 'MB', 'GB', 'TB' ];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return (bytes / Math.pow(k, i)).toFixed(2) + ' ' + sizes[i];
}

function formatMaybeBytes(bytes) {
  if (bytes === null || bytes === undefined) {
    return 'N/A';
  }
  return formatBytes(bytes);
}

function formatGbpsNumber(value, digits = 2) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) {
    return 'N/A';
  }
  return Number(value).toFixed(digits).replace(/\.?0+$/, '');
}

/**
 * Format timestamp
 */
function formatTimestamp(timestamp) {
  const date = new Date(timestamp * 1000);
  return date.toLocaleTimeString('en-US');
}

function getRateBasisNote(data) {
  const basis = data?.rate_basis;
  if (!basis) {
    return 'Runtime statistics and configured PFCP targets are shown on a common basis when available.';
  }

  const multiplier = basis.target_multiplier
                         ? `${basis.target_multiplier.toFixed(2)}x`
                         : '1.00x';
  return `${basis.measured_label}. ${
      basis.display_label ||
      'Expected ranges follow the same runtime accounting basis'}. Configured reference: ${
      basis.configured_label} (${multiplier}).`;
}

function formatRangeWithExpected(configuredGbr, configuredMbr, multiplier) {
  const displayGbr = configuredGbr * multiplier;
  const displayMbr = configuredMbr * multiplier;
  return `cfg ${configuredGbr.toFixed(1)}-${configuredMbr.toFixed(1)} | exp ${
      displayGbr.toFixed(2)}-${displayMbr.toFixed(2)} Gbps`;
}

/**
 * Update connection status
 * @param {string} status - 'api_ok' | 'api_error' | 'upf_connected' |
 *     'upf_waiting'
 */
function updateConnectionStatus(status) {
  const statusEl = document.getElementById('connection-status');
  switch (status) {
  case 'upf_connected':
    statusEl.className = 'status-indicator';
    statusEl.innerHTML = '<span class="dot"></span> UPF Connected';
    break;
  case 'upf_waiting':
    statusEl.className = 'status-indicator';
    statusEl.innerHTML =
        '<span class="dot" style="background:#f59e0b"></span> Waiting for PFCP Connection';
    break;
  case 'api_error':
    statusEl.className = 'status-indicator error';
    statusEl.innerHTML = '<span class="dot"></span> API Connection Failed';
    break;
  default:
    statusEl.className = 'status-indicator';
    statusEl.innerHTML = '<span class="dot"></span> Connecting...';
  }
}

/**
 * Update last update time
 */
function updateLastUpdateTime() {
  document.getElementById('last-update-time').textContent =
      new Date().toLocaleTimeString('en-US');
}

// ==================== API Call Functions ====================

/**
 * Fetch UPF configuration
 */
async function fetchUpfConfig() {
  try {
    const response = await fetch(`${API_BASE_URL}/upf/config`);
    if (!response.ok)
      throw new Error('Failed to fetch config');
    const data = await response.json();
    updateConfigDisplay(data);
    // Config fetch success does not change connection status, determined by
    // fetchUserSessions
  } catch (error) {
    console.error('Failed to fetch UPF config:', error);
    updateConnectionStatus('api_error');
  }
}

// Previous connection state
let lastConnectionState = null;

/**
 * Fetch user session information
 */
async function fetchUserSessions() {
  try {
    const response = await fetch(`${API_BASE_URL}/users/sessions`);
    if (!response.ok)
      throw new Error('Failed to fetch sessions');
    const data = await response.json();

    // Detect connection state change
    const currentState = data.has_active_sessions;

    // If changed from connected to disconnected, clear all data
    if (lastConnectionState === true && currentState === false) {
      console.log('UPF disconnected, clearing all data...');
      clearChartData();
    }

    lastConnectionState = currentState;

    updateSessionsDisplay(data);
    // Update connection indicator based on UPF session status
    updateConnectionStatus(currentState ? 'upf_connected' : 'upf_waiting');
  } catch (error) {
    console.error('Failed to fetch user sessions:', error);
    // Also clear data on API error
    if (lastConnectionState === true) {
      clearChartData();
    }
    lastConnectionState = false;
    updateConnectionStatus('api_error');
  }
}

/**
 * Fetch real-time statistics
 */
async function fetchRealtimeStats() {
  try {
    const response = await fetch(`${API_BASE_URL}/stats/realtime`);
    if (!response.ok)
      throw new Error('Failed to fetch statistics');
    const data = await response.json();
    updateStatsDisplay(data);
    // Real-time stats fetch success does not change connection status,
    // determined by fetchUserSessions
    updateLastUpdateTime();
  } catch (error) {
    console.error('Failed to fetch real-time statistics:', error);
    updateConnectionStatus('api_error');
  }
}

// ==================== Display Update Functions ====================

/**
 * Update configuration display
 */
function updateConfigDisplay(data) {
  // Features
  const features = data.support_features || {};
  const featuresHtml = `
        <div class="config-item">
            <span class="config-label">BPF Datapath</span>
            <span class="config-value ${
      features.enable_bpf_datapath === 'on' ? 'enabled' : 'disabled'}">
                ${
      features.enable_bpf_datapath === 'on' ? '✅ Enabled' : '❌ Disabled'}
            </span>
        </div>
        <div class="config-item">
            <span class="config-label">QoS Feature</span>
            <span class="config-value ${
      features.enable_qos === 'on' ? 'enabled' : 'disabled'}">
                ${features.enable_qos === 'on' ? '✅ Enabled' : '❌ Disabled'}
            </span>
        </div>
        <div class="config-item">
            <span class="config-label">SNAT</span>
            <span class="config-value ${
      features.enable_snat === 'on' ? 'enabled' : 'disabled'}">
                ${features.enable_snat === 'on' ? '✅ Enabled' : '❌ Disabled'}
            </span>
        </div>
        <div class="config-item">
            <span class="config-label">QDisc Scheduler</span>
            <span class="config-value">${
      features.qdisc_scheduler || 'N/A'}</span>
        </div>
        <div class="config-item">
            <span class="config-label">Max PDRs</span>
            <span class="config-value">${
      features.max_pdrs_per_pdu_session || 'N/A'}</span>
        </div>
    `;
  document.getElementById('features-config').innerHTML = featuresHtml;

  // Network interfaces - enhanced display
  const interfaces = data.interfaces || {};
  const hostname = data.hostname || 'N/A';
  const interfacesHtml = `
        <div class="config-item">
            <span class="config-label">Hostname</span>
            <span class="config-value"><strong>${hostname}</strong></span>
        </div>
        <div class="config-item">
            <span class="config-label">N3 Interface (GTP-U)</span>
            <span class="config-value">
                <strong>${interfaces.n3?.interface_name || 'N/A'}</strong><br>
                <small>📍 IP: <code>${
      interfaces.n3?.ip_address || 'N/A'}</code> | 🔌 Port: <code>${
      interfaces.n3?.port || 'N/A'}</code></small>
            </span>
        </div>
        <div class="config-item">
            <span class="config-label">N4 Interface (PFCP)</span>
            <span class="config-value">
                <strong>${interfaces.n4?.interface_name || 'N/A'}</strong><br>
                <small>📍 IP: <code>${
      interfaces.n4?.ip_address || 'N/A'}</code> | 🔌 Port: <code>${
      interfaces.n4?.port || 'N/A'}</code></small>
            </span>
        </div>
        <div class="config-item">
            <span class="config-label">N6 Interface (DN)</span>
            <span class="config-value">
                <strong>${interfaces.n6?.interface_name || 'N/A'}</strong><br>
                <small>📍 IP: <code>${
      interfaces.n6?.ip_address || 'N/A'}</code></small>
            </span>
        </div>
    `;
  document.getElementById('interfaces-config').innerHTML = interfacesHtml;

  // System settings
  const systemHtml = `
        <div class="config-item">
            <span class="config-label">HTTP Version</span>
            <span class="config-value">${data.http_version || 'N/A'}</span>
        </div>
        <div class="config-item">
            <span class="config-label">Log Level</span>
            <span class="config-value">${
      data.log_level?.general || 'N/A'}</span>
        </div>
        <div class="config-item">
            <span class="config-label">N6 Gateway</span>
            <span class="config-value">${data.remote_n6_gw || 'N/A'}</span>
        </div>
    `;
  document.getElementById('system-config').innerHTML = systemHtml;
}

/**
 * Update session display
 */
function updateSessionsDisplay(data) {
  document.getElementById('total-sessions').textContent = data.total_users || 0;

  const tbody = document.getElementById('sessions-tbody');
  if (!data.sessions || data.sessions.length === 0) {
    const message =
        data.has_active_sessions === false
            ? '⚠️ UPF has no PFCP connection, please run PFCP session establishment script first'
            : 'No session data';
    tbody.innerHTML =
        `<tr><td colspan="9" class="loading">${message}</td></tr>`;

    // When no active sessions, clear chart data and state
    if (data.has_active_sessions === false) {
      clearChartData();
    }
    return;
  }

  const rows = data.sessions
                   .map(session => `
        <tr>
            <td>U${session.user_id}</td>
            <td>${session.user_ip}</td>
            <td><code>${session.teid}</code></td>
            <td><span class="qos-badge ${session.qos_tier}">${
                            session.qos_tier}</span></td>
            <td>${session.gbr_gbps.toFixed(1)}</td>
            <td>${session.mbr_gbps.toFixed(1)}</td>
            <td>${session.qfi}</td>
            <td>${session.precedence}</td>
            <td><span class="status-badge ${session.status}">${
                            session.status}</span></td>
        </tr>
    `).join('');

  tbody.innerHTML = rows;
}

/**
 * Clear chart data and state (called when UPF disconnects)
 */
function clearChartData() {
  // Clear rate calculation state
  lastStatsData = null;
  lastStatsTime = null;

  // Clear QoS history data
  qosHistory.samples = [];

  // Clear chart data
  chartData.labels = [];
  chartData.datasets = [];

  // Update chart display
  if (trafficChart) {
    trafficChart.update('none');
  }

  // Reset statistics display
  document.getElementById('bpf-total-rate').textContent = '0.00 Gbps';
  document.getElementById('n3-rate').textContent = '0.00 / 0.00 Gbps';
  document.getElementById('n6-rate').textContent = '0.00 / 0.00 Gbps';
  document.getElementById('rate-basis-note').textContent =
      'Runtime statistics and configured PFCP targets are shown on a common basis when available.';

  // Clear statistics table
  const statsTbody = document.getElementById('stats-tbody');
  if (statsTbody) {
    statsTbody.innerHTML =
        '<tr><td colspan="9" class="loading">No statistics data</td></tr>';
  }

  // Reset QoS metrics display
  resetQosRuntimeDisplay('No active users');

  console.log('Chart data and stats cleared due to UPF disconnection');
}

function setMetricUnavailable(valueId, barId) {
  const valueEl = document.getElementById(valueId);
  const barEl = document.getElementById(barId);

  if (valueEl) {
    valueEl.textContent = 'N/A';
    valueEl.className = 'metric-value unavailable';
  }

  if (barEl) {
    barEl.style.width = '0%';
  }
}

function resetQosRuntimeDisplay(message = 'No active users',
                                unavailable = false) {
  if (unavailable) {
    setMetricUnavailable('gbr-satisfaction', 'gbr-bar');
    setMetricUnavailable('mbr-compliance', 'mbr-bar');
    setMetricUnavailable('overall-score', 'overall-bar');
  } else {
    updateMetricDisplay('gbr-satisfaction', 'gbr-bar', 0);
    updateMetricDisplay('mbr-compliance', 'mbr-bar', 0);
    updateMetricDisplay('overall-score', 'overall-bar', 0);
  }

  const tierStatsTbody = document.getElementById('tier-stats-tbody');
  if (tierStatsTbody) {
    tierStatsTbody.innerHTML =
        `<tr><td colspan="6" class="loading">${message}</td></tr>`;
  }
}

/**
 * Update statistics display
 */
function updateStatsDisplay(data) {
  // Check if there is user data
  if (!data.users || data.users.length === 0) {
    // When no user data, reset display but don't clear history (handled by
    // fetchUserSessions)
    document.getElementById('hostname').textContent = data.hostname || 'N/A';
    document.getElementById('n3-interface-name').textContent =
        data.interfaces?.n3?.name || 'N/A';
    document.getElementById('n6-interface-name').textContent =
        data.interfaces?.n6?.name || 'N/A';
    document.getElementById('bpf-total-rate').textContent = '0.00 Gbps';
    document.getElementById('n3-rate').textContent = '0.00 / 0.00 Gbps';
    document.getElementById('n6-rate').textContent = '0.00 / 0.00 Gbps';
    document.getElementById('rate-basis-note').textContent =
        getRateBasisNote(data);

    const statsTbody = document.getElementById('stats-tbody');
    if (statsTbody) {
      statsTbody.innerHTML =
          '<tr><td colspan="9" class="loading">No statistics data</td></tr>';
    }
    return;
  }

  // Update hostname and interface information
  document.getElementById('hostname').textContent = data.hostname || 'N/A';
  document.getElementById('n3-interface-name').textContent =
      data.interfaces?.n3?.name || 'N/A';
  document.getElementById('n6-interface-name').textContent =
      data.interfaces?.n6?.name || 'N/A';

  // Calculate rates
  const currentTime = data.timestamp;
  let bpfTotalRate = 0;
  let n3RxRate = 0;
  let n3TxRate = 0;
  let n6RxRate = 0;
  let n6TxRate = 0;

  if (lastStatsData && lastStatsTime) {
    const timeDelta = currentTime - lastStatsTime;
    if (timeDelta > 0) {
      // BPF rate
      const bytesDiff = data.bpf_stats.total_bytes_passed -
                        lastStatsData.bpf_stats.total_bytes_passed;
      bpfTotalRate = (bytesDiff * 8) / 1e9 / timeDelta;

      // N3 NIC rate
      const n3RxDiff =
          data.interfaces.n3.rx_bytes - lastStatsData.interfaces.n3.rx_bytes;
      const n3TxDiff =
          data.interfaces.n3.tx_bytes - lastStatsData.interfaces.n3.tx_bytes;
      n3RxRate = (n3RxDiff * 8) / 1e9 / timeDelta;
      n3TxRate = (n3TxDiff * 8) / 1e9 / timeDelta;

      // N6 NIC rate
      const n6RxDiff =
          data.interfaces.n6.rx_bytes - lastStatsData.interfaces.n6.rx_bytes;
      const n6TxDiff =
          data.interfaces.n6.tx_bytes - lastStatsData.interfaces.n6.tx_bytes;
      n6RxRate = (n6RxDiff * 8) / 1e9 / timeDelta;
      n6TxRate = (n6TxDiff * 8) / 1e9 / timeDelta;
    }
  }

  if (data.stats_mode === 'official_htb' && bpfTotalRate > 0.01 &&
      n3TxRate <= 0.01) {
    n3TxRate = bpfTotalRate;
  }

  // Update overview
  document.getElementById('bpf-total-rate').textContent =
      `${bpfTotalRate.toFixed(2)} Gbps`;
  document.getElementById('n3-rate').textContent =
      `${n3RxRate.toFixed(2)} / ${n3TxRate.toFixed(2)} Gbps`;
  document.getElementById('n6-rate').textContent =
      `${n6RxRate.toFixed(2)} / ${n6TxRate.toFixed(2)} Gbps`;
  document.getElementById('rate-basis-note').textContent =
      getRateBasisNote(data);

  // Update user statistics table
  updateUserStatsTable(data, lastStatsData,
                       currentTime - (lastStatsTime || currentTime));

  // Update chart
  updateTrafficChart(data.users, currentTime,
                     data.per_user_stats_available !== false);

  // Save current data for next calculation
  lastStatsData = data;
  lastStatsTime = currentTime;
}

/**
 * Update user statistics table
 */
function updateUserStatsTable(currentData, lastData, timeDelta) {
  const tbody = document.getElementById('stats-tbody');
  if (!currentData.users || currentData.users.length === 0) {
    tbody.innerHTML =
        '<tr><td colspan="9" class="loading">No statistics data</td></tr>';
    return;
  }

  // Data for QoS achievement calculation
  const userRatesForQos = [];
  const configuredOnlyMode = currentData.per_user_stats_available === false;

  const rows =
      currentData.users
          .map(user => {
            const displayGbr = user.target_gbr_gbps ?? 0;
            const displayMbr = user.target_mbr_gbps ?? 0;
            const configuredGbr = user.configured_gbr_gbps ?? displayGbr;
            const configuredMbr = user.configured_mbr_gbps ?? displayMbr;
            const statsAvailable = user.stats_available !== false;

            // Calculate rate
            let rate = null;
            if (statsAvailable && lastData && timeDelta > 0) {
              const lastUser =
                  lastData.users.find(u => u.user_id === user.user_id);
              if (lastUser) {
                const bytesDiff = user.bytes_passed - lastUser.bytes_passed;
                rate = (bytesDiff * 8) / 1e9 / timeDelta;
              }
            }

            // Collect QoS data
            if (!configuredOnlyMode && rate !== null) {
              userRatesForQos.push({
                user_id : user.user_id,
                rate : rate,
                target_gbr_gbps : displayGbr,
                target_mbr_gbps : displayMbr,
                qos_tier : user.qos_tier
              });
            }

            // Determine rate status
            let rateClass = 'zero';
            let status = statsAvailable ? 'NO_DATA' : 'CONFIGURED';
            if (rate !== null && rate > 0.01) {
              if (rate < displayGbr * 0.95) {
                rateClass = 'warning';
                status = 'LOW';
              } else if (rate > displayMbr * 1.05) {
                rateClass = 'danger';
                status = 'HIGH';
              } else {
                rateClass = 'good';
                status = 'OK';
              }
            } else if (statsAvailable) {
              rate = 0;
            }

            // Drop rate style
            let dropClass = 'zero';
            if (typeof user.drop_rate_percent === 'number') {
              if (user.drop_rate_percent > 10)
                dropClass = 'high';
              else if (user.drop_rate_percent > 1)
                dropClass = 'low';
            }

            const rateDisplay =
                configuredOnlyMode || rate === null ? 'N/A' : rate.toFixed(2);
            const bytesPassedDisplay =
                configuredOnlyMode
                    ? 'N/A'
                    : (statsAvailable ? formatMaybeBytes(user.bytes_passed)
                                      : 'N/A');
            const bytesDroppedDisplay =
                configuredOnlyMode
                    ? 'N/A'
                    : (statsAvailable ? formatMaybeBytes(user.bytes_dropped)
                                      : 'N/A');
            const dropRateDisplay =
                configuredOnlyMode
                    ? 'N/A'
                    : (typeof user.drop_rate_percent === 'number'
                           ? `${user.drop_rate_percent.toFixed(2)}%`
                           : 'N/A');

            return `
            <tr>
                <td>U${user.user_id}</td>
                <td>${user.user_ip}</td>
                <td><span class="qos-badge ${user.qos_tier}">${
                user.qos_tier}</span></td>
                <td><span class="rate-value ${rateClass}">${
                rateDisplay}</span></td>
                <td>
                    <div class="target-range">
                        <span class="primary">${displayGbr.toFixed(2)} - ${
                displayMbr.toFixed(2)}</span>
                        <span class="secondary">cfg ${
                configuredGbr.toFixed(1)} - ${configuredMbr.toFixed(1)}</span>
                    </div>
                </td>
                <td>${bytesPassedDisplay}</td>
                <td>${bytesDroppedDisplay}</td>
                <td><span class="drop-rate ${dropClass}">${
                dropRateDisplay}</span></td>
                <td><span class="status-badge ${status}">${status}</span></td>
            </tr>
        `;
          })
          .join('');

  tbody.innerHTML = rows;

  // Update QoS achievement metrics
  if (configuredOnlyMode) {
    resetQosRuntimeDisplay(
        'Per-user runtime statistics are unavailable in official UPF mode',
        true);
  } else {
    updateQosMetrics(userRatesForQos);
  }
}

/**
 * Update traffic chart
 */
function updateTrafficChart(users, timestamp, perUserStatsAvailable = true) {
  if (!trafficChart) {
    initTrafficChart();
  }

  if (!users || users.length === 0)
    return;

  if (!perUserStatsAvailable) {
    chartData.labels = [];
    chartData.datasets = [];
    trafficChart.options.plugins.title.text =
        'Per-user runtime chart unavailable in official UPF mode';
    trafficChart.update('none');
    return;
  }

  trafficChart.options.plugins.title.text =
      'User Measured Traffic (Gbps, runtime QoS basis)';

  const time = formatTimestamp(timestamp);
  chartData.labels.push(time);

  // Keep only the last 30 data points
  if (chartData.labels.length > 30) {
    chartData.labels.shift();
    chartData.datasets.forEach(dataset => dataset.data.shift());
  }

  // Assign unique colors for each user (10 users)
  const userColors = [
    '#10b981', // U1 - HIGH - green
    '#059669', // U2 - HIGH - dark green
    '#f59e0b', // U3 - MEDIUM - orange
    '#d97706', // U4 - MEDIUM - dark orange
    '#b45309', // U5 - MEDIUM - brown orange
    '#ef4444', // U6 - LOW - red
    '#dc2626', // U7 - LOW - dark red
    '#b91c1c', // U8 - LOW - darker red
    '#991b1b', // U9 - LOW - even darker red
    '#7f1d1d'  // U10 - LOW - darkest red
  ];

  // Update data for each user
  users.forEach((user, index) => {
    if (!chartData.datasets[index]) {
      chartData.datasets[index] = {
        label : `U${user.user_id} (${user.qos_tier})`,
        data : [],
        borderColor : userColors[index] || '#6b7280',
        backgroundColor : (userColors[index] || '#6b7280') + '20',
        tension : 0.4,
        fill : false,
        borderWidth : 2,
        pointRadius : 2
      };
    }

    // Calculate rate
    let rate = 0;
    if (user.stats_available === false) {
      rate = null;
    } else if (lastStatsData && lastStatsTime) {
      const lastUser =
          lastStatsData.users.find(u => u.user_id === user.user_id);
      if (lastUser) {
        const timeDelta = timestamp - lastStatsTime;
        if (timeDelta > 0) {
          const bytesDiff = user.bytes_passed - lastUser.bytes_passed;
          rate = (bytesDiff * 8) / 1e9 / timeDelta;
        }
      }
    }

    chartData.datasets[index].data.push(rate);
  });

  trafficChart.update('none'); // No animation for better performance
}

/**
 * Initialize traffic chart
 */
function initTrafficChart() {
  const ctx = document.getElementById('traffic-chart').getContext('2d');
  trafficChart = new Chart(ctx, {
    type : 'line',
    data : chartData,
    options : {
      responsive : true,
      maintainAspectRatio : false,
      plugins : {
        legend : {display : true, position : 'top'},
        title : {
          display : true,
          text : 'User Measured Traffic (Gbps, runtime QoS basis)'
        }
      },
      scales : {
        y : {beginAtZero : true, title : {display : true, text : 'Gbps'}},
        x : {title : {display : true, text : 'Time'}}
      },
      interaction : {intersect : false, mode : 'index'}
    }
  });
}

// ==================== Refresh Control ====================

/**
 * Refresh configuration
 */
function refreshConfig() { fetchUpfConfig(); }

/**
 * Start auto refresh
 */
function startAutoRefresh() {
  if (refreshTimer) {
    clearInterval(refreshTimer);
  }

  if (autoRefreshEnabled) {
    refreshTimer =
        setInterval(() => { fetchRealtimeStats(); }, refreshInterval);
  }
}

/**
 * Stop auto refresh
 */
function stopAutoRefresh() {
  if (refreshTimer) {
    clearInterval(refreshTimer);
    refreshTimer = null;
  }
}

// ==================== Event Listeners ====================

// Auto refresh toggle
document.getElementById('auto-refresh').addEventListener('change', (e) => {
  autoRefreshEnabled = e.target.checked;
  if (autoRefreshEnabled) {
    startAutoRefresh();
  } else {
    stopAutoRefresh();
  }
});

// Refresh interval selection
document.getElementById('refresh-interval').addEventListener('change', (e) => {
  refreshInterval = parseInt(e.target.value);
  if (autoRefreshEnabled) {
    startAutoRefresh();
  }
});

// ==================== Initialization ====================

/**
 * Initialize after page load
 */
window.addEventListener('DOMContentLoaded', () => {
  console.log('OAI-UPF Web Monitor initializing...');

  // Load initial data
  fetchUpfConfig();
  fetchUserSessions();
  fetchRealtimeStats();
  fetchQosAnalysis();

  // Start auto refresh
  startAutoRefresh();

  // Periodically refresh session status (faster rate for detecting UPF
  // disconnect)
  setInterval(() => { fetchUserSessions(); },
              2000); // Check connection status every 2 seconds

  // Periodically refresh config and QoS analysis (slower rate)
  setInterval(() => {
    fetchUpfConfig();
    fetchQosAnalysis();
  }, 10000); // Refresh every 10 seconds
});

// Cleanup before page unload
window.addEventListener('beforeunload', () => { stopAutoRefresh(); });

// ==================== QoS Achievement Analysis ====================

/**
 * Fetch QoS analysis configuration
 */
async function fetchQosAnalysis() {
  try {
    const response = await fetch(`${API_BASE_URL}/qos/analysis`);
    if (!response.ok)
      throw new Error('Failed to fetch QoS analysis');
    const data = await response.json();
    updateQosConfigDisplay(data);
  } catch (error) {
    console.error('Failed to fetch QoS analysis:', error);
  }
}

/**
 * Update QoS configuration display
 */
function updateQosConfigDisplay(data) {
  const config = data.config;
  const basis = data.rate_basis || {};
  const multiplier = basis.target_multiplier || 1.0;
  const runtimeAvailable = data.per_user_runtime_available !== false;
  document.getElementById('qos-total-users').textContent = config.total_users;
  document.getElementById('qos-total-gbr').textContent =
      `${formatGbpsNumber(config.total_gbr_gbps, 2)} Gbps`;
  document.getElementById('qos-total-mbr').textContent =
      `${formatGbpsNumber(config.total_mbr_gbps, 2)} Gbps`;
  document.getElementById('qos-display-mbr').textContent =
      `${formatGbpsNumber(config.display_total_mbr_gbps, 2)} Gbps`;
  document.getElementById('qos-config-note').textContent =
      `${basis.measured_label || 'Runtime statistics unavailable'}. ${
          basis.display_label ||
          'Expected totals follow the same runtime accounting basis'} (${
          multiplier.toFixed(2)}x vs ${
          basis.configured_label || 'PFCP GBR/MBR session targets'}).`;
  document.getElementById('tier-rate-high').textContent =
      formatRangeWithExpected(0.8, 1.2, multiplier);
  document.getElementById('tier-rate-medium').textContent =
      formatRangeWithExpected(0.4, 0.8, multiplier);
  document.getElementById('tier-rate-low').textContent =
      formatRangeWithExpected(0.2, 0.4, multiplier);

  if (!runtimeAvailable) {
    resetQosRuntimeDisplay(
        'Per-user runtime statistics are unavailable in official UPF mode',
        true);
  }
}

/**
 * Calculate and update QoS achievement metrics
 * Called after each real-time statistics fetch
 */
function updateQosMetrics(userRates) {
  if (!userRates || userRates.length === 0)
    return;

  // Record current sample
  const sample = {
    timestamp : Date.now(),
    users : userRates.map(u => ({
                            id : u.user_id,
                            rate : u.rate,
                            gbr : u.target_gbr_gbps,
                            mbr : u.target_mbr_gbps,
                            tier : u.qos_tier
                          }))
  };

  qosHistory.samples.push(sample);
  if (qosHistory.samples.length > qosHistory.maxSamples) {
    qosHistory.samples.shift();
  }

  // Calculate current achievement
  let gbrSatisfied = 0;
  let mbrCompliant = 0;
  let totalActive = 0;

  // Statistics by tier
  const tierStats = {
    HIGH : {count : 0, gbrSat : 0, mbrComp : 0, totalRate : 0},
    MEDIUM : {count : 0, gbrSat : 0, mbrComp : 0, totalRate : 0},
    LOW : {count : 0, gbrSat : 0, mbrComp : 0, totalRate : 0}
  };

  userRates.forEach(user => {
    const rate = user.rate || 0;
    const gbr = user.target_gbr_gbps;
    const mbr = user.target_mbr_gbps;
    const tier = user.qos_tier;

    // Only count users with traffic
    if (rate > 0.01) {
      totalActive++;
      if (rate >= gbr * 0.95)
        gbrSatisfied++; // Allow 5% tolerance
      if (rate <= mbr * 1.05)
        mbrCompliant++; // Allow 5% tolerance

      if (tierStats[tier]) {
        tierStats[tier].count++;
        tierStats[tier].totalRate += rate;
        if (rate >= gbr * 0.95)
          tierStats[tier].gbrSat++;
        if (rate <= mbr * 1.05)
          tierStats[tier].mbrComp++;
      }
    }
  });

  // Calculate percentages
  const gbrRate = totalActive > 0 ? (gbrSatisfied / totalActive * 100) : 0;
  const mbrRate = totalActive > 0 ? (mbrCompliant / totalActive * 100) : 0;
  const overallScore = gbrRate * 0.7 + mbrRate * 0.3;

  // Update display
  updateMetricDisplay('gbr-satisfaction', 'gbr-bar', gbrRate);
  updateMetricDisplay('mbr-compliance', 'mbr-bar', mbrRate);
  updateMetricDisplay('overall-score', 'overall-bar', overallScore);

  // Update tier statistics table
  updateTierStatsTable(tierStats);
}

/**
 * Update single metric display
 */
function updateMetricDisplay(valueId, barId, percentage) {
  const valueEl = document.getElementById(valueId);
  const barEl = document.getElementById(barId);

  if (valueEl) {
    valueEl.textContent = `${percentage.toFixed(1)}%`;
    // Set color based on percentage
    if (percentage >= 99) {
      valueEl.className = 'metric-value excellent';
    } else if (percentage >= 95) {
      valueEl.className = 'metric-value good';
    } else if (percentage >= 90) {
      valueEl.className = 'metric-value acceptable';
    } else {
      valueEl.className = 'metric-value poor';
    }
  }

  if (barEl) {
    barEl.style.width = `${Math.min(percentage, 100)}%`;
  }
}

/**
 * Update tier statistics table
 */
function updateTierStatsTable(tierStats) {
  const tbody = document.getElementById('tier-stats-tbody');
  if (!tbody)
    return;

  const tiers = [ 'HIGH', 'MEDIUM', 'LOW' ];

  const rows =
      tiers
          .map(tier => {
            const stats = tierStats[tier];
            const avgRate =
                stats.count > 0 ? (stats.totalRate / stats.count) : 0;
            const gbrPct =
                stats.count > 0 ? (stats.gbrSat / stats.count * 100) : 0;
            const mbrPct =
                stats.count > 0 ? (stats.mbrComp / stats.count * 100) : 0;
            const overall = gbrPct * 0.7 + mbrPct * 0.3;

            const gbrClass =
                gbrPct >= 95 ? 'good' : (gbrPct >= 90 ? 'acceptable' : 'poor');
            const mbrClass =
                mbrPct >= 95 ? 'good' : (mbrPct >= 90 ? 'acceptable' : 'poor');
            const overallClass = overall >= 95
                                     ? 'good'
                                     : (overall >= 90 ? 'acceptable' : 'poor');

            return `
            <tr>
                <td><span class="qos-badge ${tier}">${tier}</span></td>
                <td>${stats.count}</td>
                <td class="${gbrClass}">${gbrPct.toFixed(1)}%</td>
                <td class="${mbrClass}">${mbrPct.toFixed(1)}%</td>
                <td>${avgRate.toFixed(2)} Gbps</td>
                <td class="${overallClass}">${overall.toFixed(1)}%</td>
            </tr>
        `;
          })
          .join('');

  tbody.innerHTML =
      rows || '<tr><td colspan="6" class="loading">No active users</td></tr>';
}
