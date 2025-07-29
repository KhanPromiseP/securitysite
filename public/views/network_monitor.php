<?php

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

if (!isset($_SESSION['user_id'])) {
        header('Location: ./login.php');
        
    }


include __DIR__ . '/../../includes/header.php';
include __DIR__ . '/../../includes/sidebar.php';
include __DIR__ . '/../../includes/navbar.php';


$apiEndpoint = '../logic/monitor_data.php'; 

?>

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Advanced Security System Monitor</title>
  <style>
    body {
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      background-color:rgb(187, 187, 209); 
      color: #e0e0e0;
      padding: 20px;
      margin: 0;
      display: flex; 
    }

    
    .container {
      flex-grow: 1; 
      margin-left: 260px; 
      max-width: calc(100% - 280px); 
      background:rgb(247, 247, 252); 
      padding: 30px;
      border-radius: 12px;
      box-shadow: 0 5px 25px rgba(211, 190, 190, 0.6);
      border: 1px solid #4a4a60;
    }

    h1, h2 {
      color:rgb(16, 17, 17); 
      margin-top: 0;
      border-bottom: 2px solidrgb(125, 125, 179);
      padding-bottom: 10px;
      margin-bottom: 20px;
    }

    .dashboard-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); 
        gap: 20px;
        margin-bottom: 20px;
    }

    .stats-card, .alert-card, .log-card {
        background:rgb(59, 59, 61); 
        padding: 20px;
        border-radius: 10px;
        box-shadow: 0 2px 10px rgba(180, 160, 160, 0.4);
        border: 1px solidrgb(174, 174, 202);
    }

    .stats-card p {
        margin: 8px 0;
        font-size: 1.1em;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }

    .stats-card p strong {
        color: #99eeff; 
    }
    .stats-card p span {
        font-weight: bold;
        color: #e0e0e0;
    }

    /* Alert Styling */
    #alerts-container {
        margin-top: 20px;
        min-height: 50px;
    }
    .alert {
        padding: 12px 20px;
        margin-bottom: 10px;
        border-radius: 6px;
        font-weight: bold;
        display: flex;
        align-items: center;
    }
    .alert strong {
        margin-right: 10px;
        font-size: 1.1em;
    }
    .alert::before {
        font-family: 'Arial'; /* Or a font-awesome-like icon font */
        margin-right: 10px;
        font-size: 1.2em;
    }

    .alert-critical {
        background-color #ff4d4d; /* Red */
        color: #fff;
    }
    .alert-critical::before { content: ''; }

    .alert-high {
        background-color: #ff9933; /* Orange */
        color: #fff;
    }
    .alert-high::before { content: ''; }

    .alert-warning {
        background-color: #ffcc00; /* Yellow */
        color: #333;
    }
    .alert-warning::before { content: ''; }

    .alert-info {
        background-color: #3399ff; /* Blue */
        color: #fff;
    }
    .alert-info::before { content: 'ℹ'; }

    /* Log Output Styling */
    .log-card {
        grid-column: 1 / -1; /* Spans full width */
        min-height: 350px;
    }
    .log-table-container {
        max-height: 300px;
        overflow-y: auto;
        background: #000;
        border-radius: 5px;
        border: 1px solidrgb(124, 124, 145);
    }
    .log-table {
      width: 100%;
      border-collapse: collapse;
      font-family: monospace;
      font-size: 0.9em;
    }
    .log-table th, .log-table td {
      padding: 8px 12px;
      text-align: left;
      border-bottom: 1px solidrgb(136, 136, 158);
    }
    .log-table th {
      background-color:rgb(241, 250, 250); /* Darker green for headers */
      color:rgb(36, 29, 29);
      position: sticky;
      top: 0;
      z-index: 1;
    }
    .log-level-critical { color: #ff6666; }
    .log-level-high { color: #ffaa66; }
    .log-level-medium { color: #ffff66; }
    .log-level-low, .log-level-info { color: #99ccff; }
    .highlight {
        background-color:rgb(248, 244, 244);
        color:rgb(22, 21, 21);
        padding: 2px 4px;
        border-radius: 3px;
    }

    /* System Health Indicator */
    .system-health-status {
        display: inline-block;
        padding: 8px 15px;
        border-radius: 8px;
        font-weight: bold;
        margin-top: 10px;
        box-shadow: 0 2px 5px rgba(112, 109, 109, 0.3);
    }
    .health-good { background-color: #28a745; color: white; }
    .health-warning { background-color: #ffc107; color: black; }
    .health-critical { background-color: #dc3545; color: white; }

    /* Tables for processes and network */
    .data-table-container {
        margin-top: 20px;
        background:rgb(227, 227, 235);
        padding: 20px;
        border-radius: 10px;
        box-shadow: 0 2px 10px rgba(168, 156, 156, 0.4);
        border: 1px solid #3c3c5a;
    }
    .data-table {
        width: 100%;
        border-collapse: collapse;
        color:rgb(10, 10, 10);
        font-size: 0.9em;
    }
    .data-table th, .data-table td {
        padding: 10px;
        text-align: left;
        border-bottom: 1px solidrgb(71, 71, 184);
    }
    .data-table th {
        background-color: #005050;
        color:rgb(245, 252, 251);
    }
    .data-table tr:hover {
        background-color:rgb(221, 221, 235);
    }

    /* Responsive adjustments */
    @media (max-width: 768px) {
        .container {
            margin-left: 0;
            max-width: 100%;
            padding: 15px;
        }
        .dashboard-grid {
            grid-template-columns: 1fr; /* Stack columns on small screens */
        }
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>Advanced Security System Monitor</h1>

    <div class="stats-card">
        <h2>System Overview <span id="system-health-indicator" class="system-health-status">Loading...</span></h2>
        <p><strong>CPU Load (1-min):</strong> <span id="cpu-load-1min">Loading...</span></p>
        <p><strong>CPU % (estimated):</strong> <span id="cpu-percent">Loading...</span></p>
        <p><strong>Memory Used:</strong> <span id="memory-used">Loading...</span></p>
        <p><strong>Memory %:</strong> <span id="memory-percent">Loading...</span></p>
        <p><strong>Disk Used:</strong> <span id="disk-used">Loading...</span></p>
        <p><strong>Disk %:</strong> <span id="disk-percent">Loading...</span></p>
        <p><strong>System Uptime:</strong> <span id="system-uptime">Loading...</span></p>
    </div>

    <div class="alert-card">
        <h2>Active Alerts</h2>
        <div id="alerts-container">
            <div class="alert alert-info">Fetching alerts...</div>
        </div>
    </div>

    <div class="data-table-container">
        <h2>Top Processes by CPU/Memory</h2>
        <div style="max-height: 250px; overflow-y: auto;">
            <table class="data-table">
                <thead>
                    <tr>
                        <th>User</th>
                        <th>PID</th>
                        <th>%CPU</th>
                        <th>%MEM</th>
                        <th>Command</th>
                    </tr>
                </thead>
                <tbody id="top-processes-body">
                    <tr><td colspan="5">Loading processes...</td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <div class="data-table-container">
        <h2>Network Connections (Top 10)</h2>
        <div style="max-height: 250px; overflow-y: auto;">
            <table class="data-table">
                <thead>
                    <tr>
                        <th>State</th>
                        <th>Local Address</th>
                        <th>Peer Address</th>
                        <th>Program/PID</th>
                    </tr>
                </thead>
                <tbody id="network-connections-body">
                    <tr><td colspan="4">Loading network connections...</td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <div class="log-card">
      <h2>Security Log Monitor (Latest 50 Critical/High)</h2>
      <div class="log-table-container">
        <table class="log-table">
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Level</th>
                    <th>Process</th>
                    <th>Message</th>
                </tr>
            </thead>
            <tbody id="security-logs-body">
                <tr><td colspan="4">Fetching logs...</td></tr>
            </tbody>
        </table>
      </div>
    </div>

    <div style="margin-top: 30px; text-align: center;">
        <h2>🛠️ System Actions (Under Development)</h2>
        <button onclick="restartWebServer()" style="padding: 10px 20px; background-color: #6a05ad; color: white; border: none; border-radius: 5px; cursor: pointer; font-size: 1em;">Restart Web Server (Dummy)</button>
        <p style="font-size: 0.8em; color: #888;">*Note: These actions require proper backend handling and elevated permissions. Use with extreme caution.*</p>
    </div>

  </div>

  <script>
    // IMPORTANT: Make sure this path is correct relative to your HTML file!
    const API_ENDPOINT = '<?php echo $apiEndpoint; ?>';

    async function fetchMonitorData() {
        try {
            const response = await fetch(API_ENDPOINT);
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            const data = await response.json();
            console.log("Monitoring Data:", data);

            // --- Update UI with fetched data ---
            updateSystemMetrics(data);
            displayAlerts(data.alerts);
            displaySecurityLogs(data.security_logs);
            displayTopProcesses(data.top_processes);
            displayNetworkConnections(data.network_connections);
            updateSystemHealthIndicator(data.system_health);

        } catch (error) {
            console.error("Error fetching monitoring data:", error);
            // Display error message on the frontend for the user
            document.getElementById('alerts-container').innerHTML = `<div class="alert alert-critical"><strong>ERROR:</strong> Failed to fetch monitoring data. ${error.message}</div>`;
            document.getElementById('cpu-percent').textContent = 'Error';
            document.getElementById('memory-percent').textContent = 'Error';
            document.getElementById('disk-percent').textContent = 'Error';
            document.getElementById('system-health-indicator').textContent = 'OFFLINE';
            document.getElementById('system-health-indicator').className = 'system-health-status health-critical';
        }
    }

    function updateSystemMetrics(data) {
        document.getElementById('cpu-load-1min').textContent = data.cpu.load_1min !== undefined ? data.cpu.load_1min : 'N/A';
        document.getElementById('cpu-percent').textContent = data.cpu.percentage_1min !== undefined ? `${data.cpu.percentage_1min}%` : 'N/A';
        document.getElementById('memory-used').textContent = data.memory && data.memory.used_mb !== undefined ? `${data.memory.used_mb} MB` : 'N/A';
        document.getElementById('memory-percent').textContent = data.memory && data.memory.percentage !== undefined ? `${data.memory.percentage}%` : 'N/A';
        document.getElementById('disk-used').textContent = data.disk && data.disk.used_gb !== undefined ? `${data.disk.used_gb} GB` : 'N/A';
        document.getElementById('disk-percent').textContent = data.disk && data.disk.percentage !== undefined ? `${data.disk.percentage}%` : 'N/A';
        document.getElementById('system-uptime').textContent = data.uptime || 'N/A';
    }

    function displayAlerts(alerts) {
        const alertsContainer = document.getElementById('alerts-container');
        alertsContainer.innerHTML = ''; // Clear previous alerts
        if (alerts && alerts.length > 0) {
            alerts.forEach(alert => {
                const alertDiv = document.createElement('div');
                // Use a generic 'alert' class and specific level classes for styling
                alertDiv.className = `alert alert-${alert.level}`;
                alertDiv.innerHTML = `<strong>${alert.level.toUpperCase()} Alert:</strong> ${alert.message} (Type: ${alert.type})`;
                alertsContainer.appendChild(alertDiv);
            });
        } else {
            alertsContainer.innerHTML = '<div class="alert alert-info">No active alerts.</div>';
        }
    }

    function displaySecurityLogs(logs) {
        const logsBody = document.getElementById('security-logs-body');
        logsBody.innerHTML = ''; // Clear previous logs
        if (logs && logs.length > 0) {
            logs.forEach(log => {
                const row = logsBody.insertRow();
                row.className = `log-level-${log.level}`; // For CSS styling
                row.insertCell().textContent = log.timestamp;
                row.insertCell().textContent = log.level.toUpperCase();
                row.insertCell().textContent = log.process;
                const msgCell = row.insertCell();
                msgCell.innerHTML = highlightKeywords(log.message, log.keyword); // Use highlightKeywords
            });
        } else {
            logsBody.innerHTML = '<tr><td colspan="4">No security logs found.</td></tr>';
        }
    }

    function displayTopProcesses(processes) {
        const processesBody = document.getElementById('top-processes-body');
        processesBody.innerHTML = '';
        if (processes && processes.length > 0 && processes[0].command) { // Check if data is valid
            processes.forEach(p => {
                const row = processesBody.insertRow();
                row.insertCell().textContent = p.user;
                row.insertCell().textContent = p.pid;
                row.insertCell().textContent = `${p.cpu_percent}%`;
                row.insertCell().textContent = `${p.mem_percent}%`;
                row.insertCell().textContent = p.command;
            });
        } else {
             processesBody.innerHTML = '<tr><td colspan="5">Could not retrieve top processes or no processes running.</td></tr>';
        }
    }

    function displayNetworkConnections(connections) {
        const connectionsBody = document.getElementById('network-connections-body');
        connectionsBody.innerHTML = '';
        if (connections && connections.length > 0 && connections[0].state) { // Check if data is valid
            connections.forEach(conn => {
                const row = connectionsBody.insertRow();
                row.insertCell().textContent = conn.state;
                row.insertCell().textContent = conn.local_address;
                row.insertCell().textContent = conn.peer_address;
                row.insertCell().textContent = conn.program;
            });
        } else {
            connectionsBody.innerHTML = '<tr><td colspan="4">Could not retrieve network connections or none active.</td></tr>';
        }
    }

    function updateSystemHealthIndicator(healthStatus) {
        const indicator = document.getElementById('system-health-indicator');
        indicator.textContent = healthStatus;
        // Remove existing health classes and add the new one
        indicator.className = 'system-health-status'; // Reset
        indicator.classList.add(`health-${healthStatus.toLowerCase()}`);
    }

    // Function to highlight keywords in logs
    function highlightKeywords(message, keyword) {
        if (keyword) {
            // Use a more robust regex to ensure whole word matching for keywords like 'error', 'warn'
            // and handle multiple occurrences if needed. For simplicity, just the first match:
            const regex = new RegExp(`\\b(${keyword})\\b`, 'gi');
            return message.replace(regex, '<span class="highlight">$1</span>');
        }
        return message;
    }

    // --- Real-time Regulation on Frontend (Conceptual) ---
    // This function is a placeholder. You need a secure backend endpoint to handle actual actions.
    async function restartWebServer() {
        if (confirm('Are you sure you want to attempt to restart the web server? This is a system action and may cause downtime.')) {
            try {
                // This would hit a *separate* PHP endpoint (e.g., action_handler.php)
                // that has very strict security controls and permissions.
                const response = await fetch('<?php echo $apiEndpoint; ?>', { // Using same endpoint for demo, but SHOULD BE DIFFERENT
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ action: 'restart_service', service: 'apache2' })
                });
                const result = await response.json();
                alert(`Action response: ${result.message}`);
                // Re-fetch data after action to see its effect
                fetchMonitorData();
            } catch (error) {
                console.error("Error performing action:", error);
                alert("Failed to perform action. Check console for details and backend implementation.");
            }
        }
    }

    // Initial fetch and then poll every few seconds
    fetchMonitorData();
    setInterval(fetchMonitorData, 5000); // Poll every 5 seconds (adjust as needed)
  </script>
</body>
</html>