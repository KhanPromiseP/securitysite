<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Real-time Alerts</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
    table {
        width: 100%;
        border-collapse: collapse;
        font-family: Arial, sans-serif;
        margin-bottom: 20px;
    }

    th,
    td {
        border: 1px solid #ddd;
        padding: 10px;
        text-align: left;
    }

    th {
        background-color: #f4f4f4;
    }

    .alert-table {
        margin-top: 20px;
    }

    .alert-type {
        background-color: #e0e0e0;
        font-weight: bold;
        padding: 5px;
    }

    .no-alerts {
        text-align: center;
        font-style: italic;
        color: #777;
    }

    /* Sidebar Styling */
    .sidebar {
        width: 200px;
        height: 100vh;
        position: fixed;
        top: 0;
        left: 0;
        padding: 10px;
        background-color: #343a40;
        color: white;
    }

    .sidebar .nav-link {
        padding: 15px;
        font-size: 18px;
        transition: background-color 0.3s ease;
    }

    .sidebar .nav-link.active,
    .sidebar .nav-link:hover {
        background-color: #007bff;
        border-radius: 8px;
    }

    .main-content {
        margin-left: 250px;
        padding: 20px;
        background-color: #f8f9fa;
        height: 100vh;
        overflow-y: auto;
    }

    /* Table Styles */
    .table-hover tbody tr:hover {
        background-color: #f1f3f5;
    }

    .card-header {
        background-color: #007bff;
        color: white;
        padding: 15px;
        font-size: 18px;
    }

    .card-body {
        padding: 20px;
    }

    /* Responsive Design */
    @media (max-width: 992px) {
        .main-content {
            margin-left: 0;
        }

        .sidebar {
            position: static;
            width: 100%;
            height: auto;
        }
    }

    @media (max-width: 576px) {
        .main-content {
            padding: 10px;
        }

        .sidebar .nav-link {
            padding: 10px;
            font-size: 16px;
        }

        .card .card-body {
            padding: 15px;
        }
    }

    /* Highlight links and buttons */
    a.nav-link.active {
        background-color: #0056b3;
        color: #ffffff !important;
    }

    button:focus {
        outline: none;
        box-shadow: 0 0 5px #007bff;
    }

    /*some ther styls */
    /* Ensure that the main content and sidebar adjust properly on small screens */
    @media (max-width: 768px) {
        .sidebar {
            width: 100%;
            height: auto;
            position: relative;
        }

        .main-content {
            margin-left: 0;
        }

        /* Reduce padding and adjust font size for smaller screens */
        .sidebar .nav-link {
            padding: 10px;
            font-size: 16px;
        }

        .navbar-brand {
            font-size: 18px;
        }

        .navbar-nav .nav-link {
            font-size: 16px;
        }
    }

    /* For larger screens, ensure proper spacing and alignment */
    @media (min-width: 769px) {
        .main-content {
            margin-left: 250px;
        }

        .sidebar {
            width: 200px;
            height: 100vh;
        }

        .navbar-brand {
            font-size: 22px;
        }

        .navbar-nav .nav-link {
            font-size: 18px;
        }
    }

    /* Ensure buttons and links remain highlighted on focus/click */
    .nav-link:focus,
    .nav-link:active {
        background-color: #0056b3 !important;
        color: #fff !important;
        border-radius: 8px;
    }

    .btn-primary:focus,
    .btn-primary:active {
        background-color: #0056b3 !important;
        border-color: #0056b3 !important;
    }
    </style>
</head>

<body>
    <div class="d-flex">
        <nav class="bg-dark sidebar">
            <div class="p-3">
                <img src="assets/icons/logo.png" alt="Company Logo" class="img-fluid mb-3">
                <h3 class="text-white">Security Dashboard</h3>
                <ul class="nav flex-column">
                    <li class="nav-item"><a href="index.php" class="nav-link text-white active">Dashboard</a></li>
                    <li class="nav-item"><a href="displayAlert.js.php" class="nav-link text-white">Security Alerts</a>
                    </li>
                    <li class="nav-item"><a href="logs.php" class="nav-link text-white">System Logs</a></li>
                    <li class="nav-item"><a href="reports.php" class="nav-link text-white">Reports</a></li>
                    <li class="nav-item"><a href="users.php" class="nav-link text-white">User Management</a></li>
                    <li class="nav-item"><a href="#" class="nav-link text-white">Settings</a></li>
                </ul>
            </div>
        </nav>
        <h1>Real-time Alerts</h1>
        <div class="row">
            <div class="col-md-12">
                <div class="card">

                    <div class="card-body">
                        <!-- Responsive security alerts table -->
                        <div class="table-responsive">
                            <div id="alerts-container">
                                <!-- Alert sections will be dynamically inserted here -->
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <script>
        function fetchAlerts() {
            var xhr = new XMLHttpRequest();
            xhr.open('GET', 'displayAlerts.php', true);
            xhr.onload = function() {
                if (xhr.status >= 200 && xhr.status < 300) {

                    console.log("Raw JSON Response: ", xhr.responseText);

                    var response = JSON.parse(xhr.responseText); // Keep only one JSON.parse here
                    console.log(response);

                    var alertsContainer = document.getElementById('alerts-container');
                    alertsContainer.innerHTML = ''; // Clear previous alerts

                    if (response.alerts && response.alerts.length > 0) {
                        // Group alerts by type
                        var groupedAlerts = response.alerts.reduce(function(groups, alert) {
                            if (!groups[alert.alert_type]) {
                                groups[alert.alert_type] = [];
                            }
                            groups[alert.alert_type].push(alert);
                            return groups;
                        }, {});

                        // Create sections for each alert type
                        for (var alertType in groupedAlerts) {
                            if (groupedAlerts.hasOwnProperty(alertType)) {
                                // Create and append section for each alert type
                                var section = document.createElement('div');
                                section.innerHTML = '<div class="alert-type">' + alertType +
                                    '</div>';
                                var table = document.createElement('table');
                                table.className = 'alert-table';
                                table.innerHTML =
                                    '<thead>' +
                                    '<tr>' +
                                    '<th>Details</th>' +
                                    '<th>Detection Time</th>' +
                                    '</tr>' +
                                    '</thead>' +
                                    '<tbody>' +
                                    groupedAlerts[alertType].map(function(alert) {
                                        // Adjust the fields based on your table structure
                                        var details = '';
                                        if (alertType === 'suspicious_behavior') {
                                            details = 'User ID: ' + alert.user_id + ', IP: ' +
                                                alert.ip_address +
                                                ', Behavior: ' + alert.behavior_details;
                                        } else if (alertType === 'suspicious_files') {
                                            details = 'File: ' + alert.file_name + ', Size: ' +
                                                alert.file_size +
                                                ' bytes';
                                        } else if (alertType === 'detected_vulnerabilities') {
                                            details = 'Vulnerability: ' + alert
                                                .vulnerability_type + ', Details: ' +
                                                alert.details;
                                        } else if (alertType === 'suspicious_traffic') {
                                            details = 'Source IP: ' + alert.src_ip +
                                                ', Destination IP: ' + alert
                                                .dest_ip + ', Size: ' + alert.packet_size +
                                                ' bytes, Protocol: ' +
                                                alert.protocol;
                                        } else if (alertType === 'suspicious_emails') {
                                            details = 'Sender: ' + alert.sender +
                                                ', Recipient: ' + alert
                                                .recipient + ', Subject: ' + alert.subject;
                                        }
                                        return '<tr>' +
                                            '<td>' + details + '</td>' +
                                            '<td>' + (alert.detection_time || alert.timestamp ||
                                                "No timestamp available") + '</td>' +
                                            '</tr>';
                                    }).join('') +
                                    '</tbody>';
                                section.appendChild(table);
                                alertsContainer.appendChild(section);
                            }
                        }
                    } else {
                        var noAlerts = document.createElement('div');
                        noAlerts.className = 'no-alerts';
                        noAlerts.textContent = 'No alerts available.';
                        alertsContainer.appendChild(noAlerts);
                    }
                } else {
                    console.error('Failed to load alerts:', xhr.statusText);
                }
            };
            xhr.onerror = function() {
                console.error('Request error.');
            };
            xhr.send();
        }

        // Fetch alerts every 30 seconds
        setInterval(fetchAlerts, 30000);

        // Initial fetch
        fetchAlerts();

        function fetchAlerts() {
            var xhr = new XMLHttpRequest();
            xhr.open('GET', 'displayAlerts.php', true);
            xhr.onload = function() {
                if (xhr.status >= 200 && xhr.status < 300) {

                    console.log("Raw JSON Response: ", xhr.responseText);

                    var response = JSON.parse(xhr.responseText); // Keep only one JSON.parse here
                    console.log(response);

                    var alertsContainer = document.getElementById('alerts-container');
                    alertsContainer.innerHTML = ''; // Clear previous alerts

                    if (response.alerts && response.alerts.length > 0) {
                        // Group alerts by type
                        var groupedAlerts = response.alerts.reduce(function(groups, alert) {
                            if (!groups[alert.alert_type]) {
                                groups[alert.alert_type] = [];
                            }
                            groups[alert.alert_type].push(alert);
                            return groups;
                        }, {});

                        // Create sections for each alert type
                        for (var alertType in groupedAlerts) {
                            if (groupedAlerts.hasOwnProperty(alertType)) {
                                // Create and append section for each alert type
                                var section = document.createElement('div');
                                section.innerHTML = '<div class="alert-type">' + alertType +
                                    '</div>';
                                var table = document.createElement('table');
                                table.className = 'alert-table';
                                table.innerHTML =
                                    '<thead>' +
                                    '<tr>' +
                                    '<th>Details</th>' +
                                    '<th>Detection Time</th>' +
                                    '</tr>' +
                                    '</thead>' +
                                    '<tbody>' +
                                    groupedAlerts[alertType].map(function(alert) {
                                        // Adjust the fields based on your table structure
                                        var details = '';
                                        if (alertType === 'suspicious_behavior') {
                                            details = 'User ID: ' + alert.user_id + ', IP: ' +
                                                alert.ip_address +
                                                ', Behavior: ' + alert.behavior_details;
                                        } else if (alertType === 'suspicious_files') {
                                            details = 'File: ' + alert.file_name + ', Size: ' +
                                                alert.file_size +
                                                ' bytes';
                                        } else if (alertType === 'detected_vulnerabilities') {
                                            details = 'Vulnerability: ' + alert
                                                .vulnerability_type + ', Details: ' +
                                                alert.details;
                                        } else if (alertType === 'suspicious_traffic') {
                                            details = 'Source IP: ' + alert.src_ip +
                                                ', Destination IP: ' + alert
                                                .dest_ip + ', Size: ' + alert.packet_size +
                                                ' bytes, Protocol: ' +
                                                alert.protocol;
                                        } else if (alertType === 'suspicious_emails') {
                                            details = 'Sender: ' + alert.sender +
                                                ', Recipient: ' + alert
                                                .recipient + ', Subject: ' + alert.subject;
                                        }
                                        return '<tr>' +
                                            '<td>' + details + '</td>' +
                                            '<td>' + (alert.detection_time || alert.timestamp ||
                                                "No timestamp available") + '</td>' +
                                            '</tr>';
                                    }).join('') +
                                    '</tbody>';
                                section.appendChild(table);
                                alertsContainer.appendChild(section);
                            }
                        }
                    } else {
                        var noAlerts = document.createElement('div');
                        noAlerts.className = 'no-alerts';
                        noAlerts.textContent = 'No alerts available.';
                        alertsContainer.appendChild(noAlerts);
                    }
                } else {
                    console.error('Failed to load alerts:', xhr.statusText);
                }
            };
            xhr.onerror = function() {
                console.error('Request error.');
            };
            xhr.send();
        }

        // Fetch alerts every 30 seconds
        setInterval(fetchAlerts, 30000);

        // Initial fetch
        fetchAlerts();
        </script>
    </div>
</body>

</html>