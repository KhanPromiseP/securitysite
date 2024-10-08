<?php  include '../includes/header.php';?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Real-time Alerts</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>

    </style>
</head>

<body>
    <?php  include '../includes/navbar.php';?>
    <div class="d-flex">
        <?php  include '../includes/sidebar.php';?>
        <div class="row flex-fill main-content">
            <div class=" col-md-12">
                <div class="card">

                    <div class="card-body">
                        <div class="table-responsive">
                            <div id="alerts-container">
                                <!-- Alert inserted here -->

                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <script>
        function fetchAlerts() {
            var xhr = new XMLHttpRequest();
            xhr.open('GET', '../logic/displayAlerts.php', true);
            xhr.onload = function() {
                if (xhr.status >= 200 && xhr.status < 300) {

                    console.log("Raw JSON Response: ", xhr.responseText);

                    var response = JSON.parse(xhr.responseText);
                    console.log(response);

                    var alertsContainer = document.getElementById('alerts-container');
                    alertsContainer.innerHTML = '';

                    if (response.alerts && response.alerts.length > 0) {

                        var groupedAlerts = response.alerts.reduce(function(groups, alert) {
                            if (!groups[alert.alert_type]) {
                                groups[alert.alert_type] = [];
                            }
                            groups[alert.alert_type].push(alert);
                            return groups;
                        }, {});


                        for (var alertType in groupedAlerts) {
                            if (groupedAlerts.hasOwnProperty(alertType)) {
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

        setInterval(fetchAlerts, 30000);


        fetchAlerts();
        </script>
    </div>
</body>

</html>