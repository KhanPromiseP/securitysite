<?php 
include '../includes/header.php'; 

// session_start();
// include '../src/config/middleware.php';
// SimpleMiddleware::requireAdmin();
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Threat Dashboard</title>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f4f4;
            margin: 0;
            padding: 70px;
        }

        h1 {
            text-align: center;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            font-size: 1em;
            box-shadow: 0 0 20px rgba(0, 0, 0, 0.15);
        }

        th, td {
            padding: 12px 15px;
            text-align: left;
            border: 1px solid #ddd;
        }

        th {
            background-color: #009879;
            color: #ffffff;
        }

        tr:nth-child(even) {
            background-color: #f3f3f3;
        }

        tr:nth-child(odd) {
            background-color: #ffffff;
        }

        .block-btn, .unblock-btn {
            padding: 5px 10px;
            cursor: pointer;
            color: white;
            border: none;
            border-radius: 5px;
        }

        .block-btn {
            background-color: red;
        }

        .unblock-btn {
            background-color: green;
        }

        @media (max-width: 768px) {
            body {
                padding: 20px;
            }

            table {
                font-size: 0.9em;
            }
        }
    </style>
</head>

<body>
    <?php include '../includes/navbar.php'; ?>

    <div class="d-flex">
        <?php include '../includes/sidebar.php'; ?>
        <div class="row flex-fill main-content" style="height:90vh">
            <div class="row mt-2">
                <div class="col-md-12">
                    <div class="card">
                        <div class="card-body">
                            <div class="table-responsive">
                                <h1>Network Scan Results</h1>

                                <table id="network-logs-table">
                                    <thead>
                                        <tr>
                                            <th>IP Address</th>
                                            <th>Threat Type</th>
                                            <th>User Crime</th>
                                            <th>Detected At</th>
                                            <th>Blocked</th>
                                            <th>Action</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <!-- Table content populated by AJAX -->
                                    </tbody>
                                </table>

                                <script>
                                    $(document).ready(function () {
                        function fetchNetworkLogs() {
                            $.ajax({
                                url: '../logic/ThreatModel.php',
                                type: 'POST',
                                contentType: 'application/json',
                                data: JSON.stringify({ action: 'getAllNetworkThreats' }),
                                success: function (response) {
                                    const logs = JSON.parse(response);
                                    const tableBody = $('#network-logs-table tbody');
                                    tableBody.empty();

                                    logs.forEach(function (log) {
                                        const isBlocked = log.is_blocked;
                                        const actionButton = isBlocked
                                            ? `<button class="unblock-btn" data-ip="${log.ip_address}">Unblock</button>`
                                            : `<button class="block-btn" data-ip="${log.ip_address}">Block</button>`;

                                        const row = `
                                            <tr>
                                                <td>${log.ip_address}</td>
                                                <td>${log.threat_type}</td>
                                                <td>${log.user_crime}</td>
                                                <td>${log.detected_at}</td>
                                                <td>${isBlocked ? 'Yes' : 'No'}</td>
                                                <td>${actionButton}</td>
                                            </tr>
                                        `;
                                        tableBody.append(row);
                                    });
                                },
                                error: function (xhr, status, error) {
                                    console.error('Error fetching network logs:', xhr.responseText);
                                }
                            });
                        }

                       
                                        // Block button action
                                        $(document).on('click', '.block-btn', function () {
                                            const ipAddress = $(this).data('ip');
                                            $.ajax({
                                                url: '../logic/NetworkController.php', // Correct backend URL
                                                type: 'POST',
                                                contentType: 'application/json',
                                                data: JSON.stringify({
                                                    action: 'blockIPAddress', // Matching the backend 'action' name
                                                    ipAddress: ipAddress
                                                }),
                                                success: function (response) {
                                                    const jsonResponse = JSON.parse(response); // Ensure proper JSON parsing
                                                    alert(jsonResponse.message);
                                                    fetchNetworkLogs(); // Reload the logs after successful block
                                                },
                                                error: function (xhr, status, error) {
                                                    alert('Error blocking IP: ' + error);
                                                }
                                            });
                                        });

                                        // Unblock button action
                                        $(document).on('click', '.unblock-btn', function () {
                                            const ipAddress = $(this).data('ip');
                                            $.ajax({
                                                url: '../logic/NetworkController.php', // Correct backend URL
                                                type: 'POST',
                                                contentType: 'application/json',
                                                data: JSON.stringify({
                                                    action: 'unblockIPAddress', // Matching the backend 'action' name
                                                    ipAddress: ipAddress
                                                }),
                                                success: function (response) {
                                                    const jsonResponse = JSON.parse(response); // Ensure proper JSON parsing
                                                    alert(jsonResponse.message);
                                                    fetchNetworkLogs(); // Reload the logs after successful unblock
                                                },
                                                error: function (xhr, status, error) {
                                                    alert('Error unblocking IP: ' + error);
                                                }
                                            });
                                        });

                        // Initial fetch of network logs
                        fetchNetworkLogs();
                        setInterval(fetchNetworkLogs, 5000); // Auto-refresh every 5 seconds
                    });

                                </script>

                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>

</html>
