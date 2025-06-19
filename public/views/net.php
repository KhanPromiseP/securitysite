<?php 
include __DIR__ . '/../../includes/header.php';
include __DIR__ . '/../../includes/sidebar.php';



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

                                <!-- Updated Table Headers -->
                                <table id="network-logs-table">
                                    <thead>
                                        <tr>
                                            <th>IP Address</th>
                                            <th>Threat Type</th>
                                            <th>User Crime</th>
                                            <th>Confidence Score</th>
                                            <th>Device Name</th>
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
                                                        const isBlocked = log.is_blocked == 1;
                                                        const toggleLabel = isBlocked ? 'Unblock' : 'Block';
                                                        const toggleClass = isBlocked ? 'unblock-btn' : 'block-btn';

                                                        const row = `
                                                            <tr>
                                                                <td>${log.ip_address}</td>
                                                                <td>${log.threat_type}</td>
                                                                <td>${log.user_crime}</td>
                                                                <td>${log.confidence_score || 'N/A'}</td>
                                                                <td>${log.device_name || 'Unknown'}</td>
                                                                <td>${log.detected_at}</td>
                                                                <td>${isBlocked ? 'Yes' : 'No'}</td>
                                                               <td>
                                                                    <div style="display: flex; gap: 6px;">
                                                                        <button class="${toggleClass}" data-ip="${log.ip_address}">${toggleLabel}</button>
                                                                        <button class="delete-btn" data-ip="${log.ip_address}" style="background-color:red; color:white; border:none; border-radius:5px; padding:5px 10px;">Delete</button>
                                                                    </div>
                                                                </td>

                                                            </tr>
                                                        `;
                                                        tableBody.append(row);
                                                    });
                                                },
                                                error: function (xhr) {
                                                    console.error('Error fetching logs:', xhr.responseText);
                                                }
                                            });
                                        }

                                        // Toggle block/unblock status
                                        $(document).on('click', '.block-btn, .unblock-btn', function () {
                                            const ipAddress = $(this).data('ip');
                                            $.ajax({
                                                url: '../logic/ThreatModel.php',
                                                type: 'POST',
                                                contentType: 'application/json',
                                                data: JSON.stringify({
                                                    action: 'toggleBlockStatus',
                                                    ipAddress: ipAddress
                                                }),
                                                success: function (response) {
                                                    const res = JSON.parse(response);
                                                    alert(res.message || 'IP status updated');
                                                    fetchNetworkLogs();
                                                },
                                                error: function (xhr) {
                                                    alert('Error toggling status: ' + xhr.responseText);
                                                }
                                            });
                                        });

                                        // Delete IP
                                        $(document).on('click', '.delete-btn', function () {
                                            const ipAddress = $(this).data('ip');
                                            if (confirm(`Are you sure you want to delete IP ${ipAddress}?`)) {
                                                $.ajax({
                                                    url: '../logic/ThreatModel.php',
                                                    type: 'POST',
                                                    contentType: 'application/json',
                                                    data: JSON.stringify({
                                                        action: 'deleteThreatByIP',
                                                        ipAddress: ipAddress
                                                    }),
                                                    success: function (response) {
                                                        const res = JSON.parse(response);
                                                        alert(res.message);
                                                        fetchNetworkLogs();
                                                    },
                                                    error: function (xhr) {
                                                        alert('Error deleting record: ' + xhr.responseText);
                                                    }
                                                });
                                            }
                                        });

                                        fetchNetworkLogs();
                                        setInterval(fetchNetworkLogs, 5000);
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
