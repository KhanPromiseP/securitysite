<?php include '../includes/header.php'; ?>

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
                                                        ? `<button class="toggle-btn unblock" data-ip="${log.ip_address}">Unblock</button>`
                                                        : `<button class="toggle-btn block" data-ip="${log.ip_address}">Block</button>`;

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

                                    setInterval(fetchNetworkLogs, 5000);

                                    $(document).on('click', '.toggle-btn', function () {
                                    const ipAddress = $(this).data('ip');
                                    const isUnblockAction = $(this).hasClass('unblock');
                                    const action = isUnblockAction ? 'unblockIPAddress' : 'blockIPAddress';

                                    console.log('IP:', ipAddress, 'Action:', action); 

                                    $.ajax({
                                        url: '../logic/NetworkController.php',
                                        type: 'POST',
                                        contentType: 'application/json',
                                        data: JSON.stringify({
                                            action: action,
                                            ipAddress: ipAddress
                                        }),
                                        success: function (response) {
                                            const result = JSON.parse(response);
                                            console.log(result); 
                                            // alert(result.status);
                                            fetchNetworkLogs();
                                        },
                                        error: function (xhr, status, error) {
                                            console.error('Error:', xhr.responseText);
                                            alert('Failed to update the IP status. Please try again.');
                                        }
                                    });
                                    });

                                    fetchNetworkLogs();
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
