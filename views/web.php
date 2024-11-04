<?php  include '../includes/header.php';?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <title>Website Monitor Dashboard</title>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <style>
    body {
        font-family: Arial, sans-serif;
        background-color: #f4f4f4;
        margin: 0;
        padding: 20px;
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

    th,
    td {
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

    .block-btn,
    .unblock-btn {
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
    </style>
</head>

<body>
    <?php  include '../includes/navbar.php';?>
    <div class="d-flex" style="height:90vh">
        <?php  include '../includes/sidebar.php';?>
        <div class=" row flex-fill main-content">
            <div class="row mt-2">
                <div class="col-md-12">
                    <div class="card">
                        <div class="card-body">
                            <div class="table-responsive">

                                <h1>Website Monitor Dashboard</h1>

                                <table id="threat-logs-table">
                                    <thead>
                                        <tr>
                                            <th>ID</th>
                                            <th>URL</th>
                                            <th>Status</th>
                                            <th>Response Time</th>
                                            <th>Issue</th>
                                            <th>IP Address</th>
                                            <th>Blocked</th>
                                            <th>Action</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <!-- Table content populated by AJAX -->
                                    </tbody>
                                </table>

                                <script>
                                $(document).ready(function() {
                                    // Fetch and display threat logs
                                    function fetchThreatLogs() {
                                        $.ajax({
                                            url: 'controller.php',
                                            type: 'POST',
                                            contentType: 'application/json',
                                            data: JSON.stringify({
                                                action: 'fetchThreats'
                                            }),
                                            success: function(response) {
                                                const logs = JSON.parse(response);
                                                const tableBody = $('#threat-logs-table tbody');
                                                tableBody.empty();

                                                logs.forEach(function(log) {
                                                    const blockedText = log.is_blocked ?
                                                        'Yes' : 'No';
                                                    const actionButton = log.is_blocked ?
                                                        `<button class="unblock-btn" data-ip="${log.ip_address}">Unblock</button>` :
                                                        `<button class="block-btn" data-ip="${log.ip_address}">Block</button>`;

                                                    const row = `
                            <tr>
                                <td>${log.id}</td>
                                <td>${log.url}</td>
                                <td>${log.status}</td>
                                <td>${log.response_time}</td>
                                <td>${log.issue}</td>
                                <td>${log.ip_address}</td>
                                <td>${blockedText}</td>
                                <td>${actionButton}</td>
                            </tr>
                        `;
                                                    tableBody.append(row);
                                                });
                                            },
                                            error: function(xhr, status, error) {
                                                console.error('Error fetching threat logs:', xhr
                                                    .responseText);
                                            }
                                        });
                                    }

                                    // Start Website Monitor on button click
                                    $('#start-monitor').click(function() {
                                        $.ajax({
                                            url: 'controller.php',
                                            type: 'POST',
                                            contentType: 'application/json',
                                            data: JSON.stringify({
                                                action: 'startWebsiteMonitor'
                                            }),
                                            success: function(response) {
                                                const result = JSON.parse(response);
                                                alert(result.status);
                                            },
                                            error: function(xhr, status, error) {
                                                console.error(
                                                    'Error starting website monitor:',
                                                    xhr.responseText);
                                                alert(
                                                    'Failed to start the website monitor. Please try again.'
                                                );
                                            }
                                        });
                                    });

                                    // Block/unblock IP address on button click
                                    $(document).on('click', '.block-btn, .unblock-btn', function() {
                                        const ipAddress = $(this).data('ip');
                                        const action = $(this).hasClass('block-btn') ?
                                            'blockIPAddress' : 'unblockIPAddress';

                                        $.ajax({
                                            url: 'controller.php',
                                            type: 'POST',
                                            contentType: 'application/json',
                                            data: JSON.stringify({
                                                action: action,
                                                ipAddress: ipAddress
                                            }),
                                            success: function(response) {
                                                const result = JSON.parse(response);
                                                alert(result.status);
                                                fetchThreatLogs(); // Refresh the table
                                            },
                                            error: function(xhr, status, error) {
                                                console.error('Error:', xhr.responseText);
                                                alert(
                                                    'Failed to update the IP status. Please try again.'
                                                );
                                            }
                                        });
                                    });

                                    // Fetch logs every 5 seconds
                                    setInterval(fetchThreatLogs, 5000);

                                    // Initial data fetch
                                    fetchThreatLogs();
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