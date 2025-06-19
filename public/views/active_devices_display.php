<?php 

// include '../../src/config/middleware.php';
// SimpleMiddleware::requireAdmin();

include __DIR__ . '/../../includes/header.php';
include __DIR__ . '/../../includes/sidebar.php';
// include __DIR__ . '/../../includes/header.php';



?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Active Devices List</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f9f9f9;
        }
        h1 {
            color: #333;
            text-align: center;
        }
        .table-container {
            max-width: 900px;
            margin: 0 auto;
            background-color: #fff;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 0 15px rgba(0, 0, 0, 0.1);
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #009879;
            color: white;
        }
        tr:nth-child(even) {
            background-color: #f2f2f2;
        }
        tr:hover {
            background-color: #f1f1f1;
        }
        .device-count {
            font-size: 1.2em;
            font-weight: bold;
            color: #333;
            margin-top: 20px;
            text-align: center;
        }
    </style>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
</head>
<body>
<?php include '../includes/navbar.php'; ?>
    <div class="d-flex" style="height:90vh">
        <?php include '../includes/sidebar.php'; ?>
        <div class="row flex-fill main-content">
            <div class="row mt-2">
                <div class="col-md-12">
                    <div class="card">
                        <div class="card-body">
                            <div class="table-responsive">
                                <h1>Real-Time Active Devices</h1>

                                <div class="device-count" id="device-count">0</div>

                                <div class="table-container">
                                    <table id="device-table">
                                        <thead>
                                            <tr>
                                                <th>IP Address</th>
                                                <th>MAC Address</th>
                                                <th>Hostname</th>
                                                <th>Last Seen</th>
                                                <th>Data_usage_mb</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <tr>
                                                <td colspan="4">Loading active devices...</td>
                                            </tr>
                                        </tbody>
                                    </table>
                                </div>

                                <script>
                                    function fetchActiveDevices() {
                                        $.ajax({
                                            url: '../logic/active_devices.php', 
                                            type: 'GET', 
                                            dataType: 'json', 
                                            success: function(data) {
                                                let deviceTableBody = $('#device-table tbody');
                                                deviceTableBody.empty(); 

                                                data.forEach(function(device) {
                                                    let row = $('<tr></tr>');
                                                    row.append(`<td>${device.ip_address}</td>`);
                                                    row.append(`<td>${device.mac_address}</td>`);
                                                    row.append(`<td>${device.hostname}</td>`);
                                                    row.append(`<td>${device.timestamp}</td>`);
                                                    row.append(`<td>${device.data_usage_mb}</td>`);
                                                    deviceTableBody.append(row);
                                                });
                                            },
                                            error: function(xhr, status, error) {
                                                console.error('Error fetching active devices:', error);
                                            }
                                        });
                                    }

                                    function fetchActiveDeviceCount() {
                                        $.ajax({
                                            url: '../logic/active_devices_count.php', 
                                            type: 'GET',
                                            dataType: 'json',
                                            success: function(data) {
                                                $('#device-count').text(`Active Devices Count: ${data.active_device_count}`);
                                            },
                                            error: function(xhr, status, error) {
                                                console.error('Error fetching active device count:', error);
                                            }
                                        });
                                    }

                                    function updateRealTime() {
                                        fetchActiveDevices();
                                        fetchActiveDeviceCount();
                                    }

                                    setInterval(updateRealTime, 1000);

                                    $(document).ready(function() {
                                        updateRealTime();
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
