<?php 
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}


include __DIR__ . '/../../includes/header.php';
include __DIR__ . '/../../includes/sidebar.php';
include __DIR__ . '/../../includes/navbar.php';

if (!isset($_SESSION['user_id'])) {
        header('Location: ./login.php');
        
    }

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

        .connect-btn, .disconnect-btn {
            padding: 6px 12px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-weight: bold;
        }

        .connect-btn {
            background-color: green;
            color: white;
        }

        .disconnect-btn {
            background-color: red;
            color: white;
        }

        .counters-container {
            display: flex;
            justify-content: center;
            gap: 20px; 
            margin-top: 20px;
            flex-wrap: wrap; 
        }

        .device-count, .disconnected-count {
            font-size: 1.2em;
            font-weight: bold;
            padding: 10px 20px;
            border-radius: 4px;
            text-align: center;
        }

        .device-count {
            color: #333;
            background-color: #e9f7ef; 
            border: 1px solid #28a745;
        }

        .disconnected-count {
            color: #d9534f;
            background-color: #f9f9f9;
            border: 1px solid #d9534f;
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

                                <div class="counters-container">
                                    <div class="device-count" id="device-count">Active Devices: 0</div>
                                    <div class="disconnected-count" id="disconnected-count">Disconnected Devices: 0</div>
                                </div>

                                <div class="table-container">
                                    <table id="device-table">
                                        <thead>
                                            <tr>
                                                <th>IP Address</th>
                                                <th>MAC Address</th>
                                                <th>Hostname</th>
                                                <th>Last Seen</th>
                                                <th>Data Usage (MB)</th>
                                                <th>Status</th> <!-- New toggle column -->
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
                                                    const isConnected = device.status === 'connected';
                                                    const toggleLabel = isConnected ? 'Disconnect' : 'Connect';
                                                    const buttonClass = isConnected ? 'disconnect-btn' : 'connect-btn';

                                                    const row = `
                                                        <tr>
                                                            <td>${device.ip_address}</td>
                                                            <td>${device.mac_address}</td>
                                                            <td>${device.hostname}</td>
                                                            <td>${device.timestamp}</td>
                                                            <td>${device.data_usage_mb}</td>
                                                            <td>
                                                                <button class="${buttonClass}" data-ip="${device.ip_address}">
                                                                    ${toggleLabel}
                                                                </button>
                                                            </td>
                                                        </tr>
                                                    `;
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
                                                $('#disconnected-count').text(`Disconnected Devices: ${data.disconnected_count}`);
                                            
                                       if (data.disconnected_count > 0) {
                                            $('#disconnected-count').addClass('has-disconnected');
                                        } else {
                                            $('#disconnected-count').removeClass('has-disconnected');
                                        }
                                        
                                        $('#update-time').text(new Date().toLocaleTimeString());
                                    },
                                    error: function(xhr, status, error) {
                                        console.error('Error fetching device counts:', error);
                                        console.log('Response:', xhr.responseText);
                                    }
        });
                                    }

                                    // Handle toggle button click
                                    $(document).on('click', '.connect-btn, .disconnect-btn', function () {
                                        const ip = $(this).data('ip');
                                        const action = $(this).hasClass('disconnect-btn') ? 'disconnect' : 'connect';

                                        $.ajax({
                                            url: '../logic/toggle_connection.php',
                                            method: 'POST',
                                            contentType: 'application/json',
                                            data: JSON.stringify({ ip: ip, action: action }),
                                            success: function (response) {
                                                alert(response.message || 'Status toggled.');
                                                fetchActiveDevices(); // refresh only device list
                                            },
                                            error: function (xhr) {
                                                alert('Error toggling status: ' + xhr.responseText);
                                            }
                                        });
                                    });

                                    function updateRealTime() {
                                        fetchActiveDevices();
                                        fetchActiveDeviceCount();
                                    }

                                    setInterval(updateRealTime, 5000);

                                    $(document).ready(function () {
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
