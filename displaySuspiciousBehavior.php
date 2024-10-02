<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Suspicious Behavior Dashboard</title>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <style>
    table {
        width: 100%;
        border-collapse: collapse;
    }

    table,
    th,
    td {
        border: 1px solid black;
    }

    th,
    td {
        padding: 8px;
        text-align: left;
    }

    th {
        background-color: #f2f2f2;
    }

    .unblock-btn {
        background-color: #4CAF50;
        color: white;
        border: none;
        padding: 5px 10px;
        cursor: pointer;
    }






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
    }

    th {
        background-color: #009879;
        color: #ffffff;
    }

    tr:nth-child(even) {
        background-color: #f3f3f3f;
    }

    tr:nth-child(odd) {
        background-color: #ffffff;
    }

    button {
        padding: 10px 15px;
        background-color: #009879;
        color: white;
        border: none;
        cursor: pointer;
    }

    button:hover {
        background-color: #007f65;
    }
    </style>
</head>

<body>

    <h2>Suspicious Behavior Dashboard</h2>

    <table id="behavior-table">
        <thead>
            <tr>
                <th>User ID</th>
                <th>IP Address</th>
                <th>Behavior Details</th>
                <th>Detected Time</th>
                <th>Blocked</th>
                <th>Action</th>
            </tr>
        </thead>
        <tbody>
            <!-- Suspicious behavior rows will be populated here by JavaScript -->
        </tbody>
    </table>

    <script>
    // Function to fetch and display suspicious behavior data
    function fetchAndDisplayBehaviors() {
        $.ajax({
            url: 'fetchSuspiciousBehavior.php', // The PHP script that returns JSON data
            method: 'GET',
            dataType: 'json',
            success: function(data) {
                var tableBody = $('#behavior-table tbody');
                tableBody.empty(); // Clear the table before populating new data

                // Loop through the behaviors and add rows to the table
                data.forEach(function(behavior) {
                    var blockedStatus = behavior.is_blocked ? 'Blocked' : 'Unblocked';
                    var unblockButton = behavior.is_blocked ?
                        '<button class="unblock-btn" data-ip="' + behavior.ip_address +
                        '">Unblock</button>' : 'Already Unblocked';

                    var row = '<tr>' +
                        '<td>' + behavior.user_id + '</td>' +
                        '<td>' + behavior.ip_address + '</td>' +
                        '<td>' + behavior.behavior_details + '</td>' +
                        '<td>' + behavior.detection_time + '</td>' +
                        '<td>' + blockedStatus + '</td>' +
                        '<td>' + unblockButton + '</td>' +
                        '</tr>';

                    tableBody.append(row);
                });
            },
            error: function() {
                console.error('Error fetching suspicious behavior data.');
            }
        });
    }

    // Fetch data every 5 seconds to update the table in real time
    setInterval(fetchAndDisplayBehaviors, 5000);

    // Handle the unblock button click
    $(document).on('click', '.unblock-btn', function() {
        var ipAddress = $(this).data('ip');

        // Send an AJAX request to unblock the IP
        $.ajax({
            url: 'unblock_ip.php',
            type: 'POST',
            data: {
                ip_address: ipAddress
            },
            success: function(response) {
                alert(response); // Show the unblock response
                fetchAndDisplayBehaviors(); // Reload data to update the table
            }
        });
    });

    // Initial call to display data when the page loads
    fetchAndDisplayBehaviors();
    </script>

</body>

</html>