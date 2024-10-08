<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <title>Admin Dashboard</title>

    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <style>
    table {
        width: 100%;
        border-collapse: collapse;
    }

    th,
    td {
        padding: 10px;
        border: 1px solid #ddd;
    }

    th {
        background-color: #f4f4f4;
    }

    .block-btn,
    .unblock-btn {
        padding: 5px 10px;
        cursor: pointer;
    }

    .block-btn {
        background-color: red;
        color: white;
    }

    .unblock-btn {
        background-color: green;
        color: white;
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

    /* button {
        padding: 10px 15px;
        background-color: #009879;
        color: white;
        border: none;
        cursor: pointer;
    } */

    button:hover {
        background-color: #007f65;
    }
    </style>


</head>

<body>

    <h1>Suspicious IP Addresses</h1>

    <table id="suspicious-table">
        <thead>
            <tr>
                <th>User ID</th>
                <th>IP Address</th>
                <th>Behavior Details</th>
                <th>Detection Time</th>
                <th>Blocked</th>
                <th>Action</th>
            </tr>
        </thead>
        <tbody>
            <!--table to be populated by AJAX here -->
        </tbody>
    </table>

    <script>
    $(document).ready(function() {
        /**
         * Function to fetch and update the table in real-time
         */

        function fetchSuspiciousBehavior() {
            $.ajax({
                url: '../logic/fetch_suspicious_behavior.php',
                type: 'GET',
                success: function(response) {
                    const suspiciousUsers = JSON.parse(response);
                    const tableBody = $('#suspicious-table tbody');
                    tableBody.empty();

                    // Looping through the data to populate the table
                    suspiciousUsers.forEach(function(user) {
                        const blockedText = user.is_blocked ? 'Yes' : 'No';
                        const actionButton = user.is_blocked ?
                            `<button class="unblock-btn" data-ip="${user.ip_address}" data-action="unblock">Unblock</button>` :
                            `<button class="block-btn" data-ip="${user.ip_address}" data-action="block">Block</button>`;

                        const row = `
                        <tr>
                            <td>${user.user_id}</td>
                            <td>${user.ip_address}</td>
                            <td>${user.behavior_details}</td>
                            <td>${user.detection_time}</td>
                            <td>${blockedText}</td>
                            <td>${actionButton}</td>
                        </tr>
                    `;
                        tableBody.append(row);
                    });
                },
                error: function(xhr, status, error) {
                    console.error('Error fetching data:', xhr.responseText);
                }
            });
        }


        setInterval(fetchSuspiciousBehavior, 5000); // 5 seconds interval


        $(document).on('click', '.block-btn, .unblock-btn', function() {
            const ipAddress = $(this).data('ip');
            const action = $(this).data('action');
            const button = $(this);

            // AJAX request to block or unblock the IP
            $.ajax({
                url: '../logic/block_unblock.php',
                type: 'POST',
                data: {
                    ip: ipAddress,
                    action: action
                },
                success: function(response) {
                    alert(response);
                    fetchSuspiciousBehavior();
                },
                error: function(xhr, status, error) {
                    console.error('Error:', xhr.responseText);
                    alert('Failed to update the IP status. Please try again.');
                }
            });
        });


        fetchSuspiciousBehavior();
    });
    </script>

</body>

</html>