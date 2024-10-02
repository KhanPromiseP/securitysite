<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <title>Security Dashboard</title>

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
    <h1>Suspicious Behavior Dashboard</h1>
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

            <?php
         
            include_once __DIR__ . '/src/config/Database.php'; // Use include_once to prevent re-declaration
            
            
            $database = new Database();
            $db = $database->getConnection();
            
            $query = "SELECT * FROM suspicious_behavior WHERE is_blocked = 1";
            $stmt = $db->prepare($query);
            $stmt->execute();
            $blockedIps = $stmt->fetchAll(PDO::FETCH_ASSOC);

            foreach ($blockedIps as $ip) {
                echo "<tr>";
                echo "<td>{$ip['user_id']}</td>";
                echo "<td>{$ip['ip_address']}</td>";
                echo "<td>{$ip['behavior_details']}</td>";
                echo "<td>{$ip['detection_time']}</td>";
                echo "<td>" . ($ip['is_blocked'] ? 'Yes' : 'No') . "</td>";
                echo "<td><button class='unblock-btn' data-ip='{$ip['ip_address']}'>Unblock</button></td>";
                echo "</tr>";
            }

            ?>
        </tbody>
    </table>
    <script>
    $(document).ready(function() {
        $('.unblock-btn').click(function() {
            const ipAddress = $(this).data('ip');

            $.ajax({
                url: 'unblock.php',
                type: 'POST',
                data: {
                    ip: ipAddress
                },
                success: function(response) {
                    console.log(response); // Log the response for debugging
                    alert(response); // Show success message
                    location.reload(); // Reload the page after unblocking
                },
                error: function(xhr, status, error) {
                    console.error('Error:', xhr.responseText); // Log error details
                    alert('Failed to unblock the IP. Please try again.');
                }
            });
        });
    });
    </script>
</body>

</html>