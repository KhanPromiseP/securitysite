<?php
include __DIR__.'/src/config/Database.php'; // Adjust the path as needed

class OnlineUsers
{
    private $conn;

    public function __construct($dbConnection)
    {
        $this->conn = $dbConnection;
    }

    // Get the total number of users online
    public function getOnlineUserCount()
    {
        // Define the timeout period to consider users as online (e.g., 5 minutes)
        $timeout = 5 * 60; // 5 minutes in seconds

        // Calculate the timestamp for the timeout
        $currentTime = time();
        $timeoutTime = $currentTime - $timeout;

        // Query to count users with recent activity
        $query = "SELECT COUNT(*) AS online_count FROM user_sessions WHERE last_activity > FROM_UNIXTIME(:timeout_time) AND status = 'online'";
        $stmt = $this->conn->prepare($query);

        // Bind the timeout time parameter
        $stmt->bindParam(':timeout_time', $timeoutTime);

        // Execute the query
        $stmt->execute();

        // Fetch the count of online users
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        return $result['online_count'];
    }
}

// Create a new instance of OnlineUsers
$onlineUsers = new OnlineUsers($pdo); // $pdo is your PDO database connection instance

// Get the count of online users
$onlineUserCount = $onlineUsers->getOnlineUserCount();

// Output the count as JSON
header('Content-Type: application/json');
echo json_encode(array('online_user_count' => $onlineUserCount));