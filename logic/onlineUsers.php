<?php
header('Content-Type: application/json');
include '../src/config/Database.php';

class ActiveUserMonitor {
    private $conn;

    public function __construct($dbConnection) {
        $this->conn = $dbConnection;
    }

    // Function to get the count of active users
    public function getActiveUserCount() {
        $query = "SELECT COUNT(*) AS active_user_count FROM active_users_log WHERE is_active = 1";
        $stmt = $this->conn->prepare($query);
        $stmt->execute();
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($result) {
            return ['status' => 'success', 'active_user_count' => $result['active_user_count']];
        }
        return ['status' => 'error', 'message' => 'Could not retrieve active user count'];
    }
}

// Initialize the Database connection
$database = new Database();
$db = $database->getConnection();
$monitor = new ActiveUserMonitor($db);

// Return active user count upon request
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    echo json_encode($monitor->getActiveUserCount());
} else {
    echo json_encode(['status' => 'error', 'message' => 'Invalid request']);
}