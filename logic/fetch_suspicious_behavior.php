<?php
include '../src/config/Database.php';

class SuspiciousBehavior {
    private $conn;

    public function __construct($dbConnection) {
        $this->conn = $dbConnection;
    }

    // Fetch suspicious IPs and behavior details
    public function fetchSuspiciousIPs() {
        $query = "SELECT ip_address, behavior_details, detection_time, is_blocked FROM  suspicious_behavior  ORDER BY detection_time DESC";
        $stmt = $this->conn->prepare($query);
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
}

// Initialize the database connection
$database = new Database();
$db = $database->getConnection();
$behavior = new SuspiciousBehavior($db);

// Fetch suspicious behavior
$suspiciousIPs = $behavior->fetchSuspiciousIPs();

// Send the data as a JSON response
echo json_encode($suspiciousIPs);