<?php
// Include the database connection
include './src/config/Database.php';

class BehaviorFetcher {
    private $conn;

    public function __construct($dbConnection) {
        $this->conn = $dbConnection;
    }

    // Fetch all suspicious behaviors
    public function fetchSuspiciousBehaviors() {
        $query = "SELECT * FROM suspicious_behavior ORDER BY detection_time DESC";
        $stmt = $this->conn->prepare($query);
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
}
$database = new Database();
$dbConnection = $database->getConnection();

if (!$dbConnection) {
    die(json_encode(['error' => 'Failed to connect to the database']));
}
// Create the behavior fetcher instance
$behaviorFetcher = new BehaviorFetcher($dbConnection);
$behaviors = $behaviorFetcher->fetchSuspiciousBehaviors();

// Output the behaviors as JSON
header('Content-Type: application/json');
echo json_encode($behaviors);