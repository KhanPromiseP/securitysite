<?php
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST");
header("Content-Type: application/json");


ini_set('display_errors', 0); // Disable error reporting
error_reporting(0); // Turn off all error reporting

// Include necessary configurations
include __DIR__.'/src/config/Database.php'; // Include the database class

class AlertCounter
{
    private $conn;

    public function __construct($dbConnection)
    {
        $this->conn = $dbConnection;
    }

    // Get the total number of alerts for today from all tables
    public function getTotalAlertsForToday()
    {
        $today = date('Y-m-d');

        // Queries for each table
        $queries = [
            'suspicious_behavior' => "SELECT COUNT(*) AS alert_count FROM suspicious_behavior WHERE DATE(detection_time) = :today",
            'suspicious_files' => "SELECT COUNT(*) AS alert_count FROM suspicious_files WHERE DATE(upload_time) = :today",
            'detected_vulnerabilities' => "SELECT COUNT(*) AS alert_count FROM detected_vulnerabilities WHERE DATE(detection_time) = :today",
            'suspicious_traffic' => "SELECT COUNT(*) AS alert_count FROM suspicious_traffic WHERE DATE(timestamp) = :today",
            'suspicious_emails' => "SELECT COUNT(*) AS alert_count FROM suspicious_emails WHERE DATE(timestamp) = :today"
        ];

        $totalAlerts = 0;

        // Execute each query and accumulate the total count
        foreach ($queries as $table => $query) {
            try {
                $stmt = $this->conn->prepare($query);
                $stmt->bindParam(':today', $today);
                $stmt->execute();
                $result = $stmt->fetch(PDO::FETCH_ASSOC);

                // Add a check to ensure $result is not null and accumulate total alerts
                if ($result && isset($result['alert_count'])) {
                    $totalAlerts += (int)$result['alert_count'];
                }
            } catch (PDOException $e) {
                // Log or display an error if a query fails (e.g., table does not exist)
                error_log("Error querying table $table: " . $e->getMessage());
            }
        }

        return $totalAlerts;
    }
}

// Initialize the database connection using the Database class
$database = new Database();
$conn = $database->getConnection();

// Check if the $conn is defined and valid
if (!$conn) {
    die('Database connection not initialized.');
}

// Initialize the AlertCounter with the database connection
$alertCounter = new AlertCounter($conn);
$totalAlerts = $alertCounter->getTotalAlertsForToday();

// Output the total number of alerts as JSON
header('Content-Type: application/json');
echo json_encode(['total_alerts' => $totalAlerts]);