<?php
// Include the database configuration file
include __DIR__.'/src/config/Database.php'; // Make sure to update this path if needed

class AlertDisplay
{
    private $conn;

    // Constructor to initialize the database connection
    public function __construct($dbConnection)
    {
        $this->conn = $dbConnection;
    }

    // Function to get all alerts from all tables
    public function getAllAlerts()
    {
        // Queries for each alert table
        $queries = [
            'suspicious_behavior' => "SELECT 'suspicious_behavior' AS alert_type, id, user_id, ip_address, behavior_details, detection_time, is_blocked FROM suspicious_behavior",
            'suspicious_files' => "SELECT 'suspicious_files' AS alert_type, id, file_name, file_size, upload_time, file_path FROM suspicious_files",
            'detected_vulnerabilities' => "SELECT 'detected_vulnerabilities' AS alert_type, id, vulnerability_type, details, detection_time FROM detected_vulnerabilities",
            'suspicious_traffic' => "SELECT 'suspicious_traffic' AS alert_type, id, src_ip, dest_ip, packet_size, protocol FROM suspicious_traffic",
            'suspicious_emails' => "SELECT 'suspicious_emails' AS alert_type, id, sender, recipient, subject, body, timestamp FROM suspicious_emails"
        ];

        $allAlerts = []; // Array to store all alerts

        // Execute each query and store the results in the array
        foreach ($queries as $table => $query) {
            $stmt = $this->conn->prepare($query);
            $stmt->execute();
            $alerts = $stmt->fetchAll(PDO::FETCH_ASSOC); // Fetch all alerts

            if (!empty($alerts)) { // Only merge non-empty results
                $allAlerts = array_merge($allAlerts, $alerts);
            }
        }

        return $allAlerts; // Return all alerts
    }
}

// Initialize the database connection
$database = new Database();
$dbConnection = $database->getConnection();

if (!$dbConnection) {
    die(json_encode(['error' => 'Failed to connect to the database']));
}

// Initialize the AlertDisplay with the database connection
$alertDisplay = new AlertDisplay($dbConnection);

// Get all the alerts
$allAlerts = $alertDisplay->getAllAlerts();

// Output the alerts as JSON (this can be fetched via AJAX for display)
header('Content-Type: application/json');
if (empty($allAlerts)) {
    echo json_encode(['alerts' => []]);  // No alerts available
} else {
    echo json_encode(['alerts' => $allAlerts]);
}