<?php
header('Content-Type: application/json');
// Include the database configuration file
include __DIR__.'/src/config/Database.php'; // Update the path as necessary

class AlertDisplay
{
    private $conn;

    // Constructor to initialize the database connection
    public function __construct($dbConnection)
    {
        $this->conn = $dbConnection;
    }

    // Function to get alert counts from all tables
    public function getAlertCounts()
    {
        $counts = [
            'suspicious_behavior' => 0,
            'suspicious_files' => 0,
            'detected_vulnerabilities' => 0,
            'suspicious_traffic' => 0,
            'suspicious_emails' => 0,
        ];

        // Queries for each alert table to get counts
        $queries = [
            'suspicious_behavior' => "SELECT COUNT(*) as count FROM suspicious_behavior",
            'suspicious_files' => "SELECT COUNT(*) as count FROM suspicious_files",
            'detected_vulnerabilities' => "SELECT COUNT(*) as count FROM detected_vulnerabilities",
            'suspicious_traffic' => "SELECT COUNT(*) as count FROM suspicious_traffic",
            'suspicious_emails' => "SELECT COUNT(*) as count FROM suspicious_emails"
        ];

        foreach ($queries as $table => $query) {
            $stmt = $this->conn->prepare($query);
            $stmt->execute();
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
            $counts[$table] = (int)$result['count'];
        }

        return $counts; // Return alert counts
    }
}

// Initialize the database connection
$database = new Database();
$dbConnection = $database->getConnection();

// Initialize AlertDisplay and get alert counts
$alertDisplay = new AlertDisplay($dbConnection);
$alertCounts = $alertDisplay->getAlertCounts();

// Output the counts as JSON
header('Content-Type: application/json');
echo json_encode(['alert_counts' => $alertCounts]);