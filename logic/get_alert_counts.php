<?php
header('Content-Type: application/json');
include '../src/config/Database.php'; 

class AlertDisplay
{
    private $conn;

    public function __construct($dbConnection)
    {
        $this->conn = $dbConnection;
    }

    public function getAlertCounts()
    {
        $counts = [
            'suspicious_behavior' => 0,
            'suspicious_files' => 0,
            'detected_vulnerabilities' => 0,
            'suspicious_traffic' => 0,
            'suspicious_emails' => 0,
        ];

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

        return $counts;
    }
}

$database = new Database();
$dbConnection = $database->getConnection();

$alertDisplay = new AlertDisplay($dbConnection);
$alertCounts = $alertDisplay->getAlertCounts();

header('Content-Type: application/json');
echo json_encode(['alert_counts' => $alertCounts]);