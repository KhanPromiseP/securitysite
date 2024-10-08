<?php
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST");
header("Content-Type: application/json");


ini_set('display_errors', 0); 
error_reporting(0); 

include '../src/config/Database.php'; 

class AlertCounter
{
    private $conn;

    public function __construct($dbConnection)
    {
        $this->conn = $dbConnection;
    }

    public function getTotalAlertsForToday()
    {
        $today = date('Y-m-d');

     
        $queries = [
            'suspicious_behavior' => "SELECT COUNT(*) AS alert_count FROM suspicious_behavior WHERE DATE(detection_time) = :today",
            'suspicious_files' => "SELECT COUNT(*) AS alert_count FROM suspicious_files WHERE DATE(upload_time) = :today",
            'detected_vulnerabilities' => "SELECT COUNT(*) AS alert_count FROM detected_vulnerabilities WHERE DATE(detection_time) = :today",
            'suspicious_traffic' => "SELECT COUNT(*) AS alert_count FROM suspicious_traffic WHERE DATE(timestamp) = :today",
            'suspicious_emails' => "SELECT COUNT(*) AS alert_count FROM suspicious_emails WHERE DATE(timestamp) = :today"
        ];

        $totalAlerts = 0;

        foreach ($queries as $table => $query) {
            try {
                $stmt = $this->conn->prepare($query);
                $stmt->bindParam(':today', $today);
                $stmt->execute();
                $result = $stmt->fetch(PDO::FETCH_ASSOC);

                // check to ensure $result is not null and accumulate total alerts
                if ($result && isset($result['alert_count'])) {
                    $totalAlerts += (int)$result['alert_count'];
                }
            } catch (PDOException $e) {
                error_log("Error querying table $table: " . $e->getMessage());
            }
        }

        return $totalAlerts;
    }
}

$database = new Database();
$conn = $database->getConnection();


if (!$conn) {
    die('Database connection not initialized.');
}

$alertCounter = new AlertCounter($conn);
$totalAlerts = $alertCounter->getTotalAlertsForToday();


header('Content-Type: application/json');
echo json_encode(['total_alerts' => $totalAlerts]);