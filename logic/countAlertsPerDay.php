<?php
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST");
header("Content-Type: application/json");


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
            'network_logs' => "SELECT COUNT(*) AS alert_count FROM network_logs WHERE DATE(detected_at) = :today",
            'website_logs' => "SELECT COUNT(*) AS alert_count FROM website_logs WHERE DATE(checked_at) = :today",
        ];

        $totalAlerts = 0;

        foreach ($queries as $table => $query) {
            try {
                $stmt = $this->conn->prepare($query);
                $stmt->bindParam(':today', $today);
                $stmt->execute();
                $result = $stmt->fetch(PDO::FETCH_ASSOC);

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