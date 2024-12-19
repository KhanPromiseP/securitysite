<?php
header("Content-Type: application/json");

include '../src/config/Database.php'; 

class AlertCounter
{
    private $conn;

    public function __construct($dbConnection)
    {
        $this->conn = $dbConnection;
    }

    public function getTotalAlertsForPastWeek()
    {
        date_default_timezone_set('UTC');

        $endDate = date('Y-m-d');
        $startDate = date('Y-m-d', strtotime('-7 days')); 

        $queries = [
            'network_logs' => "SELECT COUNT(*) AS alert_count FROM network_logs WHERE DATE(detected_at) BETWEEN :start_date AND :end_date",
            'websites_logs' => "SELECT COUNT(*) AS alert_count FROM websites_logs WHERE DATE(checked_at) BETWEEN :start_date AND :end_date",
        ];
        
        $totalAlerts = 0;

        foreach ($queries as $table => $query) {
            try {
                error_log("Executing query on $table with date range: $startDate to $endDate");
                $stmt = $this->conn->prepare($query);
                $stmt->bindParam(':start_date', $startDate);
                $stmt->bindParam(':end_date', $endDate);
                $stmt->execute();
                $result = $stmt->fetch(PDO::FETCH_ASSOC);
                error_log("Result from $table: " . json_encode($result));
        
                if ($result && isset($result['alert_count'])) {
                    $totalAlerts += (int)$result['alert_count'];
                }
            } catch (PDOException $e) {
                error_log("Error querying $table: " . $e->getMessage());
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
$totalAlerts = $alertCounter->getTotalAlertsForPastWeek();

error_log("Total alerts for past week: " . $totalAlerts);
echo json_encode(['total_alerts' => $totalAlerts]);
