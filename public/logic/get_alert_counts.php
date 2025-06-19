<?php
header('Content-Type: application/json');
include '../../src/config/Database.php'; 

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
            'network_logs' => 0,
            'websites_logs' => 0,
           
        ];

        $queries = [
            'network_logs' => "SELECT COUNT(*) as count FROM network_logs",
            'website_logs' => "SELECT COUNT(*) as count FROM websites_logs",
        
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