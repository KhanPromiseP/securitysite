<?php
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST");
header("Content-Type: application/json");

include '../src/config/Database.php'; 

class WeeklyReports
{
    private $conn;

    public function __construct($dbConnection)
    {
        $this->conn = $dbConnection;
    }

    public function fetchReportsForLastWeek()
    {
        date_default_timezone_set('UTC'); // Set the default timezone

        $endDate = date('Y-m-d H:i:s'); // Current time
        $startDate = date('Y-m-d H:i:s', strtotime('-7 days')); // 7 days ago

        $query = "SELECT COUNT(*) AS report_count 
                  FROM generated_reports 
                  WHERE generated_at BETWEEN :start_date AND :end_date";

        try {
            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(':start_date', $startDate);
            $stmt->bindParam(':end_date', $endDate);
            $stmt->execute();
            $result = $stmt->fetch(PDO::FETCH_ASSOC);

            return $result ? (int)$result['report_count'] : 0;
        } catch (PDOException $e) {
            error_log("Error fetching reports: " . $e->getMessage());
            return 0;
        }
    }
}

$database = new Database();
$conn = $database->getConnection();

if (!$conn) {
    die(json_encode(['error' => 'Database connection not initialized.']));
}

$weeklyReports = new WeeklyReports($conn);
$reportCount = $weeklyReports->fetchReportsForLastWeek();

echo json_encode(['report_count' => $reportCount]);
