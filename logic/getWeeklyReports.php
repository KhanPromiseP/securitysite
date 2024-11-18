<?php

include  '../src/config/Database.php';

class WeeklyReports
{
    private $conn;

    public function __construct($dbConnection)
    {
        $this->conn = $dbConnection;
    }

    public function fetchWeeklyReportCount()
    {
        $query = "SELECT COUNT(*) as report_count FROM generated_reports WHERE YEARWEEK(generated_at, 1) = YEARWEEK(CURDATE(), 1)";
        $stmt = $this->conn->prepare($query);
        $stmt->execute();
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }
}

$database = new Database();
$conn = $database->getConnection();

$reports = new WeeklyReports($conn);

$data = $reports->fetchWeeklyReportCount();

header('Content-Type: application/json');
echo json_encode($data);