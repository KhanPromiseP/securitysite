<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

require_once '../src/config/Database.php';

$database = new Database();
$conn = $database->getConnection();

if (!$conn) {
    die('Database connection failed.');
}

date_default_timezone_set('UTC');
$endDate = date('Y-m-d');
$startDate = date('Y-m-d', strtotime('-7 days')); 

$sql = "SELECT * FROM generated_reports WHERE DATE(generated_at) BETWEEN :start_date AND :end_date ORDER BY generated_at DESC";
$stmt = $conn->prepare($sql);
$stmt->bindParam(':start_date', $startDate);
$stmt->bindParam(':end_date', $endDate);
$stmt->execute();

$reports = [];
while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
    $reports[] = [
        'alert_type' => $row['alert_type'],
        'report_details' => $row['report_details'],
        'generated_at' => $row['generated_at']
    ];
}

header('Content-Type: application/json');
echo json_encode($reports);
if (json_last_error() !== JSON_ERROR_NONE) {
    die('JSON Encoding Error: ' . json_last_error_msg());
}
