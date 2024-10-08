<?php
require_once '../src/config/Database.php';

$database = new Database();
$conn = $database->getConnection();

$sql = "SELECT * FROM generated_reports WHERE generated_at >= NOW() - INTERVAL 1 HOUR ORDER BY generated_at DESC";
$stmt = $conn->prepare($sql);
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