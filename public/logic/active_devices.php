<?php
require_once '../../src/config/Database.php';
header('Content-Type: application/json');

$database = new Database();
$dbConnection = $database->getConnection();

if (!$dbConnection) {
    die(json_encode(['error' => 'Failed to connect to the database']));
}

$query = "SELECT * FROM active_users_log ORDER BY timestamp DESC";
$stmt = $dbConnection->query($query);

$activeDevices = [];
while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
    $activeDevices[] = [
        'ip_address' => $row['ip_address'],
        'mac_address' => $row['mac_address'],
        'hostname' => $row['hostname'],
        'timestamp' => $row['timestamp'],
        'data_usage_mb' => $row['data_usage_mb'],
        'status' => $row['status'] ?? 'connected' // Default if null
    ];
}

echo json_encode($activeDevices);
?>
