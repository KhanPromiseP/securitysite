<?php

require_once '../../src/config/Database.php';

$database = new Database();
$dbConnection = $database->getConnection();

if (!$dbConnection) {
    die(json_encode(['error' => 'Failed to connect to the database']));
}

// Count all devices
$sql = "SELECT 
            (SELECT COUNT(*) FROM active_users_log) as total_count,
            (SELECT COUNT(*) FROM active_users_log WHERE status = 'disconnected') as disconnected_count";
$stmt = $dbConnection->prepare($sql);

if ($stmt->execute()) {
    $result = $stmt->fetch(PDO::FETCH_ASSOC);
    $active_count = $result['total_count'] - $result['disconnected_count'];
    echo json_encode([
        'active_device_count' => $active_count,
        'disconnected_count' => $result['disconnected_count']
    ]);
} else {
    echo json_encode(['error' => 'Failed to execute the query']);
}

$dbConnection = null;

?>