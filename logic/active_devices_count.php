<?php

require_once '../src/config/Database.php';

$database = new Database();
$dbConnection = $database->getConnection();

if (!$dbConnection) {
    die(json_encode(['error' => 'Failed to connect to the database']));
}

$sql = "SELECT COUNT(*) as count FROM active_users_log";
$stmt = $dbConnection->prepare($sql);

if ($stmt->execute()) {
    $result = $stmt->fetch(PDO::FETCH_ASSOC);
    echo json_encode(['active_device_count' => $result['count']]);
} else {
    echo json_encode(['error' => 'Failed to execute the query']);
}

$dbConnection = null;

?>
