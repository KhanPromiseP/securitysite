<?php
require_once '../../src/config/Database.php';
header('Content-Type: application/json');

$data = json_decode(file_get_contents('php://input'), true);

if (!isset($data['ip']) || !isset($data['action'])) {
    echo json_encode(['error' => 'Invalid parameters']);
    exit;
}

$ip = $data['ip'];
$action = $data['action']; // 'connect' or 'disconnect'
$status = $action === 'disconnect' ? 'disconnected' : 'connected';

$database = new Database();
$conn = $database->getConnection();

if (!$conn) {
    echo json_encode(['error' => 'Database connection failed']);
    exit;
}

try {
    $stmt = $conn->prepare("UPDATE active_users_log SET status = ? WHERE ip_address = ?");
    $stmt->execute([$status, $ip]);
    echo json_encode(['message' => "User has been $status successfully."]);
} catch (PDOException $e) {
    echo json_encode(['error' => 'Failed to update status']);
}
?>
