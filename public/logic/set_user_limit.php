<?php
require_once '../../src/config/Database.php';
header('Content-Type: application/json');

// Start session
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Debug received data
error_log("Received POST: ".print_r($_POST, true));
error_log("Session token: ".($_SESSION['csrf_token'] ?? 'NOT FOUND'));

// Verify CSRF token
if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== ($_SESSION['csrf_token'] ?? '')) {
    error_log("CSRF Token Mismatch");
    die(json_encode(['success' => false, 'error' => 'Invalid CSRF token']));
}

$database = new Database();
$pdo = $database->getConnection();

if (!$pdo) {
    die(json_encode(['success' => false, 'error' => 'Database connection failed']));
}

// Get data from $_POST instead of php://input since frontend sends form data
$mac = $_POST['mac'] ?? '';
$limit = $_POST['limit'] ?? 0;

if (empty($mac)) {
    die(json_encode(['success' => false, 'error' => 'MAC address is required']));
}

// Validate limit is a positive number
if (!is_numeric($limit) || $limit < 0) {
    die(json_encode(['success' => false, 'error' => 'Invalid data limit']));
}

try {
    // First get current week data to determine throttling
    $getStmt = $pdo->prepare("SELECT current_week_data_mb FROM user_history WHERE mac_address = ?");
    $getStmt->execute([$mac]);
    $currentData = $getStmt->fetchColumn();
    
    // Update both data limit and throttling status
    $stmt = $pdo->prepare("
        UPDATE user_history 
        SET data_limit_mb = ?,
            is_throttled = CASE WHEN ? > 0 AND ? >= ? THEN TRUE ELSE FALSE END,
            updated_at = NOW()
        WHERE mac_address = ?
    ");
    
    $stmt->execute([$limit, $limit, $currentData, $limit, $mac]);
    
    // Log this action
    $logStmt = $pdo->prepare("
        INSERT INTO user_limits_log (mac_address, data_limit_mb, action, performed_by)
        VALUES (?, ?, 'SET_LIMIT', ?)
    ");
    $logStmt->execute([$mac, $limit, $_SESSION['user_id'] ?? 'system']);
    
    echo json_encode([
        'success' => true,
        'message' => 'Data limit updated successfully',
        'throttled' => ($limit > 0 && $currentData >= $limit)
    ]);
    
} catch (PDOException $e) {
    error_log("Database error in set_user_limit: " . $e->getMessage());
    echo json_encode([
        'success' => false,
        'error' => 'Database error: ' . $e->getMessage()
    ]);
}
?>