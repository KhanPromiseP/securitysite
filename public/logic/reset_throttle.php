<?php
require_once '../../src/config/Database.php';
header('Content-Type: application/json');

// Start session
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Verify CSRF token
if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== ($_SESSION['csrf_token'] ?? '')) {
    error_log("CSRF Token Mismatch in reset_throttle");
    die(json_encode(['success' => false, 'error' => 'Invalid CSRF token']));
}

$database = new Database();
$pdo = $database->getConnection();

if (!$pdo) {
    die(json_encode(['success' => false, 'error' => 'Database connection failed']));
}

$mac = $_POST['mac'] ?? '';

if (empty($mac)) {
    die(json_encode(['success' => false, 'error' => 'MAC address is required']));
}

try {
    // Reset the throttle status
    $stmt = $pdo->prepare("
        UPDATE user_history 
        SET is_throttled = FALSE,
            updated_at = NOW()
        WHERE mac_address = ?
    ");
    
    $stmt->execute([$mac]);
    
    // Log this action
    try {
        $logStmt = $pdo->prepare("
            INSERT INTO network_limit_logs 
            (mac_address, action, timestamp, performed_by)
            VALUES (?, 'UNTHROTTLE', NOW(), ?)
        ");
        $logStmt->execute([$mac, $_SESSION['user_id'] ?? 'system']);
    } catch (PDOException $e) {
        error_log("Note: Could not log throttle reset - ".$e->getMessage());
    }
    
    echo json_encode([
        'success' => true,
        'message' => 'Throttle reset successfully'
    ]);
    
} catch (PDOException $e) {
    error_log("Database error in reset_throttle: " . $e->getMessage());
    echo json_encode([
        'success' => false,
        'error' => 'Database error: ' . $e->getMessage()
    ]);
}
?>