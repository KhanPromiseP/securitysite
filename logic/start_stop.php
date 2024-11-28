<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

require_once 'StartStopButtonController.php';

header('Content-Type: application/json');
error_reporting(E_ALL);
ini_set('display_errors', 1);

$controller = new StartStopButtonController();
$action = $_GET['action'] ?? '';
$process = $_GET['process'] ?? '';

$response = ['status' => 'Invalid request'];

if ($action && $process) {
    switch ($action) {
        case 'start':
            $response = $controller->startProcess($process);
            break;
        case 'stop':
            $response = $controller->stopProcess($process);
            break;
        case 'status':
            $response = $controller->getStatus($process);
            break;
        default:
            $response = ['status' => 'Invalid action'];
    }
} else {
    $response = ['status' => 'Invalid parameters'];
}

echo json_encode($response);
exit;
?>
