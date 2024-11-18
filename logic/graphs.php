<?php
require_once '../src/config/Database.php';
require_once 'ThreatModel.php';

$threatModel = new ThreatModel();
$type = $_GET['type'] ?? '';

header('Content-Type: application/json');

if ($type === 'network') {
    echo json_encode($threatModel->getAllNetworkThreats());
} elseif ($type === 'website') {
    echo json_encode($threatModel->getAllWebsiteThreats());
} else {
    echo json_encode(['status' => 'Error: Invalid type']);
}
?>
