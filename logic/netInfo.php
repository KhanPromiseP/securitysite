<?php 
require_once 'ThreatModel.php';

$threatModel = new ThreatModel();
$data = json_decode(file_get_contents("php://input"), true);

if (isset($data['action'])) {
    switch ($data['action']) {
        case 'getBlockedVsActive':
            $threatModel->getBlockedVsActive();
            break;
        case 'getThreatPercentage':
            $threatModel->getThreatPercentage();
            break;
        case 'getAllNetworkThreats':
            $threatModel->getAllNetworkThreats();
            break;
        case 'getThreatTrendData':  
            $threatModel->getThreatTrendData();
            break;
        case 'blockIP':
            if (isset($data['ip_address'])) {
                $threatModel->blockIP($data['ip_address']);
            } else {
                http_response_code(400);
                echo json_encode(['error' => 'IP address is required.']);
            }
            break;
        case 'unblockIP':
            if (isset($data['ip_address'])) {
                $threatModel->unblockIP($data['ip_address']);
            } else {
                http_response_code(400);
                echo json_encode(['error' => 'IP address is required.']);
            }
            break;
        default:
            http_response_code(400);
            echo json_encode(['error' => 'Invalid action.']);
            break;
    }
} else {
    http_response_code(400);
    echo json_encode(['error' => 'No action specified.']);
}

