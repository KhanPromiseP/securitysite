<?php

error_reporting(E_ALL);
ini_set('display_errors', 1);

require_once 'ThreatModel.php';

class NetworkThreatController
{
    private $threatModel;

    public function __construct()
    {
        $this->threatModel = new ThreatModel();
    }

    public function processRequest()
    {
        $input = json_decode(file_get_contents('php://input'), true);

        if ($input === null) {
            $this->sendResponse('Error', 'Invalid JSON received');
            return;
        }

        if (!isset($input['action']) || !is_string($input['action'])) {
            $this->sendResponse('Error', 'Invalid or missing action');
            return;
        }

        switch ($input['action']) {
            case 'getNetworkThreats':
                $this->getNetworkThreats();
                break;
            case 'toggleBlockStatus':
                $this->toggleBlockStatus($input['ipAddress'] ?? '');
                break;
            case 'deleteIPAddress':
                $this->deleteIPAddress($input['ipAddress'] ?? '');
                break;
            case 'getThreatDetails':
                $this->getThreatDetails($input['ipAddress'] ?? '');
                break;
            default:
                $this->sendResponse('Error', 'Invalid action');
        }
    }

    private function getNetworkThreats()
    {
        $threats = $this->threatModel->getAllNetworkThreats();
        $this->sendResponse('Success', 'Network threats retrieved successfully', $threats);
    }

    private function getThreatDetails($ipAddress)
    {
        $sanitizedIP = filter_var($ipAddress, FILTER_VALIDATE_IP);
        if (!$sanitizedIP) {
            $this->sendResponse('Error', 'Invalid IP address');
            return;
        }

        $details = $this->threatModel->getThreatByIP($sanitizedIP);
        if ($details) {
            $this->sendResponse('Success', 'Threat details retrieved successfully', $details);
        } else {
            $this->sendResponse('Error', 'No threat details found for this IP');
        }
    }

    private function toggleBlockStatus($ipAddress)
    {
        $sanitizedIP = filter_var($ipAddress, FILTER_VALIDATE_IP);
        if (!$sanitizedIP) {
            $this->sendResponse('Error', 'Invalid IP address');
            return;
        }

        $currentStatus = $this->threatModel->getBlockStatus($sanitizedIP);
        if ($currentStatus === null) {
            $this->sendResponse('Error', 'IP address not found');
            return;
        }

        $newStatus = $currentStatus ? 0 : 1;
        $success = $this->threatModel->setBlockStatus($sanitizedIP, $newStatus);


        if ($success) {
            $statusText = $newStatus ? 'blocked' : 'unblocked';
            $this->sendResponse('Success', "IP $sanitizedIP successfully $statusText");
        } else {
            $this->sendResponse('Error', 'Failed to update block status in database');
        }
    }

    private function deleteIPAddress($ipAddress)
    {
        $sanitizedIP = filter_var($ipAddress, FILTER_VALIDATE_IP);
        if (!$sanitizedIP) {
            $this->sendResponse('Error', 'Invalid IP address');
            return;
        }

        $success = $this->threatModel->deleteIP($sanitizedIP);
        if ($success) {
            $this->sendResponse('Success', "IP $sanitizedIP deleted successfully");
        } else {
            $this->sendResponse('Error', "Failed to delete IP $sanitizedIP");
        }
    }

    private function sendResponse($status, $message, $data = null)
    {
        header('Content-Type: application/json');
        $response = ['status' => $status, 'message' => $message];
        if ($data !== null) {
            $response['data'] = $data;
        }
        echo json_encode($response);
    }
}

$controller = new NetworkThreatController();
$controller->processRequest();
