<?php

error_reporting(E_ALL);
ini_set('display_errors', 1);

// Include the ThreatModel class file
require_once 'ThreatModel.php';

class NetworkThreatController
{
    private $threatModel;
    private $processIdFile = '/path/to/process_id_file'; // Define your path
    private $processNameFile = '/path/to/process_name_file'; // Define your path

    public function __construct()
    {
        $this->threatModel = new ThreatModel();
    }

    public function processRequest()
    {
        // Decoding JSON input from the request body
        $input = json_decode(file_get_contents('php://input'), true);

        // Check if input JSON is valid
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
            case 'blockIPAddress':
                $this->blockIPAddress($input['ipAddress'] ?? '');
                break;
            case 'unblockIPAddress':
                $this->unblockIPAddress($input['ipAddress'] ?? '');
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

    private function blockIPAddress($ipAddress)
    {
        $sanitizedIP = filter_var($ipAddress, FILTER_VALIDATE_IP);
        if (!$sanitizedIP) {
            $this->sendResponse('Error', 'Invalid IP address');
            return;
        }

        $os = $this->detectOS();
        $output = $this->executeFirewallCommand($os, 'block', $sanitizedIP);

        if ($output['success']) {
            if ($this->threatModel->blockIP($sanitizedIP)) {
                $this->sendResponse('Success', "IP $sanitizedIP blocked successfully");
            } else {
                $this->rollbackFirewall('block', $sanitizedIP, $os);
                $this->sendResponse('Error', "Failed to update database for IP $sanitizedIP");
            }
        } else {
            $this->sendResponse('Error', $output['message']);
        }
    }

    private function unblockIPAddress($ipAddress)
    {
        $sanitizedIP = filter_var($ipAddress, FILTER_VALIDATE_IP);
        if (!$sanitizedIP) {
            $this->sendResponse('Error', 'Invalid IP address');
            return;
        }

        $os = $this->detectOS();
        $output = $this->executeFirewallCommand($os, 'unblock', $sanitizedIP);

        if ($output['success']) {
            if ($this->threatModel->unblockIP($sanitizedIP)) {
                $this->sendResponse('Success', "IP $sanitizedIP unblocked successfully");
            } else {
                $this->rollbackFirewall('unblock', $sanitizedIP, $os);
                $this->sendResponse('Error', "Failed to update database for IP $sanitizedIP");
            }
        } else {
            $this->sendResponse('Error', $output['message']);
        }
    }

    private function executeFirewallCommand($os, $action, $ipAddress)
    {
        $escapedIP = escapeshellarg($ipAddress);
        $command = '';

        if ($os === 'linux') {
            $command = $action === 'block'
                ? "sudo iptables -A INPUT -s $escapedIP -j DROP 2>&1"
                : "sudo -u www-data bash -c 'sudo /sbin/iptables -D INPUT -s $escapedIP -j DROP' 2>&1";
        } elseif ($os === 'windows') {
            $command = $action === 'block'
                ? "netsh advfirewall firewall add rule name=\"Block IP $escapedIP\" dir=in action=block remoteip=$escapedIP 2>&1"
                : "netsh advfirewall firewall delete rule name=\"Block IP $escapedIP\" 2>&1";
        } else {
            return ['success' => false, 'message' => 'Unsupported OS'];
        }

        $output = shell_exec($command);

        // Handle potential errors from the command execution
        if (strpos($output, 'Error') !== false || empty($output)) {
            return ['success' => false, 'message' => "Firewall command failed: $output"];
        }

        return ['success' => true, 'message' => 'Command executed successfully'];
    }

    private function rollbackFirewall($action, $ipAddress, $os)
    {
        $escapedIP = escapeshellarg($ipAddress);
        if ($os === 'linux') {
            shell_exec($action === 'block'
                ? "sudo iptables -D INPUT -s $escapedIP -j DROP 2>&1"
                : "sudo iptables -A INPUT -s $escapedIP -j DROP 2>&1");
        } elseif ($os === 'windows') {
            shell_exec($action === 'block'
                ? "netsh advfirewall firewall delete rule name=\"Block IP $escapedIP\" 2>&1"
                : "netsh advfirewall firewall add rule name=\"Block IP $escapedIP\" dir=in action=block remoteip=$escapedIP 2>&1");
        }
    }

    private function detectOS()
    {
        if (stripos(PHP_OS, 'Linux') !== false) {
            return 'linux';
        } elseif (stripos(PHP_OS, 'WIN') !== false) {
            return 'windows';
        }
        return 'unknown';
    }

    private function sendResponse($status, $message, $data = null)
    {
        $response = ['status' => $status, 'message' => $message];
        if ($data !== null) {
            $response['data'] = $data;
        }
        echo json_encode($response);
    }
}

// Create an instance of the controller and process the request
$controller = new NetworkThreatController();
$controller->processRequest();

