<?php
require_once 'ThreatModel.php';

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

class AdminController {
    private $threatModel;

    public function __construct() {
        $this->threatModel = new ThreatModel();
    }

    public function startSystem($os) {
        // Paths are securely escaped
        $networkScannerPath = escapeshellarg("C:\\Users\\EMILE\\Downloads\\downloads\\htdocs\\sys\\NetworkScanner.py");
        $websiteMonitorPath = escapeshellarg("C:\\Users\\EMILE\\Downloads\\downloads\\htdocs\\sys\\WebsiteMonitor.py");
        $pythonPath = escapeshellarg("C:\\Users\\EMILE\\AppData\\Local\\Programs\\Python\\Python312\\python.exe");

        try {
            if ($os === 'linux') {
                $output1 = shell_exec("crontab -l | { cat; echo \"*/5 * * * * python3 $networkScannerPath > /dev/null 2>&1\"; } | crontab - 2>&1");
                $output2 = shell_exec("crontab -l | { cat; echo \"*/5 * * * * python3 $websiteMonitorPath > /dev/null 2>&1\"; } | crontab - 2>&1");

                if ($output1 === null || $output2 === null) {
                    throw new Exception("Failed to schedule cron jobs for Linux.");
                }
                return json_encode(['status' => 'System started with cron job scheduling for Linux.']);
            } elseif ($os === 'windows') {
                $output1 = shell_exec("schtasks /create /tn \"NetworkScan\" /tr \"$pythonPath $networkScannerPath\" /sc minute /mo 5 /f 2>&1");
                $output2 = shell_exec("schtasks /create /tn \"WebsiteMonitor\" /tr \"$pythonPath $websiteMonitorPath\" /sc minute /mo 5 /f 2>&1");

                if ($output1 === null || $output2 === null) {
                    throw new Exception("Failed to schedule tasks for Windows.");
                }
                return json_encode(['status' => 'System started with Task Scheduler for Windows.']);
            } else {
                throw new Exception('Unsupported OS specified.');
            }
        } catch (Exception $e) {
            error_log("System Start Error: " . $e->getMessage());
            return json_encode(['status' => 'Error: ' . $e->getMessage()]);
        }
    }

    public function toggleBlockIP($ip, $os) {
        $ip = escapeshellarg($ip);

        try {
            if ($os === 'linux') {
                $blockExists = shell_exec("iptables -L INPUT -v -n | grep '$ip'");
                $command = $blockExists ? "iptables -D INPUT -s $ip -j DROP" : "iptables -A INPUT -s $ip -j DROP";
                $result = shell_exec($command);
                $status = $blockExists ? "Unblocked" : "Blocked";
            } elseif ($os === 'windows') {
                $ruleExists = shell_exec("netsh advfirewall firewall show rule name=\"Block $ip\" 2>&1 | findstr /I \"$ip\"");
                $command = $ruleExists ? "netsh advfirewall firewall delete rule name=\"Block $ip\"" : "netsh advfirewall firewall add rule name=\"Block $ip\" dir=in action=block remoteip=$ip";
                $status = $ruleExists ? "Unblocked" : "Blocked";
                $result = shell_exec($command);
            } else {
                throw new Exception('Unsupported OS specified.');
            }
        }
    }

    
    public function fetchThreats() {
        return json_encode($this->threatModel->getAllThreats());
    }
}

// Process the incoming request
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = json_decode(file_get_contents('php://input'), true);

    if (isset($input['action'])) {
        $adminController = new AdminController();

        switch ($input['action']) {
            case 'startSystem':
                if (isset($input['os'])) {
                    echo $adminController->startSystem($input['os']);
                } else {
                    echo json_encode(['status' => 'Error: OS not specified']);
                }
                break;

            case 'toggleBlockIP':
                if (isset($input['ip']) && isset($input['os'])) {
                    echo $adminController->toggleBlockIP($input['ip'], $input['os']);
                } else {
                    echo json_encode(['status' => 'Error: IP or OS not specified']);
                }
                break;

            case 'fetchThreats':
                echo $adminController->fetchThreats();
                break;

            default:
                echo json_encode(['status' => 'Error: Invalid action']);
                break;
        }
    } else {
        echo json_encode(['status' => 'Error: Action not specified']);
    }
} else {
    echo json_encode(['status' => 'Error: Invalid request method']);
}