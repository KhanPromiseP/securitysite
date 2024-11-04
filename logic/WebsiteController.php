<?php

require_once 'ThreatModel.php';

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

class WebsiteController
{
    private $threatModel;
    public function __construct()
    {
        $this->threatModel = new ThreatModel();
    }

    private function detectOS()
    {
        return stripos(PHP_OS, 'WIN') === 0 ? 'windows' : 'linux';
    }

    public function startWebsiteMonitor()
    {
        $os = $this->detectOS();
        $websiteMonitorPath = escapeshellarg("C:\\Users\\EMILE\\Downloads\\downloads\\htdocs\\securitysite\\logic\\WebsiteMonitor.py");
        $pythonPath = escapeshellarg("C:\\Users\\EMILE\\AppData\\Local\\Programs\\Python\\Python312\\python.exe");

        try {
            if ($os === 'linux') {
                $output = shell_exec("crontab -l | { cat; echo \"*/5 * * * * python3 $websiteMonitorPath > /dev/null 2>&1\"; } |
    crontab
    - 2>&1");
                if ($output === null)
                    throw new Exception("Failed to schedule cron jobs for Linux.");
                return json_encode(['status' => 'Website monitoring started on Linux.']);
            } elseif ($os === 'windows') {
                $output = shell_exec("schtasks /create /tn \"WebsiteMonitor\" /tr \"$pythonPath $websiteMonitorPath\" /sc minute /mo
    5
    /f 2>&1");
                if ($output === null)
                    throw new Exception("Failed to schedule tasks for Windows.");
                return json_encode(['status' => 'Website monitoring started on Windows']);
            } else {
                throw new Exception('Unsupported OS specified.');
            }
        } catch (Exception $e) {
            error_log("System Start Error: " . $e->getMessage());
            return json_encode(['status' => 'Error: ' . $e->getMessage()]);
        }
    }

    public function fetchWebsiteThreats()
    {
        return json_encode($this->threatModel->getAllWebsiteThreats());
    }

    public function blockIPAddress($ipAddress)
    {
        $os = $this->detectOS();

        try {
            if ($os === 'linux') {
                $output = shell_exec("sudo iptables -A INPUT -s $ipAddress -j DROP 2>&1");
                if ($output === null)
                    throw new Exception("Failed to block IP on Linux.");
                if ($this->threatModel->blockIP($ipAddress)) {
                    return json_encode(['status' => "IP $ipAddress blocked on Linux"]);
                }
            } elseif ($os === 'windows') {
                $output = shell_exec("netsh advfirewall firewall add rule name=\"Block IP $ipAddress\" dir=in interface=any
    action=block
    remoteip=$ipAddress 2>&1");
                if ($output === null)
                    throw new Exception("Failed to block IP on Windows.");
                if ($this->threatModel->blockIP($ipAddress)) {
                    return json_encode(['status' => "IP $ipAddress blocked on Windows"]);
                }
            } else {
                throw new Exception('Unsupported OS specified.');
            }
        } catch (Exception $e) {
            error_log("Block IP Error: " . $e->getMessage());
            return json_encode(['status' => 'Error: ' . $e->getMessage()]);
        }
    }

    public function unblockIPAddress($ipAddress)
    {
        $os = $this->detectOS();

        try {
            if ($os === 'linux') {
                $output = shell_exec("sudo iptables -D INPUT -s $ipAddress -j DROP 2>&1");
                if ($output === null)
                    throw new Exception("Failed to unblock IP on Linux.");
                if ($this->threatModel->unblockIP($ipAddress)) {
                    return json_encode(['status' => "IP $ipAddress unblocked on Linux"]);
                }
            } elseif ($os === 'windows') {
                $output = shell_exec("netsh advfirewall firewall delete rule name=\"Block IP $ipAddress\" 2>&1");
                if ($output === null)
                    throw new Exception("Failed to unblock IP on Windows.");
                if ($this->threatModel->unblockIP($ipAddress)) {
                    return json_encode(['status' => "IP $ipAddress unblocked on Windows"]);
                }
            } else {
                throw new Exception('Unsupported OS specified.');
            }
        } catch (Exception $e) {
            error_log("Unblock IP Error: " . $e->getMessage());
            return json_encode(['status' => 'Error: ' . $e->getMessage()]);
        }
    }
}

// Handle AJAX request
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = json_decode(file_get_contents('php://input'), true);
    $websiteController = new WebsiteController();

    if (isset($input['action'])) {
        switch ($input['action']) {
            case 'startWebsiteMonitor':
                echo $websiteController->startWebsiteMonitor();
                break;
            case 'fetchThreats':
                echo $websiteController->fetchWebsiteThreats();
                break;
            case 'blockIPAddress':
                if (isset($input['ipAddress'])) {
                    echo $websiteController->blockIPAddress($input['ipAddress']);
                } else {
                    echo json_encode(['status' => 'Error: IP address not provided']);
                }
                break;
            case 'unblockIPAddress':
                if (isset($input['ipAddress'])) {
                    echo $websiteController->unblockIPAddress($input['ipAddress']);
                } else {
                    echo json_encode(['status' => 'Error: IP address not provided']);
                }
                break;
            default:
                echo json_encode(['status' => 'Error: Invalid action']);
        }
    } else {
        echo json_encode(['status' => 'Error: Action not specified']);
    }
} else {
    echo json_encode(['status' => 'Error: Invalid request method']);
}