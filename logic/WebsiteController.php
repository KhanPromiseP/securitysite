<?php

require_once 'ThreatModel.php';

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

class WebsiteController
{
    private $threatModel;
    private $processIdFile = '/tmp/website_monitor_pid.txt'; 
    private $processNameFile = 'network_scanner_process_name.txt'; 

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
        $scriptPath = "/opt/lampp/htdocs/securitysite/scripts/WebsiteMonitor.py";
        $os = $this->detectOS();

        if ($os === 'linux') {
            $output = shell_exec("nohup /usr/bin/python3 $scriptPath > /dev/null 2>&1 & echo $!");
            if ($output) {
                file_put_contents($this->processIdFile, $output);
                return json_encode(['status' => 'Website monitoring started on Linux', 'pid' => trim($output)]);
            }
            return json_encode(['status' => 'Failed to start Website monitoring on Linux']);
        } elseif ($os === 'windows') {
            $output = shell_exec("powershell -Command \"Start-Process python -ArgumentList '$scriptPath' -WindowStyle Hidden -PassThru | Select-Object -ExpandProperty Id\"");
            if ($output) {
                file_put_contents($this->processNameFile, $output);
                return json_encode(['status' => 'Website monitoring started on Windows', 'pid' => trim($output)]);
            }
            return json_encode(['status' => 'Failed to start Website monitoring on Windows']);
        } else {
            return json_encode(['status' => 'Unsupported OS']);
        }
    }

    public function stopWebsiteMonitor()
    {
        $os = $this->detectOS();

        if ($os === 'linux') {
            if (file_exists($this->processIdFile)) {
                $pid = trim(file_get_contents($this->processIdFile));
                shell_exec("kill $pid"); 
                unlink($this->processIdFile); 
                return json_encode(['status' => 'Website monitoring stopped on Linux']);
            }
            return json_encode(['status' => 'No running Website monitoring process found on Linux']);
        } elseif ($os === 'windows') {
            if (file_exists($this->processNameFile)) {
                $pid = trim(file_get_contents($this->processNameFile));
                shell_exec("powershell -Command \"Stop-Process -Id $pid -Force\"");
                unlink($this->processNameFile); 
                return json_encode(['status' => 'Website monitoring stopped on Windows']);
            }
            return json_encode(['status' => 'No running Website monitoring process found on Windows']);
        } else {
            return json_encode(['status' => 'Unsupported OS']);
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
                $output = shell_exec("netsh advfirewall firewall add rule name=\"Block IP $ipAddress\" dir=in interface=any action=block remoteip=$ipAddress 2>&1");
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


if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = json_decode(file_get_contents('php://input'), true);
    $websiteController = new WebsiteController();
    $threatModel->getAllWebsiteThreats();
    if (isset($input['action'])) {
        switch ($input['action']) {
            case 'startWebsiteMonitor':
                echo $websiteController->startWebsiteMonitor();
                break;
            case 'stopWebsiteMonitor':
                echo $websiteController->stopWebsiteMonitor();
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
