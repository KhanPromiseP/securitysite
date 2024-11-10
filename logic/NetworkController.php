<?php
require_once 'ThreatModel.php';

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);


// Suppress error display to avoid JSON encoding issues
ini_set('display_errors', 0);
ini_set('display_startup_errors', 0);
error_reporting(0);

class NetworkController
{
    private $threatModel;
    private $processIdFile = '/tmp/network_scanner_pid.txt';
    private $processNameFile = 'network_scanner_process_name.txt';

    public function __construct()
    {
        $this->threatModel = new ThreatModel();
    }

    private function detectOS()
    {
        return stripos(PHP_OS, 'WIN') === 0 ? 'windows' : 'linux';
    }

    public function startNetworkScanner()
    {
        $scriptPath = "/opt/lampp/htdocs/securitysite/scripts/NetworkScanner.py scan";
        $os = $this->detectOS();

        if ($os === 'linux') {
            $output = shell_exec("nohup sudo python3 $scriptPath > /dev/null 2>&1 & echo $!");
            if ($output) {
                file_put_contents($this->processIdFile, trim($output));
                return ['status' => 'Network scanning started on Linux', 'pid' => trim($output)];
            } else {
                return ['status' => 'Failed to start network scanning on Linux'];
            }
        } elseif ($os === 'windows') {
            $output = shell_exec("powershell -Command \"Start-Process python -ArgumentList '$scriptPath' -WindowStyle Hidden -PassThru | Select-Object -ExpandProperty Id\"");
            if ($output) {
                file_put_contents($this->processNameFile, trim($output));
                return ['status' => 'Network scanning started on Windows', 'pid' => trim($output)];
            } else {
                return ['status' => 'Failed to start network scanning on Windows'];
            }
        } else {
            return ['status' => 'Unsupported OS'];
        }
    }

    public function stopNetworkScanner()
    {
        $os = $this->detectOS();

        if ($os === 'linux') {
            if (file_exists($this->processIdFile)) {
                $pid = trim(file_get_contents($this->processIdFile));
                shell_exec("kill $pid");
                unlink($this->processIdFile);
                return ['status' => 'Network scanning stopped on Linux'];
            }
            return ['status' => 'No running network scanning process found on Linux'];
        } elseif ($os === 'windows') {
            if (file_exists($this->processNameFile)) {
                $pid = trim(file_get_contents($this->processNameFile));
                shell_exec("powershell -Command \"Stop-Process -Id $pid -Force\"");
                unlink($this->processNameFile);
                return ['status' => 'Network scanning stopped on Windows'];
            }
            return ['status' => 'No running network scanning process found on Windows'];
        } else {
            return ['status' => 'Unsupported OS'];
        }
    }

    public function fetchNetworkThreats()
    {
        $threats = $this->threatModel->getAllNetworkThreats();
        return $threats;
    }

    public function blockIPAddress($ipAddress)
    {
        $os = $this->detectOS();
        try {
            if ($os === 'linux') {
                $output = shell_exec("sudo iptables -A INPUT -s $ipAddress -j DROP 2>&1");
                if ($output === null) {
                    throw new Exception("Failed to block IP on Linux.");
                }
                if ($this->threatModel->blockIP($ipAddress)) {
                    return ['status' => "IP $ipAddress blocked on Linux"];
                }
            } elseif ($os === 'windows') {
                $output = shell_exec("netsh advfirewall firewall add rule name=\"Block IP $ipAddress\" dir=in interface=any action=block remoteip=$ipAddress 2>&1");
                if ($output === null) {
                    throw new Exception("Failed to block IP on Windows.");
                }
                if ($this->threatModel->blockIP($ipAddress)) {
                    return ['status' => "IP $ipAddress blocked on Windows"];
                }
            } else {
                throw new Exception('Unsupported OS');
            }
        } catch (Exception $e) {
            return ['status' => 'Error: ' . $e->getMessage()];
        }
    }

    public function unblockIPAddress($ipAddress)
    {
        $os = $this->detectOS();

        try {
            if ($os === 'linux') {
                $output = shell_exec("sudo iptables -D INPUT -s $ipAddress -j DROP 2>&1");
                if ($output === null) throw new Exception("Failed to unblock IP on Linux.");
                if ($this->threatModel->unblockIP($ipAddress)) {
                    return ['status' => "IP $ipAddress unblocked on Linux"];
                }
            } elseif ($os === 'windows') {
                $output = shell_exec("netsh advfirewall firewall delete rule name=\"Block IP $ipAddress\" 2>&1");
                if ($output === null) throw new Exception("Failed to unblock IP on Windows.");
                if ($this->threatModel->unblockIP($ipAddress)) {
                    return ['status' => "IP $ipAddress unblocked on Windows"];
                }
            } else {
                throw new Exception('Unsupported OS');
            }
        } catch (Exception $e) {
            return ['status' => 'Error: ' . $e->getMessage()];
        }
    }
}

// Clear any previous output and start buffering
ob_start();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = json_decode(file_get_contents('php://input'), true);

    // Ensure input is valid
    if (json_last_error() !== JSON_ERROR_NONE) {
        echo json_encode(['status' => 'Error: Invalid JSON input']);
        exit;
    }

    // Log input for debugging purposes
    // var_dump($input); // Uncomment this line to check what you're receiving

    $networkController = new NetworkController();

    header('Content-Type: application/json'); // Ensure JSON response
    if (isset($input['action']) && !empty($input['action'])) {
        switch ($input['action']) {
            case 'startNetworkScanner':
                echo json_encode($networkController->startNetworkScanner());
                break;
            case 'stopNetworkScanner':
                echo json_encode($networkController->stopNetworkScanner());
                break;
            case 'fetchThreats':
                echo json_encode($networkController->fetchNetworkThreats());
                break;
            case 'blockIPAddress':
                if (isset($input['ipAddress'])) {
                    echo json_encode($networkController->blockIPAddress($input['ipAddress']));
                } else {
                    echo json_encode(['status' => 'Error: IP address not provided']);
                }
                break;
            case 'unblockIPAddress':
                if (isset($input['ipAddress'])) {
                    echo json_encode($networkController->unblockIPAddress($input['ipAddress']));
                } else {
                    echo json_encode(['status' => 'Error: IP address not provided']);
                }
                break;
            default:
                echo json_encode(['status' => 'Error: Invalid action']);
                break;
        }
    } else {
        echo json_encode(['status' => 'Error: No action specified']);
    }
}

// Send and clear buffer to ensure no additional output
ob_end_clean();
