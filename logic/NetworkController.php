<?php
require_once 'ThreatModel.php';

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

class NetworkController
{
    private $threatModel;
    private $processIdFile = '/tmp/network_scanner_pid.txt'; // Ensure this directory is writable
    private $processNameFile = '/tmp/network_scanner_process_name.txt'; // Updated for consistency

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
        $scriptPath = escapeshellcmd("/opt/lampp/htdocs/securitysite/scripts/NetworkScanner.py scan");
        $os = $this->detectOS();

        if ($os === 'linux') {
            $output = shell_exec("nohup sudo python3 $scriptPath > /dev/null 2>&1 & echo $!");
            if ($output && is_numeric(trim($output))) {
                file_put_contents($this->processIdFile, trim($output));
                return ['status' => 'Network scanning started on Linux', 'pid' => trim($output)];
            } else {
                return ['status' => 'Failed to start network scanning on Linux. Check script path or permissions.'];
            }
        } elseif ($os === 'windows') {
            $output = shell_exec("powershell -Command \"Start-Process python -ArgumentList '$scriptPath' -WindowStyle Hidden -PassThru | Select-Object -ExpandProperty Id\"");
            if ($output && is_numeric(trim($output))) {
                file_put_contents($this->processNameFile, trim($output));
                return ['status' => 'Network scanning started on Windows', 'pid' => trim($output)];
            } else {
                return ['status' => 'Failed to start network scanning on Windows. Check script path or permissions.'];
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
                shell_exec("kill $pid 2>&1");
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
        try {
            $threats = $this->threatModel->getAllNetworkThreats();
            return ['status' => 'success', 'threats' => $threats];
        } catch (Exception $e) {
            return ['status' => 'Error fetching threats: ' . $e->getMessage()];
        }
    }

    public function blockIPAddress($ipAddress)
    {
        $os = $this->detectOS();
        $sanitizedIP = filter_var($ipAddress, FILTER_VALIDATE_IP);
        if (!$sanitizedIP) {
            return ['status' => 'Invalid IP address provided'];
        }

        try {
            if ($os === 'linux') {
                shell_exec("sudo iptables -A INPUT -s $sanitizedIP -j DROP");
                if ($this->threatModel->blockIP($sanitizedIP)) {
                    return ['status' => "IP $sanitizedIP blocked on Linux"];
                }
            } elseif ($os === 'windows') {
                shell_exec("netsh advfirewall firewall add rule name=\"Block IP $sanitizedIP\" dir=in interface=any action=block remoteip=$sanitizedIP");
                if ($this->threatModel->blockIP($sanitizedIP)) {
                    return ['status' => "IP $sanitizedIP blocked on Windows"];
                }
            } else {
                return ['status' => 'Unsupported OS'];
            }
        } catch (Exception $e) {
            return ['status' => 'Error: ' . $e->getMessage()];
        }
    }

    public function unblockIPAddress($ipAddress)
    {
        $os = $this->detectOS();
        $sanitizedIP = filter_var($ipAddress, FILTER_VALIDATE_IP);
        if (!$sanitizedIP) {
            return ['status' => 'Invalid IP address provided'];
        }

        try {
            if ($os === 'linux') {
                shell_exec("sudo iptables -D INPUT -s $sanitizedIP -j DROP");
                if ($this->threatModel->unblockIP($sanitizedIP)) {
                    return ['status' => "IP $sanitizedIP unblocked on Linux"];
                }
            } elseif ($os === 'windows') {
                shell_exec("netsh advfirewall firewall delete rule name=\"Block IP $sanitizedIP\"");
                if ($this->threatModel->unblockIP($sanitizedIP)) {
                    return ['status' => "IP $sanitizedIP unblocked on Windows"];
                }
            } else {
                return ['status' => 'Unsupported OS'];
            }
        } catch (Exception $e) {
            return ['status' => 'Error: ' . $e->getMessage()];
        }
    }
}

header('Content-Type: application/json');
$input = json_decode(file_get_contents('php://input'), true);

if ($input === null) {
    echo json_encode(['status' => 'Error: Invalid JSON input']);
    exit;
}

$controller = new NetworkController();
if (isset($input['action'])) {
    $action = $input['action'];
    $response = match ($action) {
        'startNetworkScanner' => $controller->startNetworkScanner(),
        'stopNetworkScanner' => $controller->stopNetworkScanner(),
        'fetchThreats' => $controller->fetchNetworkThreats(),
        'blockIPAddress' => isset($input['ipAddress']) ? $controller->blockIPAddress($input['ipAddress']) : ['status' => 'IP address missing'],
        'unblockIPAddress' => isset($input['ipAddress']) ? $controller->unblockIPAddress($input['ipAddress']) : ['status' => 'IP address missing'],
        default => ['status' => 'Unknown action'],
    };
    echo json_encode($response);
    exit;
} else {
    echo json_encode(['status' => 'No action specified']);
    exit;
}
