<?php

class NetworkScannerController {
    private $pidFile = __DIR__ . '../../scripts/network_scan_pid.txt';

    public function startProcess() {
        $scriptPath = escapeshellarg("/home/khan/myenv/bin/python /opt/lampp/htdocs/securitysite/scripts/NetworkScanner.py");

        // Check if already running
        $status = $this->getStatus();
        if ($status['status'] === 'Running') {
            return ['status' => 'Network Scan already running', 'pid' => $status['pid']];
        }

        // Start script in background
        $command = "sudo python3 $scriptPath > /tmp/network_scan_log.txt 2>&1 & echo $!";
        exec($command, $output, $return_var);

        if ($return_var === 0 && !empty($output[0])) {
            $pid = trim($output[0]);
            file_put_contents($this->pidFile, $pid);
            return ['status' => 'Network Scan started', 'pid' => $pid];
        }

        return ['status' => 'Failed to start Network Scan'];
    }

    public function stopProcess() {
        if (!file_exists($this->pidFile)) {
            return ['status' => 'Network Scan not running'];
        }

        $pid = trim(file_get_contents($this->pidFile));
        if (!is_numeric($pid) || !file_exists("/proc/$pid")) {
            unlink($this->pidFile);
            return ['status' => 'Network Scan not running'];
        }

        // Try to terminate the process gracefully
        exec("kill $pid", $output, $return_var);
        sleep(1);

        // Forcefully terminate if still running
        if (file_exists("/proc/$pid")) {
            exec("kill -9 $pid");
        }

        unlink($this->pidFile);
        return ['status' => 'Network Scan stopped'];
    }

    public function getStatus() {
        if (!file_exists($this->pidFile)) {
            return ['status' => 'Not running'];
        }

        $pid = trim(file_get_contents($this->pidFile));
        if (!is_numeric($pid) || !file_exists("/proc/$pid")) {
            unlink($this->pidFile);
            return ['status' => 'Not running'];
        }

        return ['status' => 'Running', 'pid' => $pid];
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json');
    $action = $_POST['action'] ?? null;

    if (!$action) {
        echo json_encode(["status" => "Invalid request"]);
        exit;
    }

    $controller = new NetworkScannerController();

    switch ($action) {
        case "start":
            $response = $controller->startProcess();
            break;
        case "stop":
            $response = $controller->stopProcess();
            break;
        case "status":
            $response = $controller->getStatus();
            break;
        default:
            $response = ["status" => "Invalid action"];
    }

    echo json_encode($response);
}
?>
