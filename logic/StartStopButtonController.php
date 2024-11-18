<?php 

class StartStopButtonController {
    private $processIdFiles = [
        'network_scan' => __DIR__ . '/../scripts/network_scan_pid.txt',
        'website_monitor' => __DIR__ . '/../scripts/website_monitor_pid.txt'
    ];

    private function detectOS() {
        return PHP_OS_FAMILY === 'Windows' ? 'windows' : 'linux';
    }

    public function startProcess($process) {
        $scriptPath = __DIR__ . '/../scripts/' . ($process === 'network_scan' ? 'NetworkScanner.py' : 'WebsiteMonitor.py');
        $os = $this->detectOS();
        $output = [];
        $return_var = 0;

        $status = $this->getStatus($process);
        if ($status['status'] === 'Running') {
            return ['status' => ucfirst($process) . ' already running'];
        }

        if ($os === 'linux') {
            exec("nohup python3 $scriptPath > /dev/null 2>&1 & echo $!", $output, $return_var);
            if ($return_var === 0 && !empty($output[0])) {
                file_put_contents($this->processIdFiles[$process], trim($output[0]));
                return ['status' => ucfirst($process) . ' started on Linux', 'pid' => trim($output[0])];
            }
        } elseif ($os === 'windows') {
            exec("start /B python $scriptPath", $output, $return_var);
            if ($return_var === 0) {
                exec("powershell -Command \"Get-Process python | Where-Object { $_.Path -like '*$scriptPath*' } | Select-Object -ExpandProperty Id\"", $output);
                if (!empty($output[0])) {
                    file_put_contents($this->processIdFiles[$process], trim($output[0]));
                    return ['status' => ucfirst($process) . ' started on Windows', 'pid' => trim($output[0])];
                }
            }
        }

        return ['status' => 'Failed to start ' . $process];
    }

    public function stopProcess($process) {
        $pidFile = $this->processIdFiles[$process];
        if (!file_exists($pidFile)) {
            return ['status' => ucfirst($process) . ' not running'];
        }

        $pid = trim(file_get_contents($pidFile));
        $os = $this->detectOS();
        $output = [];
        $return_var = 0;

        if ($os === 'linux') {
            exec("kill $pid", $output, $return_var);
        } elseif ($os === 'windows') {
            exec("powershell -Command \"Stop-Process -Id $pid -Force\"", $output, $return_var);
        }

        if ($return_var === 0 && unlink($pidFile)) {
            return ['status' => ucfirst($process) . ' stopped'];
        }

        return ['status' => 'Failed to stop ' . $process];
    }

    public function getStatus($process) {
        $pidFile = $this->processIdFiles[$process];
        if (!file_exists($pidFile)) {
            return ['status' => 'Not running'];
        }

        $pid = trim(file_get_contents($pidFile));
        $os = $this->detectOS();
        $output = [];
        $return_var = 0;

        if ($os === 'linux') {
            exec("ps -p $pid", $output, $return_var);
        } elseif ($os === 'windows') {
            exec("tasklist /FI \"PID eq $pid\"", $output, $return_var);
        }

        if ($return_var === 0 && !empty($output)) {
            return ['status' => 'Running', 'pid' => $pid];
        }

        return ['status' => 'Not running'];
    }
}
