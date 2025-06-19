<?php

class StartStopButtonController {
    private $processIdFiles = [
        'network_scan' => __DIR__ . '../../scripts/network_scan_pid.txt',
        'website_monitor' => __DIR__ . '../../scripts/website_monitor_pid.txt'
    ];

    public function startProcess($process) {
    $scriptPath = __DIR__ . '../../scripts/' . ($process === 'network_scan' ? 'NetworkScanner.py scan' : 'WebsiteMonitor.py');

    $status = $this->getStatus($process);
    if ($status['status'] === 'Running') {
        return ['status' => ucfirst($process) . ' already running'];
    }

    // Run script in the background
    $command = "nohup python3 $scriptPath > /tmp/{$process}_log.txt 2>&1 & echo $!";
    exec($command, $output, $return_var);

    if ($return_var === 0 && !empty($output[0])) {
        $pid = trim($output[0]);
        file_put_contents($this->processIdFiles[$process], $pid);
        return ['status' => ucfirst($process) . ' started', 'pid' => $pid];
    }

    return ['status' => 'Failed to start ' . $process];
}

    public function stopProcess($process) {
        $pidFile = $this->processIdFiles[$process];
        if (!file_exists($pidFile)) {
            return ['status' => ucfirst($process) . ' not running'];
        }

        $pid = trim(file_get_contents($pidFile));
        if (!is_numeric($pid)) {
            unlink($pidFile);
            return ['status' => ucfirst($process) . ' not running'];
        }
        
        if (function_exists('posix_kill')) {
            posix_kill($pid, 9);
        } else {
            exec("kill $pid 2>/dev/null || taskkill /F /PID $pid");
        }
        
        unlink($pidFile);
        return ['status' => ucfirst($process) . ' stopped'];
    }

    public function getStatus($process) {
        $pidFile = $this->processIdFiles[$process];
        if (!file_exists($pidFile)) {
            return ['status' => 'Not running'];
        }

        $pid = trim(file_get_contents($pidFile));
        if (!is_numeric($pid)) {
            unlink($pidFile);
            return ['status' => 'Not running'];
        }

        if (function_exists('posix_getpgid')) {
            return posix_getpgid($pid) !== false ? ['status' => 'Running', 'pid' => $pid] : ['status' => 'Not running'];
        }

        exec("ps -p $pid || tasklist /FI \"PID eq $pid\"", $output, $return_var);
        if ($return_var === 0 && count($output) > 1) {
            return ['status' => 'Running', 'pid' => $pid];
        }
        
        unlink($pidFile);
        return ['status' => 'Not running'];
    }
}
