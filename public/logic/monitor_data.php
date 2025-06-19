<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *'); // IMPORTANT for frontend to access from different domains/ports. Restrict this in production!
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

// --- Configuration ---
// Path to the main security log file
$securityLogFile = '/var/log/syslog'; // Example for Linux, adjust as needed.
// You might have other specific application logs:
$webserverErrorLog = '/var/log/apache2/error.log'; // Example for Apache
$authLog = '/var/log/auth.log'; // Example for Linux authentication logs

// Thresholds for alerts (adjust these based on your system's normal behavior)
const CPU_HIGH_THRESHOLD = 80; // %
const MEMORY_HIGH_THRESHOLD = 90; // %
const DISK_HIGH_THRESHOLD = 90; // %
const IMPORTANT_LOGS_THRESHOLD = 10; // Number of "important" logs in the last interval

// --- Helper Functions ---

/**
 * Executes a shell command and returns its output.
 * Handles potential command execution errors.
 * @param string $command
 * @return array [output, exit_code]
 */
function executeShellCommand(string $command): array {
    $output = [];
    $exitCode = 0;
    exec($command . ' 2>&1', $output, $exitCode);
    return [$output, $exitCode];
}

/**
 * Parses and categorizes log lines.
 * @param array $lines
 * @return array
 */
function parseSecurityLogs(array $lines): array {
    $parsedLogs = [];
    $alertKeywords = [
        'critical' => ['critical', 'panic', 'denied', 'unauthorized'],
        'high'     => ['error', 'failed', 'inject', 'malicious', 'blocked'],
        'medium'   => ['warn', 'warning', 'suspicious'],
        'low'      => ['info', 'access', 'connected']
    ];

    foreach ($lines as $line) {
        $level = 'info'; // Default level
        $matchedKeyword = '';

        foreach ($alertKeywords as $severity => $keywords) {
            foreach ($keywords as $keyword) {
                if (stripos($line, $keyword) !== false) {
                    $level = $severity;
                    $matchedKeyword = $keyword;
                    break 2; // Break out of inner loops
                }
            }
        }

        // Attempt to extract timestamp and process info (highly dependent on log format)
        $timestamp = 'N/A';
        $process = 'N/A';
        if (preg_match('/^(\w+\s+\d+\s+\d{2}:\d{2}:\d{2})/', $line, $matches)) {
            $timestamp = date('Y-m-d H:i:s', strtotime($matches[1] . ' ' . date('Y'))); // Add current year
        }
        if (preg_match('/(\w+): /', $line, $matches, PREG_OFFSET_CAPTURE, strpos($line, $timestamp) + strlen($timestamp))) {
            $process = trim(str_replace(':', '', $matches[1][0]));
        }


        $parsedLogs[] = [
            'timestamp' => $timestamp,
            'level' => $level,
            'process' => $process,
            'message' => htmlspecialchars(trim($line)), // Sanitize for HTML display
            'keyword' => $matchedKeyword // For highlighting
        ];
    }
    return $parsedLogs;
}


// --- Collect System Data ---
$systemData = [
    'status' => 'success',
    'timestamp' => date('Y-m-d H:i:s'),
    'alerts' => [] // To store triggered alerts
];

// 1. CPU Usage
// Using sys_getloadavg() for load average.
// For real-time % CPU, you'd typically parse `top -bn1` or `mpstat`.
// For simplicity and common availability, sys_getloadavg is used here.
$load_avg = sys_getloadavg();
$systemData['cpu'] = [
    'load_1min' => round($load_avg[0], 2),
    'load_5min' => round($load_avg[1], 2),
    'load_15min' => round($load_avg[2], 2),
    'percentage_1min' => round($load_avg[0] * 100, 2) // Rough % for single core. Adjust for multi-core if needed.
];
if ($systemData['cpu']['percentage_1min'] >= CPU_HIGH_THRESHOLD) {
    $systemData['alerts'][] = ['type' => 'CPU_USAGE', 'level' => 'critical', 'message' => 'High CPU load detected!'];
}

// 2. Memory Usage
// PHP's memory_get_usage is for the script itself. To get system memory:
list($memInfoRaw, $exitCode) = executeShellCommand('free -m');
if ($exitCode === 0 && !empty($memInfoRaw[1])) {
    // Expected output format: Mem: total used free shared buff/cache available
    $memParts = preg_split('/\s+/', $memInfoRaw[1]);
    if (isset($memParts[1]) && isset($memParts[2]) && isset($memParts[3])) {
        $totalMemMB = (int)$memParts[1];
        $usedMemMB = (int)$memParts[2];
        $freeMemMB = (int)$memParts[3];
        $memory_percentage = round(($usedMemMB / $totalMemMB) * 100, 2);

        $systemData['memory'] = [
            'total_mb' => $totalMemMB,
            'used_mb' => $usedMemMB,
            'free_mb' => $freeMemMB,
            'percentage' => $memory_percentage
        ];
        if ($memory_percentage >= MEMORY_HIGH_THRESHOLD) {
            $systemData['alerts'][] = ['type' => 'MEMORY_USAGE', 'level' => 'critical', 'message' => 'High memory usage detected!'];
        }
    }
} else {
    $systemData['memory'] = ['status' => 'error', 'message' => 'Could not get system memory info.'];
}


// 3. Disk Usage
// For the root partition. Adjust path if your application or logs are on a different partition.
$diskPath = '/';
$totalDiskSpace = @disk_total_space($diskPath);
$freeDiskSpace = @disk_free_space($diskPath);

if ($totalDiskSpace !== false && $freeDiskSpace !== false) {
    $usedDiskSpace = $totalDiskSpace - $freeDiskSpace;
    $disk_percentage = round(($usedDiskSpace / $totalDiskSpace) * 100, 2);

    $systemData['disk'] = [
        'path' => $diskPath,
        'total_gb' => round($totalDiskSpace / (1024 * 1024 * 1024), 2),
        'used_gb' => round($usedDiskSpace / (1024 * 1024 * 1024), 2),
        'free_gb' => round($freeDiskSpace / (1024 * 1024 * 1024), 2),
        'percentage' => $disk_percentage
    ];
    if ($disk_percentage >= DISK_HIGH_THRESHOLD) {
        $systemData['alerts'][] = ['type' => 'DISK_USAGE', 'level' => 'critical', 'message' => 'High disk space usage detected!'];
    }
} else {
    $systemData['disk'] = ['status' => 'error', 'message' => 'Could not get disk space info. Check path/permissions.'];
}


// 4. Uptime
list($uptimeRaw, $exitCode) = executeShellCommand('uptime -p');
if ($exitCode === 0 && !empty($uptimeRaw[0])) {
    $systemData['uptime'] = trim($uptimeRaw[0]);
} else {
    $systemData['uptime'] = 'N/A';
}

// 5. Top Processes by CPU/Memory (Linux specific)
list($topProcessesRaw, $exitCode) = executeShellCommand('ps aux --sort=-%cpu | head -n 6'); // Top 5 + header
if ($exitCode === 0 && count($topProcessesRaw) > 1) {
    $processes = [];
    $header = preg_split('/\s+/', trim($topProcessesRaw[0])); // Split header line
    for ($i = 1; $i < count($topProcessesRaw); $i++) {
        $parts = preg_split('/\s+/', trim($topProcessesRaw[$i]), -1, PREG_SPLIT_NO_EMPTY);
        // This parsing is fragile and depends on 'ps aux' output format.
        // You might need to adjust indices based on your system's 'ps' output.
        // Common indices: USER, PID, %CPU, %MEM, VSZ, RSS, TTY, STAT, START, TIME, COMMAND
        if (count($parts) >= 11) { // Ensure enough parts
            $processes[] = [
                'user' => $parts[0],
                'pid' => $parts[1],
                'cpu_percent' => floatval($parts[2]),
                'mem_percent' => floatval($parts[3]),
                'command' => implode(' ', array_slice($parts, 10)) // Command can have spaces
            ];
        }
    }
    $systemData['top_processes'] = $processes;
} else {
    $systemData['top_processes'] = ['status' => 'error', 'message' => 'Could not get top processes. Check permissions or if `ps` is available.'];
}

// 6. Network Connections (Basic - using `ss` or `netstat`)
list($netstatRaw, $exitCode) = executeShellCommand('ss -tunap | head -n 11'); // Top 10 TCP/UDP + header with process names
if ($exitCode === 0 && count($netstatRaw) > 1) {
    $network_connections = [];
    for ($i = 1; $i < count($netstatRaw); $i++) {
        $parts = preg_split('/\s+/', trim($netstatRaw[$i]));
        if (count($parts) >= 6) { // Minimum expected parts for common output
             $pid_program = 'N/A';
             if (isset($parts[6]) && preg_match('/pid=(\d+),comm=(.+)/', $parts[6], $matches)) {
                 $pid_program = "PID: {$matches[1]}, CMD: {$matches[2]}";
             } else if (isset($parts[7]) && preg_match('/pid=(\d+),comm=(.+)/', $parts[7], $matches)) { // Sometimes different index
                 $pid_program = "PID: {$matches[1]}, CMD: {$matches[2]}";
             }

            $network_connections[] = [
                'state' => $parts[0],
                'recv_q' => $parts[1],
                'send_q' => $parts[2],
                'local_address' => $parts[3],
                'peer_address' => $parts[4],
                'program' => $pid_program
            ];
        }
    }
    $systemData['network_connections'] = $network_connections;
} else {
    $systemData['network_connections'] = ['status' => 'error', 'message' => 'Could not get network connections. Check permissions or if `ss` is available.'];
}


// --- Log Analysis and Alert Indicators ---

// Combine relevant log files
$allLogLines = [];
if (file_exists($securityLogFile)) {
    $allLogLines = array_merge($allLogLines, file($securityLogFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES));
}
if (file_exists($webserverErrorLog)) {
    $allLogLines = array_merge($allLogLines, file($webserverErrorLog, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES));
}
if (file_exists($authLog)) {
    $allLogLines = array_merge($allLogLines, file($authLog, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES));
}

$parsedImportantLogs = parseSecurityLogs(array_slice(array_values($allLogLines), -500)); // Get latest 500 lines for analysis
$systemData['security_logs'] = array_slice($parsedImportantLogs, -50); // Display latest 50 important logs

// Count high-severity logs
$highSeverityLogCount = count(array_filter($parsedImportantLogs, function($log) {
    return in_array($log['level'], ['critical', 'high']);
}));

if ($highSeverityLogCount >= IMPORTANT_LOGS_THRESHOLD) {
    $systemData['alerts'][] = [
        'type' => 'LOG_ACTIVITY',
        'level' => 'critical',
        'message' => "High number of critical/high severity logs detected: {$highSeverityLogCount} in recent activity!"
    ];
}

// Global System Status
$systemData['system_health'] = 'GOOD';
if (!empty($systemData['alerts'])) {
    foreach ($systemData['alerts'] as $alert) {
        if ($alert['level'] === 'critical') {
            $systemData['system_health'] = 'CRITICAL';
            break;
        } elseif ($alert['level'] === 'high' && $systemData['system_health'] === 'GOOD') {
            $systemData['system_health'] = 'WARNING';
        }
    }
}


// --- Output JSON ---
echo json_encode($systemData, JSON_PRETTY_PRINT); // Use JSON_PRETTY_PRINT for readability during development
?>