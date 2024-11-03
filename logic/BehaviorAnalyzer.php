<?php
header('Content-Type: application/json');
include '../src/config/Database.php';

class SecurityMonitor {
    private $conn;

    public function __construct($dbConnection) {
        $this->conn = $dbConnection;
    }

    // Function to insert scanned host or anomaly into the database
    public function logSuspiciousBehavior($user_id, $ip_address, $behavior_details, $is_anomaly, $threat_level) {
        $query = "INSERT INTO suspicious_behavior (user_id, ip_address, behavior_details, detection_time, is_blocked, threat_level)
                  VALUES (:user_id, :ip_address, :behavior_details, NOW(), :is_blocked, :threat_level)";
        $stmt = $this->conn->prepare($query);
        
        // Bind parameters
        $stmt->bindParam(':user_id', $user_id);
        $stmt->bindParam(':ip_address', $ip_address);
        $stmt->bindParam(':behavior_details', $behavior_details);
        $stmt->bindValue(':is_blocked', $is_anomaly ? 1 : 0);  // Block if anomaly
        $stmt->bindParam(':threat_level', $threat_level);
        
        return $stmt->execute();
    }

    // Function to trigger Python script for scanning and anomaly detection
    public function triggerPythonScript() {
        $command = escapeshellcmd('C:\Users\EMILE\AppData\Local\Programs\Python\Python312\python.exe C:\Users\EMILE\Downloads\downloads\htdocs\securitysite\scripts\main_monitor.py 2>&1'); // Capture both output and errors
        $output = shell_exec($command);
        
        // Log output for debugging
        file_put_contents('../logs/python_output.log', $output . PHP_EOL, FILE_APPEND); // Append output to a log file
    
        return json_decode($output, true);  // Convert Python output from JSON to PHP array
    }
    
    // Function to process the output from Python and store it in the database
    public function processMonitoringData() {
        $scanResult = $this->triggerPythonScript();
        
        if (!empty($scanResult)) {
            $user_id = 1;  // Replace with real user ID logic, possibly fetched from the session
            
            // Log active users
            $active_user_count = $scanResult['active_users'];
            $this->logActiveUsers($active_user_count);

            // Log each detected host, anomalies, and their threat levels
            foreach ($scanResult['monitoring_data'] as $entry) {
                $ip_address = $entry['ip_address'];
                $behavior_details = $entry['behavior_details'];
                $is_anomaly = isset($entry['is_anomaly']) && $entry['is_anomaly'];
                $threat_level = isset($entry['threat_level']) ? $entry['threat_level'] : 'low';  // Use threat intelligence data

                // Log the activity into the suspicious_behavior table
                $this->logSuspiciousBehavior($user_id, $ip_address, $behavior_details, $is_anomaly, $threat_level);
            }

            return ['status' => 'success', 'message' => 'Monitoring data logged', 'active_users' => $active_user_count];
        }

        return ['status' => 'error', 'message' => 'No data to log'];
    }

    // Function to log the number of active users into a separate table
    public function logActiveUsers($active_user_count) {
        $query = "INSERT INTO active_users_log (timestamp, active_user_count) VALUES (NOW(), :active_user_count)";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(':active_user_count', $active_user_count);
        $stmt->execute();
    }

    // Function to query and retrieve stored suspicious behavior from the database
    public function getSuspiciousBehavior() {
        $query = "SELECT user_id, ip_address, behavior_details, detection_time, is_blocked, threat_level FROM suspicious_behavior ORDER BY detection_time DESC";
        $stmt = $this->conn->prepare($query);
        $stmt->execute();

        $data = $stmt->fetchAll(PDO::FETCH_ASSOC);
        return $data ? $data : [];
    }

    // Function to query and retrieve active users log from the database
    public function getActiveUsersLog() {
        $query = "SELECT timestamp, active_user_count FROM active_users_log ORDER BY timestamp DESC";
        $stmt = $this->conn->prepare($query);
        $stmt->execute();

        $data = $stmt->fetchAll(PDO::FETCH_ASSOC);
        return $data ? $data : [];
    }
}

// Initialize the Database connection
$database = new Database();
$db = $database->getConnection();
$monitor = new SecurityMonitor($db);
$monitor->processMonitoringData();

// Handle monitoring, logging, and querying upon request
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    if (isset($_GET['action'])) {
        switch ($_GET['action']) {
            case 'get_suspicious_behavior':
                echo json_encode($monitor->getSuspiciousBehavior());
                break;
            case 'get_active_users_log':
                echo json_encode($monitor->getActiveUsersLog());
                break;
            default:
                echo json_encode(['status' => 'error', 'message' => 'Invalid action']);
                break;
        }
    } else {
        echo json_encode(['status' => 'error', 'message' => 'No action specified']);
    }
} else {
    echo json_encode(['status' => 'error', 'message' => 'Invalid request']);
}