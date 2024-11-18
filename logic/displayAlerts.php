<?php

// include '../src/config/Database.php';
// class AlertDisplay
// {
//     private $conn;

  
//     public function __construct($dbConnection)
//     {
//         $this->conn = $dbConnection;
//     }
//     public function getAllAlerts()
//     {
        
//         $queries = [
//             'suspicious_behavior' => "SELECT 'suspicious_behavior' AS alert_type, id, user_id, ip_address, behavior_details, detection_time, is_blocked FROM suspicious_behavior",
//             'suspicious_files' => "SELECT 'suspicious_files' AS alert_type, id, file_name, file_size, upload_time, file_path FROM suspicious_files",
//             'detected_vulnerabilities' => "SELECT 'detected_vulnerabilities' AS alert_type, id, vulnerability_type, details, detection_time FROM detected_vulnerabilities",
//             'suspicious_traffic' => "SELECT 'suspicious_traffic' AS alert_type, id, src_ip, dest_ip, packet_size, protocol FROM suspicious_traffic",
//             'suspicious_emails' => "SELECT 'suspicious_emails' AS alert_type, id, sender, recipient, subject, body, timestamp FROM suspicious_emails"
//         ];

//         $allAlerts = []; 
//         foreach ($queries as $table => $query) {
//             $stmt = $this->conn->prepare($query);
//             $stmt->execute();
//             $alerts = $stmt->fetchAll(PDO::FETCH_ASSOC); 

//             if (!empty($alerts)) { 
//                 $allAlerts = array_merge($allAlerts, $alerts);
//             }
//         }

//         return $allAlerts; 
//     }
// }

// $database = new Database();
// $dbConnection = $database->getConnection();

// if (!$dbConnection) {
//     die(json_encode(['error' => 'Failed to connect to the database']));
// }

// $alertDisplay = new AlertDisplay($dbConnection);

// $allAlerts = $alertDisplay->getAllAlerts();

// header('Content-Type: application/json');
// if (empty($allAlerts)) {
//     echo json_encode(['alerts' => []]); 
// } else {
//     echo json_encode(['alerts' => $allAlerts]);
// }