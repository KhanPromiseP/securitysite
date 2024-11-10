<?php
require_once '../src/config/Database.php';

class ThreatModel {
    private $conn;

    public function __construct() {
        $db = new Database();
        $this->conn = $db->getConnection();
    }

    public function getBlockedVsActive() {
        $query = "SELECT 
                     SUM(is_blocked = 1) AS blocked, 
                     SUM(is_blocked = 0) AS active 
                  FROM network_logs";
        $stmt = $this->conn->prepare($query);
        $stmt->execute();
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        echo json_encode($result);
    }

    public function getThreatPercentage() {
        try {
            $query = "SELECT 
                        threat_type, 
                        COUNT(*) AS count 
                      FROM network_logs 
                      GROUP BY threat_type";
            $stmt = $this->conn->prepare($query);
            $stmt->execute();
            $data = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
            $totalThreats = array_sum(array_column($data, 'count'));
            $result = array_map(function($row) use ($totalThreats) {
                return [
                    'threat_type' => $row['threat_type'],
                    'percentage' => ($row['count'] / $totalThreats) * 100 
                ];
            }, $data);
    
            echo json_encode($result);
        } catch (Exception $e) {
            echo json_encode(['error' => $e->getMessage()]);
            http_response_code(500);
        }
    }

    public function getAllNetworkThreats() {
        try {
            $query = "SELECT * FROM network_logs ORDER BY detected_at DESC";
            $stmt = $this->conn->prepare($query);
            $stmt->execute();
            $data = $stmt->fetchAll(PDO::FETCH_ASSOC);
            echo json_encode($data);
        } catch (Exception $e) {
            echo json_encode(['error' => $e->getMessage()]);
            http_response_code(500);
        }
    }

    public function getThreatTrendData() {
        try {
            $query = "SELECT 
                        DATE_FORMAT(detected_at, '%Y-%m-%d %H:%i:%s') AS detected_at,
                        COUNT(*) AS threat_count 
                      FROM network_logs 
                      GROUP BY detected_at 
                      ORDER BY detected_at DESC";
            $stmt = $this->conn->prepare($query);
            $stmt->execute();
            $data = $stmt->fetchAll(PDO::FETCH_ASSOC);

            echo json_encode($data);
        } catch (Exception $e) {
            echo json_encode(['error' => $e->getMessage()]);
            http_response_code(500);
        }
    }

    public function blockIP($ipAddress) {
        try {
            $query = "UPDATE network_logs SET is_blocked = 1 WHERE ip_address = :ip_address";
            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(':ip_address', $ipAddress);

            if ($stmt->execute()) {
                $file = '../logs/ip_block.log';
                $logEntry = sprintf("IP: %s blocked at %s\n", $ipAddress, date('Y-m-d H:i:s'));
                file_put_contents($file, $logEntry, FILE_APPEND);

                echo json_encode(['success' => true, 'message' => "IP blocked successfully."]);
                exit;
            } else {
                echo json_encode(['success' => false, 'message' => "Failed to block IP."]);
                http_response_code(400);
            }
            
        } catch (Exception $e) {
            echo json_encode(['error' => $e->getMessage()]);
            http_response_code(500);
        }
    }

    public function unblockIP($ipAddress) {
        try {
            $query = "UPDATE network_logs SET is_blocked = 0 WHERE ip_address = :ip_address";
            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(':ip_address', $ipAddress);

            if ($stmt->execute()) {
                $file = '../logs/ip_unblock.log';
                $logEntry = sprintf("IP: %s unblocked at %s\n", $ipAddress, date('Y-m-d H:i:s'));
                file_put_contents($file, $logEntry, FILE_APPEND);
                echo json_encode(['success' => true, 'message' => "IP unblocked successfully."]);
                exit;
            } else {
                echo json_encode(['success' => false, 'message' => "Failed to unblock IP."]);
                http_response_code(400);
            }
        } catch (Exception $e) {
            echo json_encode(['error' => $e->getMessage()]);
            http_response_code(500);
        }
    }
}

$threatModel = new ThreatModel();
$data = json_decode(file_get_contents("php://input"), true);

if (isset($data['action'])) {
    switch ($data['action']) {
        case 'getBlockedVsActive':
            $threatModel->getBlockedVsActive();
            break;
        case 'getThreatPercentage':
            $threatModel->getThreatPercentage();
            break;
        case 'getAllNetworkThreats':
            $threatModel->getAllNetworkThreats();
            break;
        case 'getThreatTrendData':  
            $threatModel->getThreatTrendData();
            break;
       
        default:
            http_response_code(400);
            echo json_encode(['error' => 'Invalid action.']);
            break;
    }
} else {
    http_response_code(400);
    echo json_encode(['error' => 'No action specified.']);
}
