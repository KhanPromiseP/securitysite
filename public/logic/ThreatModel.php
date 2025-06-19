<?php
require_once '../../src/config/Database.php';

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
            $query = "SELECT threat_type, COUNT(*) AS count FROM network_logs GROUP BY threat_type";
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
            $query = "SELECT ip_address, threat_type, user_crime, is_blocked, confidence_score, device_name, detected_at 
                      FROM network_logs 
                      ORDER BY detected_at DESC";
            $stmt = $this->conn->prepare($query);
            $stmt->execute();
            $data = $stmt->fetchAll(PDO::FETCH_ASSOC);
            return $data;
        } catch (Exception $e) {
            return ['error' => $e->getMessage()];
        }
    }

    public function getThreatByIP($ipAddress) {
        try {
            $query = "SELECT ip_address, threat_type, user_crime, is_blocked, confidence_score, device_name, detected_at 
                      FROM network_logs 
                      WHERE ip_address = :ip_address 
                      LIMIT 1";
            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(':ip_address', $ipAddress);
            $stmt->execute();
            return $stmt->fetch(PDO::FETCH_ASSOC);
        } catch (Exception $e) {
            return null;
        }
    }

    public function getBlockStatus($ipAddress) {
        try {
            $query = "SELECT is_blocked FROM network_logs WHERE ip_address = :ip_address";
            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(':ip_address', $ipAddress);
            $stmt->execute();
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            return $row ? (int)$row['is_blocked'] : null;
        } catch (Exception $e) {
            return null;
        }
    }

    public function toggleBlockStatus($ipAddress) {
        $currentStatus = $this->getBlockStatus($ipAddress);
        if ($currentStatus === null) {
            echo json_encode(['success' => false, 'message' => 'IP address not found']);
            return;
        }

        $newStatus = $currentStatus ? 0 : 1;
        $success = $this->setBlockStatus($ipAddress, $newStatus);
        
        echo json_encode([
            'success' => $success,
            'message' => $success 
                ? "IP $ipAddress successfully " . ($newStatus ? "blocked" : "unblocked") 
                : "Failed to update status for $ipAddress"
        ]);
}


    public function setBlockStatus($ipAddress, $newStatus) {
        try {
            $query = "UPDATE network_logs 
                      SET is_blocked = :new_status, detected_at = NOW() 
                      WHERE ip_address = :ip_address";
            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(':new_status', $newStatus, PDO::PARAM_INT);
            $stmt->bindParam(':ip_address', $ipAddress);
            return $stmt->execute();
        } catch (Exception $e) {
            return false;
        }
    }

    public function deleteIP($ipAddress) {
        try {
            $query = "DELETE FROM network_logs WHERE ip_address = :ip_address";
            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(':ip_address', $ipAddress);
            return $stmt->execute();
        } catch (Exception $e) {
            return false;
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
}

// Entry point for direct fetch or standalone use
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
            echo json_encode($threatModel->getAllNetworkThreats());
            break;
        case 'getThreatTrendData':
            $threatModel->getThreatTrendData();
            break;
        case 'getThreatByIP':
            echo json_encode($threatModel->getThreatByIP($data['ipAddress'] ?? ''));
            break;
        case 'toggleBlockStatus':
            $threatModel->toggleBlockStatus($data['ipAddress'] ?? '');
            break;
        case 'deleteThreatByIP':
        case 'deleteIPAddress':
            echo json_encode($threatModel->deleteIP($data['ipAddress'] ?? ''));
            break;
        default:
            http_response_code(400);
            echo json_encode(['error' => 'Invalid action.']);
    }
} else {
    http_response_code(400);
    echo json_encode(['error' => 'No action specified.']);
}
