<?php
require_once '../../src/config/Database.php';

class WebThreatModel {
    private $conn;

    public function __construct() {
        $db = new Database();
        $this->conn = $db->getConnection();
    }

    public function getAllWebsiteThreats() {
        try {
            $query = "SELECT * FROM websites_logs ORDER BY checked_at DESC";
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
                        DATE_FORMAT(checked_at, '%Y-%m-%d %H:%i:%s') AS checked_at,
                        COUNT(*) AS threat_count 
                      FROM websites_logs 
                      GROUP BY checked_at 
                      ORDER BY checked_at DESC";
            $stmt = $this->conn->prepare($query);
            $stmt->execute();
            $data = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            echo json_encode($data);
        } catch (Exception $e) {
            echo json_encode(['error' => $e->getMessage()]);
            http_response_code(500);
        }
    }

    public function getBlockedVsActive() {
        try {
            $query = "SELECT COUNT(*) AS total, SUM(is_blocked = 1) AS blocked FROM websites_logs";
            $stmt = $this->conn->prepare($query);
            $stmt->execute();
            $data = $stmt->fetch(PDO::FETCH_ASSOC);
            $active = $data['total'] - $data['blocked'];
            echo json_encode(['active' => $active, 'blocked' => $data['blocked']]);
        } catch (Exception $e) {
            echo json_encode(['error' => $e->getMessage()]);
            http_response_code(500);
        }
    }

    public function getThreatPercentage() {
        try {
            $query = "SELECT status, COUNT(*) AS threat_count FROM websites_logs GROUP BY status";
            $stmt = $this->conn->prepare($query);
            $stmt->execute();
            $data = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            $totalThreats = array_sum(array_column($data, 'threat_count'));
            foreach ($data as &$item) {
                $item['percentage'] = ($item['threat_count'] / $totalThreats) * 100;
            }
            
            echo json_encode($data);
        } catch (Exception $e) {
            echo json_encode(['error' => $e->getMessage()]);
            http_response_code(500);
        }
    }


    public function blockIP($ipAddress) {
        try {
            $checkQuery = "SELECT is_blocked FROM websites_logs WHERE ip_address = :ip_address";
            $stmt = $this->conn->prepare($checkQuery);
            $stmt->bindParam(':ip_address', $ipAddress);
            $stmt->execute();
            $log = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($log && $log['is_blocked'] == 0) {
                $query = "UPDATE websites_logs SET is_blocked = 1, blocked_at = NOW() WHERE ip_address = :ip_address";
                $stmt = $this->conn->prepare($query);
                $stmt->bindParam(':ip_address', $ipAddress);

                if ($stmt->execute()) {
                    $this->logAction('ip_block', $ipAddress);
                    echo json_encode(['success' => true, 'message' => "IP blocked successfully."]);
                } else {
                    echo json_encode(['success' => false, 'message' => "Failed to block IP."]);
                    http_response_code(400);
                }
            } else {
                echo json_encode(['success' => false, 'message' => "IP is already blocked or doesn't exist."]);
            }
        } catch (Exception $e) {
            echo json_encode(['error' => $e->getMessage()]);
            http_response_code(500);
        }
    }

    public function unblockIP($ipAddress) {
        try {
            $checkQuery = "SELECT is_blocked FROM websites_logs WHERE ip_address = :ip_address";
            $stmt = $this->conn->prepare($checkQuery);
            $stmt->bindParam(':ip_address', $ipAddress);
            $stmt->execute();
            $log = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($log && $log['is_blocked'] == 1) {
                $query = "UPDATE websites_logs SET is_blocked = 0, unblocked_at = NOW() WHERE ip_address = :ip_address";
                $stmt = $this->conn->prepare($query);
                $stmt->bindParam(':ip_address', $ipAddress);

                if ($stmt->execute()) {
                    $this->logAction('ip_unblock', $ipAddress);
                    echo json_encode(['success' => true, 'message' => "IP unblocked successfully."]);
                } else {
                    echo json_encode(['success' => false, 'message' => "Failed to unblock IP."]);
                    http_response_code(400);
                }
            } else {
                echo json_encode(['success' => false, 'message' => "IP is not blocked or doesn't exist."]);
            }
        } catch (Exception $e) {
            echo json_encode(['error' => $e->getMessage()]);
            http_response_code(500);
        }
    }

    private function logAction($action, $ipAddress) {
        $file = ($action === 'ip_block') ? '../logs/ip_block.log' : '../logs/ip_unblock.log';
        $logEntry = sprintf("IP: %s %s at %s\n", $ipAddress, ($action === 'ip_block' ? 'blocked' : 'unblocked'), date('Y-m-d H:i:s'));
        file_put_contents($file, $logEntry, FILE_APPEND);
    }
}

$threatModel = new WebThreatModel();
$data = json_decode(file_get_contents("php://input"), true);

if (isset($data['action'])) {
    switch ($data['action']) {
        case 'fetchThreats':
            $threatModel->getAllWebsiteThreats();
            break;
        case 'getThreatTrendData':
            $threatModel->getThreatTrendData();
            break;
        case 'getBlockedVsActive':
            $threatModel->getBlockedVsActive();
            break;
        case 'getThreatPercentage':
            $threatModel->getThreatPercentage();
            break;
        case 'blockIPAddress':
            if (isset($data['ipAddress'])) {
                $threatModel->blockIP($data['ipAddress']);
            } else {
                echo json_encode(['error' => 'IP address is required']);
            }
            break;
        case 'unblockIPAddress':
            if (isset($data['ipAddress'])) {
                $threatModel->unblockIP($data['ipAddress']);
            } else {
                echo json_encode(['error' => 'IP address is required']);
            }
            break;
        default:
            echo json_encode(['error' => 'Invalid action']);
    }
} else {
    echo json_encode(['error' => 'No action specified']);
}
?>
