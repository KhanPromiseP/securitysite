<?php
require_once 'Database.php';

class ThreatModel {
    private $conn;

    public function __construct() {
        $db = new Database();
        $this->conn = $db->getConnection();
    }
   
    public function getAllNetworkThreats() {
        $query = "SELECT * FROM network_logs ORDER BY detected_at DESC";
        $stmt = $this->conn->prepare($query);
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public function addNetworkThreat($ip, $type, $crime) {
        $query = "INSERT INTO network_logs (ip_address, threat_type, user_crime) VALUES (:ip, :type, :crime)";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(':ip', $ip);
        $stmt->bindParam(':type', $type);
        $stmt->bindParam(':crime', $crime);
        $stmt->execute();
    }


    public function getAllWebsiteThreats() {
        $query = "SELECT * FROM website_logs ORDER BY detected_at DESC";
        $stmt = $this->conn->prepare($query);
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public function addWebsiteThreat($ip, $type, $crime) {
        $query = "INSERT INTO website_logs (ip_address, threat_type, user_crime) VALUES (:ip, :type, :crime)";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(':ip', $ip);
        $stmt->bindParam(':type', $type);
        $stmt->bindParam(':crime', $crime);
        $stmt->execute();
    }






   
    public function blockIP($ipAddress) {
        $query = "UPDATE suspicious_behavior SET is_blocked = 1, blocked_at = NOW() WHERE ip_address = :ip_address";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(':ip_address', $ipAddress);
        if ($stmt->execute()) {
            file_put_contents('../logs/ip_block.log', "Blocked IP: " . $ipAddress . " at " . date('Y-m-d H:i:s') . PHP_EOL, FILE_APPEND);
            return true;
        }
        return false;
    }

    public function unblockIP($ipAddress) {
        $query = "UPDATE suspicious_behavior SET is_blocked = 0, unblocked_at = NOW() WHERE ip_address = :ip_address";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(':ip_address', $ipAddress);
        if ($stmt->execute()) {
            file_put_contents('../logs/ip_unblock.log', "Unblocked IP: " . $ipAddress . " at " . date('Y-m-d H:i:s') . PHP_EOL, FILE_APPEND);
            return true;
        }
        return false;
    }

    public function isBlocked($ipAddress) {
        $query = "SELECT is_blocked FROM suspicious_behavior WHERE ip_address = :ip_address";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(':ip_address', $ipAddress);
        $stmt->execute();
        return $stmt->fetchColumn() > 0;
    }
}