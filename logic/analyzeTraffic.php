<?php


include '../src/config/Database.php'; 

class TrafficAnalyzer
{
    private $conn;
    
    public function __construct($dbConnection)
    {
        $this->conn = $dbConnection;
    }

    /**
     * Function to analyze network traffic and store suspicious activities in the database
     */
    public function analyzeTraffic($trafficData)
    {
        foreach ($trafficData as $packet) {
            if ($this->isSuspicious($packet)) {
              
                $this->storeSuspiciousTraffic($packet);
            }
        }
    }

 
    private function isSuspicious($packet)
    {
        return $packet['packet_size'] > 5000 || $this->isBlacklisted($packet['src_ip']);
    }

    private function isBlacklisted($ipAddress)
    {
        include 'logic/blacklist.php';
        return in_array($ipAddress, $blacklistedIps);
    }

    private function storeSuspiciousTraffic($packet)
    {
        $query = "INSERT INTO suspicious_traffic (src_ip, dest_ip, packet_size, protocol, timestamp) 
                  VALUES (:src_ip, :dest_ip, :packet_size, :protocol, :timestamp)";
        $stmt = $this->conn->prepare($query);

        $stmt->bindParam(':src_ip', $packet['src_ip']);
        $stmt->bindParam(':dest_ip', $packet['dest_ip']);
        $stmt->bindParam(':packet_size', $packet['packet_size']);
        $stmt->bindParam(':protocol', $packet['protocol']);
        $stmt->bindParam(':timestamp', $packet['timestamp']);
        $stmt->execute();
   
        $this->logSuspiciousTraffic($packet);
    }

    private function logSuspiciousTraffic($packet)
    {
        $logEntry = "Suspicious traffic detected - Source IP: " . $packet['src_ip'] . 
                    ", Destination IP: " . $packet['dest_ip'] . 
                    ", Packet Size: " . $packet['packet_size'] . 
                    ", Protocol: " . $packet['protocol'] . 
                    ", Timestamp: " . date('Y-m-d H:i:s', $packet['timestamp']) . PHP_EOL;

        file_put_contents('../logs/suspicious_traffic.log', $logEntry, FILE_APPEND);
    }

    public function getAllTraffic() {
        $query = "SELECT * FROM suspicious_traffic ORDER BY timestamp DESC";
        $stmt = $this->conn->prepare($query);
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    }
}


$database = new Database();
$conn = $database->getConnection();

if (!$conn) {
    die('Database connection not initialized.');
}

 
$trafficAnalyzer = new TrafficAnalyzer($conn);
$traffic = $trafficAnalyzer->getAllTraffic();

header('Content-Type: application/json');
echo json_encode($traffic);