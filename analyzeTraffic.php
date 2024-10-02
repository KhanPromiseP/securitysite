<?php

// Include the database connection configuration
include __DIR__.'/src/config/Database.php'; // Modify this path as necessary

class TrafficAnalyzer
{
    // Database connection property
    private $conn;
    
    // Constructor to initialize the database connection
    public function __construct($dbConnection)
    {
        $this->conn = $dbConnection;
    }

    // Function to analyze network traffic and store suspicious activities in the database
    public function analyzeTraffic($trafficData)
    {
        foreach ($trafficData as $packet) {
            if ($this->isSuspicious($packet)) {
                // Store suspicious traffic in the database
                $this->storeSuspiciousTraffic($packet);
            }
        }
    }

    // Logic to determine if traffic is suspicious based on custom conditions
    private function isSuspicious($packet)
    {
        // Custom logic for analyzing network traffic patterns
        // Replace the condition below with the logic that fits your specific requirements.
        return $packet['packet_size'] > 5000 || $this->isBlacklisted($packet['src_ip']);
    }

    // Logic to check if an IP is blacklisted (can connect to an external service or local DB)
    private function isBlacklisted($ipAddress)
    {
        // Example: Check against a list of blacklisted IP addresses
        include 'blacklist.php'; // Modify this file to include a list or API call to retrieve blacklisted IPs

        return in_array($ipAddress, $blacklistedIps);
    }

    // Store suspicious traffic data in the database
    private function storeSuspiciousTraffic($packet)
    {
        $query = "INSERT INTO suspicious_traffic (src_ip, dest_ip, packet_size, protocol, timestamp) 
                  VALUES (:src_ip, :dest_ip, :packet_size, :protocol, :timestamp)";
        $stmt = $this->conn->prepare($query);
        
        // Bind parameters to the query
        $stmt->bindParam(':src_ip', $packet['src_ip']);
        $stmt->bindParam(':dest_ip', $packet['dest_ip']);
        $stmt->bindParam(':packet_size', $packet['packet_size']);
        $stmt->bindParam(':protocol', $packet['protocol']);
        $stmt->bindParam(':timestamp', $packet['timestamp']);
        
        // Execute the query
        $stmt->execute();
        
        // Log the suspicious traffic for auditing purposes
        $this->logSuspiciousTraffic($packet);
    }

    // Log suspicious traffic into a file for audit or review purposes
    private function logSuspiciousTraffic($packet)
    {
        $logEntry = "Suspicious traffic detected - Source IP: " . $packet['src_ip'] . 
                    ", Destination IP: " . $packet['dest_ip'] . 
                    ", Packet Size: " . $packet['packet_size'] . 
                    ", Protocol: " . $packet['protocol'] . 
                    ", Timestamp: " . date('Y-m-d H:i:s', $packet['timestamp']) . PHP_EOL;
        
        // Write the log entry to a log file (path can be configured)
        file_put_contents('../logs/suspicious_traffic.log', $logEntry, FILE_APPEND);
    }

    // Function to fetch all suspicious traffic data for real-time display
    public function getAllTraffic() {
        $query = "SELECT * FROM suspicious_traffic ORDER BY timestamp DESC";
        $stmt = $this->conn->prepare($query);
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    }
}


// Initialize the database connection using the Database class
$database = new Database();
$conn = $database->getConnection();

// Check if the $conn is defined and valid
if (!$conn) {
    die('Database connection not initialized.');
}

 
$trafficAnalyzer = new TrafficAnalyzer($conn);
$traffic = $trafficAnalyzer->getAllTraffic();

// Output traffic data as JSON
header('Content-Type: application/json');
echo json_encode($traffic);