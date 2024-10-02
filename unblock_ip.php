<?php
// Include the necessary configurations and logic
include './src/config/Database.php';

class BehaviorAnalyzer
{
    private $conn;

    public function __construct($dbConnection)
    {
        $this->conn = $dbConnection;
    }

    // Unblock IP address
    public function unblockIpAddress($ipAddress)
    {
        $query = "UPDATE suspicious_behavior 
                  SET is_blocked = 0, unblocked_at = :unblocked_at 
                  WHERE ip_address = :ip_address AND is_blocked = 1";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(':ip_address', $ipAddress);
        $stmt->bindParam(':unblocked_at', date('Y-m-d H:i:s'));

        if ($stmt->execute()) {
            return "IP address $ipAddress has been unblocked.";
        } else {
            return "Failed to unblock IP address $ipAddress.";
        }
    }
}

// Check if IP address is passed in the POST request
if (isset($_POST['ip_address'])) {

    $database = new Database();
    $dbConnection = $database->getConnection();

    if (!$dbConnection) {
        die(json_encode(['error' => 'Failed to connect to the database']));
    }
    $behaviorAnalyzer = new BehaviorAnalyzer($dbConnection);
    $ipAddress = $_POST['ip_address'];

    // Unblock the IP and return the response
    $response = $behaviorAnalyzer->unblockIpAddress($ipAddress);
    echo $response;
}