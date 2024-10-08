<?php

include '../src/config/Database.php';


$database = new Database();
$db = $database->getConnection();


function getUserIP()
{
    if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
        $ip = $_SERVER['HTTP_CLIENT_IP'];
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
    } else {
        $ip = $_SERVER['REMOTE_ADDR'];
    }
    return $ip;
}

class IPBlocker
{
    private $conn;

    public function __construct($dbConnection)
    {
        $this->conn = $dbConnection;
    }

   
    public function blockIP($ipAddress)
    {
        $query = "UPDATE suspicious_behavior SET is_blocked = 1, blocked_at = NOW() WHERE ip_address = :ip_address";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(':ip_address', $ipAddress);
        $stmt->execute();
        if ($stmt->execute()) {
            file_put_contents('../logs/ip_block.log', "Blocked IP:" . $ipAddress . " at " . date('Y-m-d H:i:s') . PHP_EOL, FILE_APPEND);
            return true;
        }
    }

    public function unblockIP($ipAddress)
    {
        $query = "UPDATE suspicious_behavior SET is_blocked = 0, unblocked_at = NOW() WHERE ip_address = :ip_address";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(':ip_address', $ipAddress);
        $stmt->execute();
        if ($stmt->execute()) {
            file_put_contents('../logs/ip_unblock.log', "Unblocked IP:" . $ipAddress . " at " . date('Y-m-d H:i:s') . PHP_EOL, FILE_APPEND);
            return true;
        }
    }

    public function isBlocked($ipAddress)
    {
        $query = "SELECT is_blocked FROM suspicious_behavior WHERE ip_address = :ip_address";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(':ip_address', $ipAddress);
        $stmt->execute();
        return $stmt->fetchColumn() > 0;
    }
}

$ipBlocker = new IPBlocker($db);

$userIP = getUserIP();

if ($ipBlocker->isBlocked($userIP)) { 
    header("Location: ../views/blocked.php"); 
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $ipAddress = $_POST['ip'];
    $action = $_POST['action']; 

    if ($action === 'block') {
     
        $ipBlocker->blockIP($ipAddress);
        echo "IP $ipAddress has been blocked.";
    } elseif ($action === 'unblock') {
       
        $ipBlocker->unblockIP($ipAddress);
        echo "IP $ipAddress has been unblocked.";
    }
}