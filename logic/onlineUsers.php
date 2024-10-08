<?php
include '../src/config/Database.php'; 

class OnlineUsers
{
    private $conn;

    public function __construct($dbConnection)
    {
        $this->conn = $dbConnection;
    }

    public function getOnlineUserCount()
    {
       
        $timeout = 5 * 60;
        $currentTime = time();
        $timeoutTime = $currentTime - $timeout;

        $query = "SELECT COUNT(*) AS online_count FROM user_sessions WHERE last_activity > FROM_UNIXTIME(:timeout_time) AND status = 'online'";
        $stmt = $this->conn->prepare($query);

        $stmt->bindParam(':timeout_time', $timeoutTime);
        $stmt->execute();

        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        return $result['online_count'];
    }
}

$database = new Database();
$conn = $database->getConnection();

$onlineUsers = new OnlineUsers($conn);

$onlineUserCount = $onlineUsers->getOnlineUserCount();

header('Content-Type: application/json');
echo json_encode(array('online_user_count' => $onlineUserCount));