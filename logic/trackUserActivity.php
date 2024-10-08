<?php
include '../src/config/Database.php'; 

session_start();

class UserActivity
{
    private $conn;

    public function __construct($dbConnection)
    {
        $this->conn = $dbConnection;
    }

    public function updateUserActivity($userId)
    {
        $query = "INSERT INTO user_sessions (user_id, last_activity, status)
                  VALUES (:user_id, NOW(), 'online')
                  ON DUPLICATE KEY UPDATE last_activity = NOW(), status = 'online'";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(':user_id', $userId);
        $stmt->execute();
    }
}

$database = new Database();
$conn = $database->getConnection();

$userActivity = new UserActivity($conn); 
$userId = $_SESSION['user_id']; 
$userActivity->updateUserActivity($userId);