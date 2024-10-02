<?php
include '../config/database.php'; // Adjust the path as needed

session_start();

class UserActivity
{
    private $conn;

    public function __construct($dbConnection)
    {
        $this->conn = $dbConnection;
    }

    // Update user activity
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

// Update activity for the logged-in user
$userActivity = new UserActivity($pdo); // $pdo is your PDO database connection instance
$userId = $_SESSION['user_id']; // Get user ID from session
$userActivity->updateUserActivity($userId);