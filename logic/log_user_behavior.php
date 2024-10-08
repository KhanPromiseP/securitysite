<?php
include_once '../src/config/Database.php';

session_start();  

if (!isset($_SESSION['user_id'])) {
    $_SESSION['user_id'] = rand(1, 1000);  
}

$data = json_decode(file_get_contents('php://input'), true);

if (isset($data['activity'])) {
    $database = new Database();
    $db = $database->getConnection();

    $ip_address = $_SERVER['REMOTE_ADDR'];

    $checkQuery = "SELECT is_blocked FROM suspicious_behavior WHERE ip_address = :ip_address AND is_blocked = 1";
    $stmt = $db->prepare($checkQuery);
    $stmt->bindParam(':ip_address', $ip_address);
    $stmt->execute();
    
    if ($stmt->rowCount() > 0) {
        echo json_encode(['status' => 'blocked']);
        exit();
    }

    $query = "INSERT INTO user_behavior (user_id, ip_address, page_url, activity, activity_time) 
              VALUES (:user_id, :ip_address, :page_url, :activity, :activity_time)";
    
    $stmt = $db->prepare($query);
    $stmt->bindParam(':user_id', $_SESSION['user_id']);
    $stmt->bindParam(':ip_address', $ip_address);
    $stmt->bindParam(':page_url', $data['page_url']);
    $stmt->bindParam(':activity', $data['activity']);
    $stmt->bindParam(':activity_time', $data['activity_time']);
    $stmt->execute();
}