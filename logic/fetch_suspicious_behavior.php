<?php
include '../src/config/Database.php';


$database = new Database();
$db = $database->getConnection();

$query = "SELECT user_id, ip_address, behavior_details, detection_time, is_blocked, blocked_at FROM suspicious_behavior  ORDER BY detection_time DESC";
$stmt = $db->prepare($query);
$stmt->execute();
$suspiciousUsers = $stmt->fetchAll(PDO::FETCH_ASSOC);


echo json_encode($suspiciousUsers);