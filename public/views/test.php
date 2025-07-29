<?php
require_once '../../src/config/Database.php';
header('Content-Type: application/json');

$database = new Database();
$pdo = $database->getConnection();

if (!$pdo) {
    die(json_encode(['error' => 'Database connection failed']));
}

$users = $pdo->query("SELECT * FROM user_history LIMIT 5")->fetchAll(PDO::FETCH_ASSOC);
echo json_encode(['users' => $users]);
?>