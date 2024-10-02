<?php
include 'BehaviorAnalyzer.php'; // Include the behavior analyzer class

include_once __DIR__ . '/src/config/Database.php'; // Use include_once to prevent re-declaration


// Initialize the Database class
$database = new Database();
$conn = $database->getConnection();

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['ip'])) {
    $ipAddress = $_POST['ip'];
    // Initialize BehaviorAnalyzer with the database connection and your OpenAI API key
    $behaviorAnalyzer = new BehaviorAnalyzer($conn, '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'); // Replace 'your-openai-api-key' with your real OpenAI API key
    
    // Call unblockIpAddress to unblock the IP
    if ($behaviorAnalyzer->unblockIpAddress($ipAddress)) {
        echo "Successfully unblocked IP: " . $ipAddress;
    } else {
        echo "Failed to unblock IP: " . $ipAddress;
    }
} else {
    echo "Invalid request.";
}