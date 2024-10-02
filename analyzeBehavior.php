<?php

// Include the necessary configurations and Gemini AI logic
include './src/config/Database.php'; // Database connection
include 'GeminiAI.php'; // Gemini AI for advanced behavioral analysis

class BehaviorAnalyzer
{
    private $conn;

    public function __construct($dbConnection)
    {
        $this->conn = $dbConnection;
    }

    // Analyze user behavior data
    public function analyzeUserBehavior($userData)
    {
        foreach ($userData as $user) {
            if ($this->isSuspicious($user)) {
                // Store suspicious behavior and block the IP
                $this->storeSuspiciousBehavior($user);
            }
        }
    }

    // Determine if user behavior is suspicious
    private function isSuspicious($user)
    {
        return $this->isUnusualLoginTime($user['login_time']) || 
               $this->hasMultipleFailedLogins($user['failed_logins']) || 
               $this->hasSuspiciousActivity($user['activity']);
    }

    // Check for unusual login times
    private function isUnusualLoginTime($loginTime)
    {
        $startTime = strtotime("08:00:00");
        $endTime = strtotime("18:00:00");
        $loginTimestamp = strtotime($loginTime);
        return $loginTimestamp < $startTime || $loginTimestamp > $endTime;
    }

    // Check for multiple failed login attempts
    private function hasMultipleFailedLogins($failedLogins)
    {
        $threshold = 3;
        return $failedLogins > $threshold;
    }

    // Check for other suspicious activities (using Gemini AI)
    private function hasSuspiciousActivity($activity)
    {
        include 'GeminiAI.php';
        $ai = new GeminiAI($apiKey, $apiEndpoint);
        return $ai->analyzeBehavior();
    }

    // Store suspicious behavior and block IP in the same table
    private function storeSuspiciousBehavior($user)
    {
        $query = "INSERT INTO suspicious_behavior (user_id, ip_address, behavior_details, detection_time, is_blocked, blocked_at) 
                  VALUES (:user_id, :ip_address, :behavior_details, :detection_time, 1, :blocked_at)";
        $stmt = $this->conn->prepare($query);

        // Bind parameters
        $stmt->bindParam(':user_id', $user['id']);
        $stmt->bindParam(':ip_address', $user['ip_address']);
        $stmt->bindParam(':behavior_details', json_encode($user['activity']));
        $stmt->bindParam(':detection_time', date('Y-m-d H:i:s'));
        $stmt->bindParam(':blocked_at', date('Y-m-d H:i:s'));

        // Execute the query
        $stmt->execute();

        // Optionally, log the blocking
        $this->logSuspiciousBehavior($user);
    }

    // Log suspicious behavior details into a log file
    private function logSuspiciousBehavior($user)
    {
        $logEntry = "Suspicious behavior detected for User ID: " . $user['id'] . 
                    ", IP: " . $user['ip_address'] . 
                    ", Activity: " . json_encode($user['activity']) . 
                    ", Detected at: " . date('Y-m-d H:i:s') . PHP_EOL;

        file_put_contents('./logs/suspicious_behavior.log', $logEntry, FILE_APPEND);
    }

    // Admin can unblock the IP address
    public function unblockIpAddress($ipAddress)
    {
        $query = "UPDATE suspicious_behavior 
                  SET is_blocked = 0, unblocked_at = :unblocked_at 
                  WHERE ip_address = :ip_address AND is_blocked = 1";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(':ip_address', $ipAddress);
        $stmt->bindParam(':unblocked_at', date('Y-m-d H:i:s'));

        // Execute the query to unblock the IP
        if ($stmt->execute()) {
            file_put_contents('./logs/ip_unblock.log', "Unblocked IP: $ipAddress at " . date('Y-m-d H:i:s') . PHP_EOL, FILE_APPEND);
            return true;
        }

        return false;
    }
}