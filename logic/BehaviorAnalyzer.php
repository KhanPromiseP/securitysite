<?php
include '../src/config/Database.php';
include '../src/config/config.php';

class BehaviorAnalyzer {
    private $conn;
    private $config;

    public function __construct($dbConnection) {
        $this->conn = $dbConnection;
        $this->config = include('../src/config/config.php');
    }

    public function run() {
        // continuos real time monitoring
        while (true) {
            $this->monitorUserBehavior();
            $this->analyzeUserBehavior();
            sleep(30);
        }
    }

    /**
     * Monitor user behavior by fetching from the specified website's API
     */ 
    private function monitorUserBehavior() {
        $websiteUrl = $this->config['websiteUrl'];
        $ch = curl_init($websiteUrl);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $response = curl_exec($ch);
        curl_close($ch);

        if ($response === false) {
            error_log("Failed to fetch data from website: " . curl_error($ch));
            return;
        }

        $userData = json_decode($response, true);

        if (!empty($userData)) {
            foreach ($userData as $user) {
                $this->storeUserBehavior($user);
            }
        }
    }

    private function storeUserBehavior($user) {
        $query = "INSERT INTO user_behavior (user_id, ip_address, activity, timestamp)
                  VALUES (:user_id, :ip_address, :activity, :timestamp)";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(':user_id', $user['user_id']);
        $stmt->bindParam(':ip_address', $user['ip_address']);
        $stmt->bindParam(':activity', json_encode($user['activity']));
        $stmt->bindParam(':timestamp', $user['timestamp']); 
        $stmt->execute();
    }

    public function analyzeUserBehavior() {
        $query = "SELECT * FROM user_behavior";
        $stmt = $this->conn->prepare($query);
        $stmt->execute();
        $userData = $stmt->fetchAll(PDO::FETCH_ASSOC);

        foreach ($userData as $user) {
            if ($this->isSuspicious($user)) {
                $this->storeSuspiciousBehavior($user);
                $this->blockUserIP($user['ip_address']);
            }
        }
    }

    /**
     * Checking if a user activity is suspicious using the OpenAI API
     * 
     */
    private function isSuspicious($user) {
        $url = 'https://api.openai.com/v1/completions';
        $data = json_encode([
            'model' => 'text-davinci-003',
            'prompt' => "Analyze this user activity and determine if it is suspicious: " . json_encode($user['activity']),
            'max_tokens' => 100,
        ]);

        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Content-Type: application/json',
            'Authorization: ' . 'Bearer ' . $this->config['openAiApiKey'],
        ]);
        $response = curl_exec($ch);
        curl_close($ch);

        $result = json_decode($response, true);
        return strpos($result['choices'][0]['text'], 'suspicious') !== false;
    }

    private function storeSuspiciousBehavior($user) {
        $query = "INSERT INTO suspicious_behavior (user_id, ip_address, behavior_details, detection_time) 
                  VALUES (:user_id, :ip_address, :behavior_details, :detection_time)";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(':user_id', $user['user_id']);
        $stmt->bindParam(':ip_address', $user['ip_address']);
        $stmt->bindParam(':behavior_details', json_encode($user['activity']));
        $stmt->bindParam(':detection_time', date('Y-m-d H:i:s'));
        $stmt->execute();
    }

    /**
     * Block suspicious IP address and redirect to the blocked page
     * 
     */
    private function blockUserIP($ip_address) {
        $query = "UPDATE suspicious_behavior SET is_blocked = 1, blocked_at = NOW() WHERE ip_address = :ip_address";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(':ip_address', $ip_address);
        $stmt->execute();
        
        if ($stmt->execute()) {
            file_put_contents('../logs/ip_block.log', "Blocked IP:" .$ip_address. " at " . date('Y-m-d H:i:s') . PHP_EOL, FILE_APPEND);
            return true;
        }
        if ($this->getCurrentUserIP() === $ip_address) {
            header("Location: ../views/blocked.php"); 
            exit;
        }
    }

    /**
     * Get the current user's IP address
     */
    private function getCurrentUserIP() {
        if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
            $ip = $_SERVER['HTTP_CLIENT_IP'];
        } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
        } else {
            $ip = $_SERVER['REMOTE_ADDR'];
        }
        return $ip;
    }

    /**
     * Checking if the current user's IP is blocked before loading the website
     */
    public function checkIfIPBlocked() {
        $userIP = $this->getCurrentUserIP();
        $query = "SELECT is_blocked FROM suspicious_behavior WHERE ip_address = :ip_address";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(':ip_address', $userIP);
        $stmt->execute();
        $isBlocked = $stmt->fetchColumn();

        if ($isBlocked) {
            header("Location: /logic/blocked.php");
            exit;
        }
    }
}

$database = new Database();
$db = $database->getConnection();
$analyzer = new BehaviorAnalyzer($db);

$analyzer->checkIfIPBlocked();

$analyzer->run();