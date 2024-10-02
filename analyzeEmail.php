<?php

// Include the database connection configuration
include __DIR__.'/src/config/Database.php'; // Modify the path as needed

class EmailAnalyzer
{
    // Database connection property
    private $conn;
    
    // Constructor to initialize the database connection
    public function __construct($dbConnection)
    {
        $this->conn = $dbConnection;
    }

    // Analyze email traffic data and store any suspicious emails
    public function analyzeEmails($emailData)
    {
        foreach ($emailData as $email) {
            if ($this->isSuspicious($email)) {
                // Store suspicious emails in the database
                $this->storeSuspiciousEmail($email);
            }
        }
    }

    // Logic to determine if an email is suspicious based on content, sender, or attachments
    private function isSuspicious($email)
    {
        // Custom logic for email threat analysis
        // Check for blacklisted senders, keywords, or suspicious attachments
        return $this->isBlacklistedSender($email['from']) || 
               $this->hasSuspiciousContent($email['subject'], $email['body']) || 
               $this->hasSuspiciousAttachments($email['attachments']);
    }

    // Check if the email sender is blacklisted
    private function isBlacklistedSender($emailAddress)
    {
        include 'blacklist.php'; // Modify this file to include blacklisted email addresses or connect to an API

        return in_array($emailAddress, $blacklistedEmails);
    }

    // Check if the email contains suspicious content (e.g., phishing keywords, malware links)
    private function hasSuspiciousContent($subject, $body)
    {
        // Example of suspicious keywords (phishing attempts, malware links, etc.)
        $suspiciousKeywords = ['urgent', 'password', 'click here', 'verify account'];
        foreach ($suspiciousKeywords as $keyword) {
            if (stripos($subject, $keyword) !== false || stripos($body, $keyword) !== false) {
                return true;
            }
        }
        return false;
    }

    // Check for suspicious attachments (e.g., executable files, malware)
    private function hasSuspiciousAttachments($attachments)
    {
        // Example: Block potentially dangerous file types (e.g., .exe, .bat)
        $suspiciousExtensions = ['exe', 'bat', 'js', 'vbs', 'sh'];
        foreach ($attachments as $attachment) {
            $ext = pathinfo($attachment['filename'], PATHINFO_EXTENSION);
            if (in_array($ext, $suspiciousExtensions)) {
                return true;
            }
        }
        return false;
    }

    // Store suspicious email data in the database
    private function storeSuspiciousEmail($email)
    {
        $query = "INSERT INTO suspicious_emails (sender, recipient, subject, body, timestamp) 
                  VALUES (:sender, :recipient, :subject, :body, :timestamp)";
        $stmt = $this->conn->prepare($query);

        // Bind parameters
        $stmt->bindParam(':sender', $email['from']);
        $stmt->bindParam(':recipient', $email['to']);
        $stmt->bindParam(':subject', $email['subject']);
        $stmt->bindParam(':body', $email['body']);
        $stmt->bindParam(':timestamp', $email['timestamp']);

        // Execute the query
        $stmt->execute();

        // Log the suspicious email for auditing purposes
        $this->logSuspiciousEmail($email);
    }

    // Log suspicious email into a file for audit or review purposes
    private function logSuspiciousEmail($email)
    {
        $logEntry = "Suspicious email detected - Sender: " . $email['from'] . 
                    ", Recipient: " . $email['to'] . 
                    ", Subject: " . $email['subject'] . 
                    ", Timestamp: " . date('Y-m-d H:i:s', $email['timestamp']) . PHP_EOL;

        // Write the log entry to a log file (path can be configured)
        file_put_contents('../logs/suspicious_emails.log', $logEntry, FILE_APPEND);
    }

    // Fetch all suspicious emails for real-time display or review
    public function getAllSuspiciousEmails()
    {
        $query = "SELECT * FROM suspicious_emails ORDER BY timestamp DESC";
        $stmt = $this->conn->prepare($query);
        $stmt->execute();

        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
}

// Include this script in your dashboard to trigger real-time display of suspicious emails
// Example: include '../dashboard/displayEmails.php'; // Modify this path as necessary