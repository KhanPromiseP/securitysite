<?php


include '../src/config/Database.php';

class EmailAnalyzer
{
  
    private $conn;
    
    public function __construct($dbConnection)
    {
        $this->conn = $dbConnection;
    }

    public function analyzeEmails($emailData)
    {
        foreach ($emailData as $email) {
            if ($this->isSuspicious($email)) {
              
                $this->storeSuspiciousEmail($email);
            }
        }
    }

    
    private function isSuspicious($email)
    {
        return $this->isBlacklistedSender($email['from']) || 
               $this->hasSuspiciousContent($email['subject'], $email['body']) || 
               $this->hasSuspiciousAttachments($email['attachments']);
    }

    
    private function isBlacklistedSender($emailAddress)
    {
        include 'logic/blacklist.php'; 

        return in_array($emailAddress, $blacklistedEmails);
    }

    /**
     *  Checks if the email contains suspicious content (e.g., phishing keywords, malware links)
     */ 
    private function hasSuspiciousContent($subject, $body)
    {
        $suspiciousKeywords = ['urgent', 'password', 'click here', 'verify account', 'verify now'];
        foreach ($suspiciousKeywords as $keyword) {
            if (stripos($subject, $keyword) !== false || stripos($body, $keyword) !== false) {
                return true;
            }
        }
        return false;
    }

    private function hasSuspiciousAttachments($attachments)
    {
        $suspiciousExtensions = ['exe', 'bat', 'js', 'vbs', 'sh', 'rar', 'zip'];
        foreach ($attachments as $attachment) {
            $ext = pathinfo($attachment['filename'], PATHINFO_EXTENSION);
            if (in_array($ext, $suspiciousExtensions)) {
                return true;
            }
        }
        return false;
    }
    private function storeSuspiciousEmail($email)
    {
        $query = "INSERT INTO suspicious_emails (sender, recipient, subject, body, timestamp) 
                  VALUES (:sender, :recipient, :subject, :body, :timestamp)";
        $stmt = $this->conn->prepare($query);

        $stmt->bindParam(':sender', $email['from']);
        $stmt->bindParam(':recipient', $email['to']);
        $stmt->bindParam(':subject', $email['subject']);
        $stmt->bindParam(':body', $email['body']);
        $stmt->bindParam(':timestamp', $email['timestamp']);

        $stmt->execute();

        /**
         *  Log the suspicious email for auditing purposes
         */
        $this->logSuspiciousEmail($email);
    }

    private function logSuspiciousEmail($email)
    {
        $logEntry = "Suspicious email detected - Sender: " . $email['from'] . 
                    ", Recipient: " . $email['to'] . 
                    ", Subject: " . $email['subject'] . 
                    ", Timestamp: " . date('Y-m-d H:i:s', $email['timestamp']) . PHP_EOL;

        file_put_contents('../logs/suspicious_emails.log', $logEntry, FILE_APPEND);
    }

    /**
     *  Fetch all suspicious emails for real-time display or review
     */
    public function getAllSuspiciousEmails()
    {
        $query = "SELECT * FROM suspicious_emails ORDER BY timestamp DESC";
        $stmt = $this->conn->prepare($query);
        $stmt->execute();

        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
}