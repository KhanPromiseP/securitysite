<?php

// Include the database connection configuration
include '../config/database.php'; // Modify the path as necessary

class FileAnalyzer
{
    // Database connection property
    private $conn;

    // Constructor to initialize the database connection
    public function __construct($dbConnection)
    {
        $this->conn = $dbConnection;
    }

    // Analyze uploaded files and store suspicious ones
    public function analyzeFiles($files)
    {
        foreach ($files as $file) {
            if ($this->isSuspicious($file)) {
                // Store suspicious file details in the database
                $this->storeSuspiciousFile($file);
            }
        }
    }

    // Logic to determine if a file is suspicious based on its type, size, or content
    private function isSuspicious($file)
    {
        // Example: Check for suspicious extensions and file size
        return $this->isSuspiciousExtension($file['name']) || 
               $this->isSuspiciousSize($file['size']) || 
               $this->hasMaliciousContent($file['tmp_name']);
    }

    // Check if the file extension is blacklisted
    private function isSuspiciousExtension($fileName)
    {
        // Example of blocked file types
        $blacklistedExtensions = ['exe', 'js', 'bat', 'vbs', 'sh'];
        $extension = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));
        return in_array($extension, $blacklistedExtensions);
    }

    // Check if the file size exceeds allowed limits
    private function isSuspiciousSize($fileSize)
    {
        // Example: Limit file size to 10MB
        $maxFileSize = 10 * 1024 * 1024; // 10 MB
        return $fileSize > $maxFileSize;
    }

    // Check file content for malware, viruses, or malicious code
    private function hasMaliciousContent($filePath)
    {
        // Integrate with Gemini AI or a malware scanning API
        include 'GeminiAI.php'; // Logic for AI-based file content scanning
        $ai = new GeminiAI($apiKey, $apiEndpoint);
        return $ai->analyzeFiles($filePath); // Assumes GeminiAI has a `scanFile` function
    }

    // Store suspicious file data in the database
    private function storeSuspiciousFile($file)
    {
        $query = "INSERT INTO suspicious_files (file_name, file_size, upload_time, file_path) 
                  VALUES (:file_name, :file_size, :upload_time, :file_path)";
        $stmt = $this->conn->prepare($query);

        // Bind parameters
        $stmt->bindParam(':file_name', $file['name']);
        $stmt->bindParam(':file_size', $file['size']);
        $stmt->bindParam(':upload_time', date('Y-m-d H:i:s'));
        $stmt->bindParam(':file_path', $file['tmp_name']); // Use file path as reference

        // Execute the query
        $stmt->execute();

        // Log the suspicious file for auditing purposes
        $this->logSuspiciousFile($file);
    }

    // Log suspicious file information into a log file
    private function logSuspiciousFile($file)
    {
        $logEntry = "Suspicious file detected - Name: " . $file['name'] . 
                    ", Size: " . $file['size'] . " bytes" . 
                    ", Uploaded at: " . date('Y-m-d H:i:s') . PHP_EOL;

        // Write the log entry to a log file (path can be configured)
        file_put_contents('../logs/suspicious_files.log', $logEntry, FILE_APPEND);
    }

    // Fetch all suspicious files for real-time display or review
    public function getAllSuspiciousFiles()
    {
        $query = "SELECT * FROM suspicious_files ORDER BY upload_time DESC";
        $stmt = $this->conn->prepare($query);
        $stmt->execute();

        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
}

// Usage in your dashboard to trigger real-time display of suspicious files
// Example: include '../dashboard/displayFiles.php'; // Modify this path as necessary