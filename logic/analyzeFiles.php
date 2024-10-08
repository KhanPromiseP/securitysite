<?php

include '../src/config/Database.php'; 

class FileAnalyzer
{
    
    private $conn;

    public function __construct($dbConnection)
    {
        $this->conn = $dbConnection;
    }

    /**
     * Analyze uploaded files and store suspicious ones
     */
    public function analyzeFiles($files)
    {
        foreach ($files as $file) {
            if ($this->isSuspicious($file)) {
               
                $this->storeSuspiciousFile($file);
            }
        }
    }

    private function isSuspicious($file)
    {

        return $this->isSuspiciousExtension($file['name']) || 
               $this->isSuspiciousSize($file['size']) ||
               $this->hasMaliciousContent($file['tmp_name']);
    }

    /**
     * Check if the file extension is blacklisted
     */
    private function isSuspiciousExtension($fileName)
    {
       
        $blacklistedExtensions = ['exe', 'js', 'bat', 'vbs', 'sh'];
        $extension = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));
        return in_array($extension, $blacklistedExtensions);
    }

  
    private function isSuspiciousSize($fileSize)
    {
        $maxFileSize = 10 * 1024 * 1024;
        return $fileSize > $maxFileSize;
    }

    private function hasMaliciousContent($filePath)
    {
        include 'logic/OpenAI.php'; 
        $ai = new OpenAI($apiKey, $apiEndpoint);
        return $ai->analyzeFiles($filePath); 
    }


    private function storeSuspiciousFile($file)
    {
        $query = "INSERT INTO suspicious_files (file_name, file_size, upload_time, file_path) 
                  VALUES (:file_name, :file_size, :upload_time, :file_path)";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(':file_name', $file['name']);
        $stmt->bindParam(':file_size', $file['size']);
        $stmt->bindParam(':upload_time', date('Y-m-d H:i:s'));
        $stmt->bindParam(':file_path', $file['tmp_name']); 

    
        $stmt->execute();

        $this->logSuspiciousFile($file);
    }

    private function logSuspiciousFile($file)
    {
        $logEntry = "Suspicious file detected - Name: " . $file['name'] . 
                    ", Size: " . $file['size'] . " bytes" . 
                    ", Uploaded at: " . date('Y-m-d H:i:s') . PHP_EOL;

      
        file_put_contents('../logs/suspicious_files.log', $logEntry, FILE_APPEND);
    }

    /**
     *  Fetch all suspicious files for real-time display or review
     */
    public function getAllSuspiciousFiles()
    {
        $query = "SELECT * FROM suspicious_files ORDER BY upload_time DESC";
        $stmt = $this->conn->prepare($query);
        $stmt->execute();

        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
}