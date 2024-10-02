<?php
// Include the necessary configurations and GeminiAI class
include __DIR__.'/src/config/Database.php'; // Ensure this path is correct
include 'GeminiAI.php'; // Path to your GeminiAI class file

class Reports
{
    private $geminiAI;
    private $conn;
    public function __construct($apiKey, $apiEndpoint,$dbConnection)
    {
        $this->conn = $dbConnection;
        $this->geminiAI = new GeminiAI($apiKey, $apiEndpoint);
    }

    // Function to generate a report based on alert type
    public function generateReportBasedOnAlertType($alertType, $reportDetails)
    {
        // Validate input
        if (empty($alertType) || empty($reportDetails)) {
            throw new InvalidArgumentException('Alert type and report details cannot be empty.');
        }

        // Prepare the SQL query
        $query = "INSERT INTO generated_reports (alert_type, report_details, generated_at) 
                  VALUES (:alert_type, :report_details, :generated_at)";
        $stmt = $stmt = $this->conn->prepare($query);

        // Bind parameters
        $stmt->bindParam(':alert_type', $alertType);
        $stmt->bindParam(':report_details', $reportDetails);
        $stmt->bindParam(':generated_at', date('Y-m-d H:i:s'));

        // Execute the query
        if ($stmt->execute()) {
            return true;
        } else {
            // Handle the error if report generation fails
            return false;
        }
    }
}

// Example usage of the Reports class
try {
    // Initialize the database connection
    $database = new Database();
    $database ->getConnection(); 
    // Create an instance of Reports
    $reports = new Reports($apiKey, $apiEndpoint,$conn);

    // Example data for the report
    $alertType = 'Suspicious Login';
    $reportDetails = 'Details about the suspicious login event.';

    // Generate the report
    if ($reports->generateReportBasedOnAlertType($alertType, $reportDetails)) {
        echo "Report generated successfully.";
    } else {
        echo "Failed to generate report.";
    }
} catch (InvalidArgumentException $e) {
    echo "Error: " . $e->getMessage();
}