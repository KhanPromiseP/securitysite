<?php

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

class ReportGenerator
{
    private $conn;

    public function __construct($db)
    {
        $this->conn = $db;
    }

    private function formatReportDetails($alertType, $reportDetails)
    {
        $formatted = "Report Details:\n";
        $formatted .= "Alert Type: " . ucfirst(str_replace('_', ' ', $alertType)) . "\n";
        $formatted .= "Details:\n";

        foreach ($reportDetails as $key => $value) {
            $formatted .= ucfirst(str_replace('_', ' ', $key)) . ": $value\n";
        }

        $formatted .= str_repeat('-', 40) . "\n";
        return $formatted;
    }

    private function generateReport($alertType, $reportDetails)
    {
        $currentDate = date('Y-m-d H:i:s');
        $header = "Generated Report - $currentDate\n";
        $header .= str_repeat('=', 50) . "\n";

        $body = $this->formatReportDetails($alertType, $reportDetails);

        return $header . $body;
    }

    private function reportExists($alertType, $entryId)
    {
        $sql = "SELECT id FROM generated_reports WHERE alert_type = :alert_type AND entry_id = :entry_id";
        $stmt = $this->conn->prepare($sql);
        $stmt->bindParam(':alert_type', $alertType);
        $stmt->bindParam(':entry_id', $entryId);
        $stmt->execute();

        return $stmt->fetch(PDO::FETCH_ASSOC) !== false;
    }

    private function saveGeneratedReport($alertType, $entryId, $report)
    {
        $sql = "INSERT INTO generated_reports (alert_type, entry_id, report_details, generated_at) 
                VALUES (:alert_type, :entry_id, :report_details, NOW())";
        $stmt = $this->conn->prepare($sql);
        $stmt->bindParam(':alert_type', $alertType);
        $stmt->bindParam(':entry_id', $entryId);
        $stmt->bindParam(':report_details', $report);
        $stmt->execute();
    }

    public function monitorDatabaseForReports()
    {
        $tables = [
            'network_logs' => "SELECT * FROM network_logs WHERE detected_at >= NOW() - INTERVAL 0.5 MINUTE",
            'website_logs' => "SELECT * FROM website_logs WHERE checked_at >= NOW() - INTERVAL 0.5 MINUTE",
        ];

        while (true) {
            foreach ($tables as $alertType => $sql) {
                $stmt = $this->conn->prepare($sql);
                $stmt->execute();

                while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                    $entryId = $row['id']; 
                    $reportDetails = $row; 

                    if (!$this->reportExists($alertType, $entryId)) {
                        $generatedReport = $this->generateReport($alertType, $reportDetails);
                        $this->saveGeneratedReport($alertType, $entryId, $generatedReport);

                        echo "Report Generated and Saved for $alertType (Entry ID: $entryId)\n";
                    } else {
                        echo "Report already exists for $alertType (Entry ID: $entryId). Skipping...\n";
                    }
                }
            }

            sleep(10);
        }
    }
}

require_once '../src/config/Database.php';
$database = new Database();
$conn = $database->getConnection();

$reportGenerator = new ReportGenerator($conn);

$reportGenerator->monitorDatabaseForReports();
