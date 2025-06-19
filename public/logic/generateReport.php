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
        $formatted = "<strong>Report Details:</strong><br>";
        $formatted .= "<strong>Alert Type:</strong> " . ucfirst(str_replace('_', ' ', $alertType)) . "<br><br>";
        $formatted .= "<table border='1' cellpadding='5' cellspacing='0'>";
        $formatted .= "<tr><th>Field</th><th>Value</th></tr>";

        foreach ($reportDetails as $key => $value) {
            $formatted .= "<tr><td><strong>" . ucfirst(str_replace('_', ' ', $key)) . ":</strong></td><td>$value</td></tr>";
        }

        $formatted .= "</table><br>";
        $formatted .= str_repeat('-', 40) . "<br>";
        return $formatted;
    }

    private function generateReport($alertType, $reportDetails)
    {
        $currentDate = date('Y-m-d H:i:s');
        // $header = "<h2>Generated Report - $currentDate</h2>";
        // $header .= "<hr style='border: 1px solid #ccc;'>";
        $body = $this->formatReportDetails($alertType, $reportDetails);

        return $header . $body;
    }

    private function reportExists($alertType, $entryId)
    {
        $column = ($alertType === 'network_logs') ? 'network_entry_id' : 'website_entry_id';
    
        $sql = "SELECT id FROM generated_reports WHERE alert_type = :alert_type AND $column = :entry_id";
        $stmt = $this->conn->prepare($sql);
        $stmt->bindParam(':alert_type', $alertType);
        $stmt->bindParam(':entry_id', $entryId);
    
        if (!$stmt->execute()) {
            error_log("Error executing query: " . implode(" ", $stmt->errorInfo()));
            return false;
        }
    
        return $stmt->fetch(PDO::FETCH_ASSOC) !== false;
    }

    private function saveGeneratedReport($alertType, $entryId, $report)
    {
        $column = ($alertType === 'network_logs') ? 'network_entry_id' : 'website_entry_id';
    
        $sql = "INSERT INTO generated_reports (alert_type, $column, report_details, generated_at) 
                VALUES (:alert_type, :entry_id, :report_details, NOW())";
        $stmt = $this->conn->prepare($sql);
    
        $stmt->bindParam(':alert_type', $alertType);
        $stmt->bindParam(':entry_id', $entryId);
        $stmt->bindParam(':report_details', $report);
    
        if ($stmt->execute()) {
            echo "Report saved for Entry ID: $entryId\n";
        } else {
            error_log("Error saving report for Entry ID: $entryId: " . implode(" ", $stmt->errorInfo()));
        }
    }

    public function monitorDatabaseForReports()
    {
        $lastChecked = [
            'network_logs' => '1970-01-01 00:00:00',
            'websites_logs' => '1970-01-01 00:00:00',
        ];

        while (true) {
            foreach ($lastChecked as $alertType => $lastTime) {
                $table = $alertType;
                $column = ($alertType === 'network_logs') ? 'detected_at' : 'checked_at';

                // Fetch new alerts since last check
                $sql = "SELECT * FROM $table WHERE $column > :last_checked ORDER BY $column ASC";
                $stmt = $this->conn->prepare($sql);
                $stmt->bindParam(':last_checked', $lastTime);

                if ($stmt->execute()) {
                    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                        $entryId = $row['id'];
                        $reportDetails = $row;
                        $lastChecked[$alertType] = $row[$column];  

                        // Check if a report for this entry already exists
                        if (!$this->reportExists($alertType, $entryId)) {
                            // Generate and save the report
                            $generatedReport = $this->generateReport($alertType, $reportDetails);
                            $this->saveGeneratedReport($alertType, $entryId, $generatedReport);
                            echo "Report Generated and Saved for $alertType (Entry ID: $entryId)\n";
                        } else {
                            echo "Report already exists for $alertType (Entry ID: $entryId). Skipping...\n";
                        }
                    }
                } else {
                    error_log("Error fetching records for $alertType: " . implode(" ", $stmt->errorInfo()));
                }
            }

            sleep(5);  // Check every 5 seconds
        }
    }
}

require_once '../src/config/Database.php';
$database = new Database();
$conn = $database->getConnection();

$reportGenerator = new ReportGenerator($conn);

$reportGenerator->monitorDatabaseForReports();
?>
