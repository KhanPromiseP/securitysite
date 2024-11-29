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
        $header = "Generated Report - $currentDate\n br";
        $header .= str_repeat('=', 50) . "\n br";

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
    
        $stmt->execute();
    }
    

    public function monitorDatabaseForReports()
    {
        $lastChecked = [
            'network_logs' => '1970-01-01 00:00:00',
            'website_logs' => '1970-01-01 00:00:00',
        ];
    
        while (true) {
            foreach ($lastChecked as $alertType => $lastTime) {
                $table = $alertType;
                $column = ($alertType === 'network_logs') ? 'detected_at' : 'checked_at';
                
                $sql = "SELECT * FROM $table WHERE $column > :last_checked ORDER BY $column ASC";
                $stmt = $this->conn->prepare($sql);
                $stmt->bindParam(':last_checked', $lastTime);
    
                if ($stmt->execute()) {
                    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                        $entryId = $row['id'];
                        $reportDetails = $row;
                        $lastChecked[$alertType] = $row[$column];  
                        if (!$this->reportExists($alertType, $entryId)) {
                            $generatedReport = $this->generateReport($alertType, $reportDetails);
                            $this->saveGeneratedReport($alertType, $entryId, $generatedReport);
    
                            echo "Report Generated and Saved for $alertType (Entry ID: $entryId)\n";
                            flush();  // Ensure immediate output to the browser
                        } else {
                            echo "Report already exists for $alertType (Entry ID: $entryId). Skipping...\n";
                            flush();  // For immediate output to the browser
                        }
                    }
                } else {
                    error_log("Error fetching records for $alertType: " . implode(" ", $stmt->errorInfo()));
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
