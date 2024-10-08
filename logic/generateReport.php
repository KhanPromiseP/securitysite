<?php
class ReportGenerator
{
    private $conn;
    public function __construct($db)
    {
        $this->conn = $db;
    }

    public function generateAIReport($alertType, $reportDetails)
    {
        try {
            $description = $this->formatReportDetails($alertType, $reportDetails);

            $data = [
                'model' => 'text-davinci-003',
                'prompt' => "Generate a detailed report for the following alert type: " . ucfirst(str_replace('_', ' ', $alertType))
                    .
                    "\n" . $description,
                'max_tokens' => 1000,
            ];

            $apiKey =
                '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';

            $options = [
                'http' => [
                    'header' => "Content-type: application/json\r\nAuthorization: Bearer $apiKey\r\n",
                    'method' => 'POST',
                    'content' => json_encode($data),
                ],
            ];

            $context = stream_context_create($options);
            $result = file_get_contents('https://api.openai.com/v1/completions', false, $context);

            if ($result === FALSE) {
                throw new Exception("Failed to call AI API.");
            }

            $response = json_decode($result, true);
            return $response['choices'][0]['text'];

        } catch (Exception $e) {
            echo "OpenAI API failed: " . $e->getMessage();
            return false;
        }
    }


    // Function to call the Python script as a fallback
    public function generateFallbackReport($alertType, $reportDetails)
    {
        $reportDetailsJson = json_encode($reportDetails);
        echo "JSON passed to Python: " . $reportDetailsJson;

        $command = escapeshellcmd("python3 generate_report.py '$alertType' '$reportDetailsJson' 2>&1");
        $output = shell_exec($command);

        if ($output) {
            return $output;
        } else {
            echo "Error running Python script: " . $output;
            return false;
        }
    }

    private function formatReportDetails($alertType, $reportDetails)
    {
        $formatted = "Report Details:\n";
        $formatted .= "Alert Type: " . ucfirst($alertType) . "\n";
        $formatted .= "Details: " . $reportDetails . "\n";
        $formatted .= "--------------------------------------------\n";
        return $formatted;
    }

    private function saveGeneratedReport($alertType, $reportDetails)
    {
        $sql = "INSERT INTO generated_reports (alert_type, report_details, generated_at) VALUES (:alert_type,
    :report_details,
    NOW())";
        $stmt = $this->conn->prepare($sql);
        $stmt->bindParam(':alert_type', $alertType);
        $stmt->bindParam(':report_details', $reportDetails);
        $stmt->execute();
    }

    public function monitorDatabaseForReports()
    {
        $tables = [
            'suspicious_behavior' => "SELECT * FROM suspicious_behavior",
            'suspicious_files' => "SELECT * FROM suspicious_files",
            'detected_vulnerabilities' => "SELECT * FROM detected_vulnerabilities",
            'suspicious_traffic' => "SELECT * FROM suspicious_traffic",
            'suspicious_emails' => "SELECT * FROM suspicious_emails"
        ];

        foreach ($tables as $alertType => $sql) {
            $stmt = $this->conn->prepare($sql);
            $stmt->execute();

            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $reportDetails = json_encode($row);

                $aiReport = $this->generateAIReport($alertType, $reportDetails);

                if ($aiReport) {

                    $this->saveGeneratedReport($alertType, $aiReport);
                    echo "AI Report Generated and Saved for $alertType:\n";
                } else {

                    $fallbackReport = $this->generateFallbackReport($alertType, $reportDetails);

                    if ($fallbackReport) {

                        $this->saveGeneratedReport($alertType, $fallbackReport);
                        echo "Fallback Report Generated and Saved for $alertType:\n";
                    } else {
                        echo "Failed to generate report for $alertType.";
                    }
                }
            }
        }
    }
}

require_once '../src/config/Database.php';

$database = new Database();
$conn = $database->getConnection();

$reportGenerator = new ReportGenerator($conn);

$reportGenerator->monitorDatabaseForReports();