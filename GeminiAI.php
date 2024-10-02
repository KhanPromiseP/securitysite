<?php

class GeminiAI
{
    private $apiKey;
    private $apiEndpoint;

    public function __construct($apiKey, $apiEndpoint)
    {
        $this->apiKey = $apiKey;
        $this->apiEndpoint = $apiEndpoint;
    }




    // Analyze email by including the analyzeEmail.php file
    public function analyzeEmail()
    {
        include 'analyzeEmail.php'; // Extracts and queries the email data
        
        // Use $emailContent variable from analyzeEmail.php for analysis
        $data = ['email_content' => $emailContent];
        
        return $this->sendRequest('/analyze-email', $data);
    }

    // Analyze files by including the analyzeFiles.php file
    public function analyzeFiles($filePath)
    {
        include 'analyzeFiles.php'; // Extracts and queries the file data
        
        // Use $fileData variable from analyzeFiles.php for analysis
        $data = ['file_data' => $fileData];
        
        return $this->sendRequest('/analyze-files', $data);
    }

    // Analyze vulnerabilities by including the analyzeVulnerability.php file
    public function analyzeVulnerability()
    {
        include 'analyzeVulnerability.php'; // Extracts and queries the vulnerability data
        
        // Use $vulnerabilityData variable from analyzeVulnerability.php for analysis
        $data = ['vulnerability_data' => $vulnerabilityData];
        
        return $this->sendRequest('/analyze-vulnerability', $data);
    }

    // Analyze user behavior by including the analyzeBehavior.php file
    public function analyzeBehavior()
    {
        include 'analyzeBehavior.php'; // Extracts and queries the behavior data
        
        // Use $behaviorData variable from analyzeBehavior.php for analysis
        $data = ['behavior_data' => $behaviorData];
        
        return $this->sendRequest('/analyze-behavior', $data);
    }

    // Analyze network/website traffic by including the analyzeTraffic.php file
    public function analyzeTraffic()
    {
        include 'analyzeTraffic.php'; // Extracts and queries the traffic data
        
        // Use $trafficData variable from analyzeTraffic.php for analysis
        $data = ['traffic_data' => $trafficData];
        
        return $this->sendRequest('/analyze-traffic', $data);
    }

    // Send request to Gemini AI API
    private function sendRequest($endpoint, $data)
    {
        $url = $this->apiEndpoint . $endpoint;

        $options = [
            'http' => [
                'header'  => "Content-Type: application/json\r\n" .
                             "Authorization: Bearer " . $this->apiKey . "\r\n",
                'method'  => 'POST',
                'content' => json_encode($data),
            ],
        ];

        $context  = stream_context_create($options);
        $response = file_get_contents($url, false, $context);

        if ($response === FALSE) {
            // Handle error
            return [
                'success' => false,
                'message' => 'Error connecting to Gemini AI API'
            ];
        }

        return json_decode($response, true);
    }

    // Process and handle AI responses with automated and user-friendly alerts
    public function handleAIResponse($response, $type)
    {
        if (isset($response['success']) && $response['success']) {
            // Automated response handling
            switch ($type) {
                case 'email':
                    include 'analyzeEmail.php'; // Include the PHP file for email analysis
                    break;
                case 'files':
                    include 'analyzeFiles.php'; // Include the PHP file for file analysis
                    break;
                case 'vulnerability':
                    include 'analyzeVulnerability.php'; // Include the PHP file for vulnerability analysis
                    break;
                case 'behavior':
                    include 'analyzeBehavior.php'; // Include the PHP file for behavior analysis
                    break;
                case 'traffic':
                    include 'analyzeTraffic.php'; // Include the PHP file for traffic analysis
                    break;
                default:
                    return 'Unknown analysis type';
            }
        } else {
            // Provide user-friendly alerts
            return 'AI analysis failed: ' . $response['message'];
        }
    }
}

// Example initialization (adjust as per actual use case)
$apiKey = 'AIzaSyAYGMWGTzPad8g58v76M9CxzzD1k8Lyk6o';
$apiEndpoint = 'https://api.gemini.ai/v1'; // Replace with actual API endpoint

$geminiAI = new GeminiAI($apiKey, $apiEndpoint);

// Call AI analysis functions for all included data
$emailResponse = $geminiAI->analyzeEmail();
$fileResponse = $geminiAI->analyzeFiles($filePath);
$vulnerabilityResponse = $geminiAI->analyzeVulnerability();
$behaviorResponse = $geminiAI->analyzeBehavior();
$trafficResponse = $geminiAI->analyzeTraffic();

// Handle the responses and output relevant alerts
echo $geminiAI->handleAIResponse($emailResponse, 'email');
echo $geminiAI->handleAIResponse($fileResponse, 'files');
echo $geminiAI->handleAIResponse($vulnerabilityResponse, 'vulnerability');
echo $geminiAI->handleAIResponse($behaviorResponse, 'behavior');
echo $geminiAI->handleAIResponse($trafficResponse, 'traffic');// Function to generate a report based on alert type