<?php

class OpenAI
{
    private $apiKey;
    private $apiEndpoint;

    public function __construct($apiKey, $apiEndpoint)
    {
        $this->apiKey = $apiKey;
        $this->apiEndpoint = $apiEndpoint;
    }


    public function analyzeEmail()
    {
        include 'analyzeEmail.php'; 
        $data = ['email_content' => $emailContent];
        
        return $this->sendRequest('/analyzeEmail', $data);
    }

    public function analyzeFiles($filePath)
    {
        include 'analyzeFiles.php'; 
        $data = ['file_data' => $fileData];
        
        return $this->sendRequest('/analyzeFiles', $data);
    }

    public function analyzeVulnerability()
    {
        include 'analyzeVulnerability.php'; 
        $data = ['vulnerability_data' => $vulnerabilityData];
        
        return $this->sendRequest('/analyzeVulnerability', $data);
    }

    public function analyzeBehavior()
    {
        include 'analyzeBehavior.php'; 
        $data = ['behavior_data' => $behaviorData];
        
        return $this->sendRequest('/analyzeBehavior', $data);
    }

    public function analyzeTraffic()
    {
        include 'analyzeTraffic.php'; 
        $data = ['traffic_data' => $trafficData];
        
        return $this->sendRequest('/analyzeTraffic', $data);
    }

    /**
     *  Sending request to openAI AI API
     */
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
            return [
                'success' => false,
                'message' => 'Error connecting to openAI AI API'
            ];
        }

        return json_decode($response, true);
    }

    // Function to Process and handle AI responses with automated and user friendly alerts
    public function handleAIResponse($response, $type)
    {
        if (isset($response['success']) && $response['success']) {
            switch ($type) {
                case 'email':
                    include 'analyzeEmail.php';
                    break;
                case 'files':
                    include 'analyzeFiles.php'; 
                    break;
                case 'vulnerability':
                    include 'analyzeVulnerability.php'; 
                    break;
                case 'behavior':
                    include 'analyzeBehavior.php';
                    break;
                case 'traffic':
                    include 'analyzeTraffic.php';
                    break;
                default:
                    return 'Unknown analysis type';
            }
        } else {
            return 'AI analysis failed: ' . $response['message'];
        }
    }
}


$apiKey = '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';
$apiEndpoint = 'https://api.openai.com/v1/completions'; 
$openAI = new OpenAI($apiKey, $apiEndpoint);

// Calls the AI analysis functions for anaysing all included data
$emailResponse = $openAI->analyzeEmail();
$fileResponse = $openAI->analyzeFiles($filePath);
$vulnerabilityResponse =$openAI->analyzeVulnerability();
$behaviorResponse = $openAI->analyzeBehavior();
$trafficResponse = $openAI->analyzeTraffic();

// Handle routes for the responses and outputing of relevant alerts
echo $geminiAI->handleAIResponse($emailResponse, 'email');
echo $geminiAI->handleAIResponse($fileResponse, 'files');
echo $geminiAI->handleAIResponse($vulnerabilityResponse, 'vulnerability');
echo $geminiAI->handleAIResponse($behaviorResponse, 'behavior');
echo $geminiAI->handleAIResponse($trafficResponse, 'traffic');