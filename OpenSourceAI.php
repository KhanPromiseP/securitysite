<?php

class OpenSourceAI
{
    private $apiKey;
    private $apiEndpoint;

    public function __construct($apiKey)
    {
        $this->apiKey = $apiKey; // API key for OpenAI
        $this->apiEndpoint = "https://api.openai.com/v1/completions"; // OpenAI API endpoint
    }

    // Function to analyze behavior with AI (replace GeminiAI)
    public function analyzeBehavior($userActivity)
    {
        // Call OpenAI API for AI-based analysis
        $openAIAnalysis = $this->analyzeWithOpenAI($userActivity);

        // Call Snort for real-time network analysis
        $snortAnalysis = $this->analyzeWithSnort();

        // Return both AI and Snort results combined
        return [
            'ai_analysis' => $openAIAnalysis,
            'snort_analysis' => $snortAnalysis,
        ];
    }

    // Analyze activity using OpenAI API
    private function analyzeWithOpenAI($activity)
    {
        $curl = curl_init();

        curl_setopt_array($curl, [
            CURLOPT_URL => $this->apiEndpoint,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/json',
                'Authorization: ' . 'Bearer ' . $this->apiKey // Provide the OpenAI API key
            ],
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => json_encode([
                "model" => "gpt-4",
                "prompt" => "Analyze this user behavior: " . $activity,
                "max_tokens" => 150,
            ])
        ]);

        $response = curl_exec($curl);

        if ($response === false) {
            return "Error: " . curl_error($curl);
        }

        curl_close($curl);

        $responseData = json_decode($response, true);
        return $responseData['choices'][0]['text'] ?? 'No analysis available';
    }

    // Analyze using Snort for real-time analysis
    private function analyzeWithSnort()
    {
        // Command to trigger Snort for real-time network monitoring
        $snortCommand = "snort -c /etc/snort/snort.conf -A console -l /var/log/snort"; // Update with Snort config path

        // Execute the command and capture the output
        $output = shell_exec($snortCommand);

        if ($output) {
            return $output; // Return Snort detection results
        } else {
            return "No suspicious activity detected by Snort.";
        }
    }
}