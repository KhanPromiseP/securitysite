<?php
header("Content-Type: application/json");

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, "http://localhost:5000/active-devices");
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

$response = curl_exec($ch);

if (curl_errno($ch)) {
    echo json_encode(["error" => "Failed to fetch active device count."]);
} else {
    echo $response;
}

curl_close($ch);
?>
