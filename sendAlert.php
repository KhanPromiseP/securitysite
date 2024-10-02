<?php
// sendAlert.php

// Function to send email alert when IP is blocked
function sendAlert($ipAddress)
{
    $to = 'admin@example.com';
    $subject = "Security Alert: IP $ipAddress Blocked";
    $message = "The IP address $ipAddress has been blocked after multiple failed access attempts.";

    // Send email
    mail($to, $subject, $message);

    // Optionally log the alert in the database
    global $db;
    $stmt = $db->prepare("INSERT INTO alert_logs (ip_address, message, sent_at) VALUES (?, ?, NOW())");
    $stmt->bind_param("ss", $ipAddress, $message);
    $stmt->execute();
    $stmt->close();
}