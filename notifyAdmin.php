<?php
// notifyAdmin.php

// Function to store notification in the database for the admin dashboard
function notifyAdmin($ipAddress)
{
    global $db;

    $message = "IP address $ipAddress has been blocked due to multiple failed access attempts.";

    // Store the notification in the database
    $stmt = $db->prepare("INSERT INTO notifications (message, created_at, is_read) VALUES (?, NOW(), 0)");
    $stmt->bind_param("s", $message);
    $stmt->execute();
    $stmt->close();
}