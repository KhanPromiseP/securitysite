<?php
// Include the necessary configurations
include '../config/database.php'; // Ensure this path is correct

// Function to get the number of reports generated this week
function getWeeklyReportCount($dbConnection) {
    $currentWeekStart = date('Y-m-d 00:00:00', strtotime('monday this week'));
    $currentWeekEnd = date('Y-m-d 23:59:59', strtotime('sunday this week'));

    // Prepare the SQL query
    $query = "SELECT COUNT(*) as report_count 
              FROM generated_reports 
              WHERE generated_at BETWEEN :week_start AND :week_end";
    $stmt = $dbConnection->prepare($query);

    // Bind parameters
    $stmt->bindParam(':week_start', $currentWeekStart);
    $stmt->bindParam(':week_end', $currentWeekEnd);

    // Execute the query
    $stmt->execute();

    // Fetch the result
    $result = $stmt->fetch(PDO::FETCH_ASSOC);
    return $result['report_count'];
}

try {
    // Initialize the database connection  
    $database = new Database();
    $database ->getConnection();
    // Get the weekly report count
    $reportCount = getWeeklyReportCount($dbConnection);

    // Output the result as JSON
    echo json_encode(['report_count' => $reportCount]);
} catch (PDOException $e) {
    echo json_encode(['error' => 'Database connection failed: ' . $e->getMessage()]);
}