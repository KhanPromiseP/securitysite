<?php
include '../scripts/analyzeVulnerability.php';

$database = new Database();
$dbConnection = $database->getConnection();
$vulnerabilityAnalyzer = new VulnerabilityAnalyzer($dbConnection);

$detectedVulnerabilities = $vulnerabilityAnalyzer->getAllDetectedVulnerabilities();
?>

<table border="1">
    <thead>
        <tr>
            <th>Vulnerability Type</th>
            <th>Details</th>
            <th>Detection Time</th>
        </tr>
    </thead>
    <tbody>
        <?php foreach ($detectedVulnerabilities as $vulnerability): ?>
        <tr>
            <td><?php echo htmlspecialchars($vulnerability['vulnerability_type']); ?></td>
            <td><?php echo htmlspecialchars($vulnerability['details']); ?></td>
            <td><?php echo htmlspecialchars($vulnerability['detection_time']); ?></td>
        </tr>
        <?php endforeach; ?>
    </tbody>
</table>