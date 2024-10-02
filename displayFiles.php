<?php
include '../scripts/analyzeFiles.php';

$database = new Database();
$dbConnection = $database->getConnection();
$fileAnalyzer = new FileAnalyzer($dbConnection);

$suspiciousFiles = $fileAnalyzer->getAllSuspiciousFiles();
?>

<table border="1">
    <thead>
        <tr>
            <th>File Name</th>
            <th>File Size</th>
            <th>Upload Time</th>
        </tr>
    </thead>
    <tbody>
        <?php foreach ($suspiciousFiles as $file): ?>
        <tr>
            <td><?php echo $file['file_name']; ?></td>
            <td><?php echo $file['file_size']; ?></td>
            <td><?php echo $file['upload_time']; ?></td>
        </tr>
        <?php endforeach; ?>
    </tbody>
</table>