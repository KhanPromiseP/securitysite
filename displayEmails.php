<?php
include 'analyzeEmail.php';

$database = new Database();
$dbConnection = $database->getConnection();
$emailAnalyzer = new EmailAnalyzer($dbConnection);

$suspiciousEmails = $emailAnalyzer->getAllSuspiciousEmails();
?>

<table border="1">
    <thead>
        <tr>
            <th>Sender</th>
            <th>Recipient</th>
            <th>Subject</th>
            <th>Timestamp</th>
        </tr>
    </thead>
    <tbody>
        <?php foreach ($suspiciousEmails as $email): ?>
        <tr>
            <td><?php echo $email['sender']; ?></td>
            <td><?php echo $email['recipient']; ?></td>
            <td><?php echo $email['subject']; ?></td>
            <td><?php echo $email['timestamp']; ?></td>
        </tr>
        <?php endforeach; ?>
    </tbody>
</table>