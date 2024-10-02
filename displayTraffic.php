<?php
include 'analyzeTraffic.php';

$database = new Database();
$dbConnection = $database->getConnection();
$trafficAnalyzer = new TrafficAnalyzer($dbConnection);

$suspiciousTraffic = $trafficAnalyzer->getAllTraffic();
?>

<table border="1">
    <thead>
        <tr>
            <th>Source IP</th>
            <th>Destination IP</th>
            <th>Packet Size</th>
            <th>Protocol</th>
            <th>Timestamp</th>
        </tr>
    </thead>
    <tbody>
        <?php foreach ($suspiciousTraffic as $traffic): ?>
        <tr>
            <td><?php echo $traffic['src_ip']; ?></td>
            <td><?php echo $traffic['dest_ip']; ?></td>
            <td><?php echo $traffic['packet_size']; ?></td>
            <td><?php echo $traffic['protocol']; ?></td>
            <td><?php echo $traffic['timestamp']; ?></td>
        </tr>
        <?php endforeach; ?>
    </tbody>
</table>