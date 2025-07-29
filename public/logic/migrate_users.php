<?php
require_once '../../src/config/Database.php';

$database = new Database();
$pdo = $database->getConnection();

if (!$pdo) {
    die("Database connection failed\n");
}

function migrateAllUsers($pdo) {
    // Get current week start (Sunday 00:00:00)
    $weekStart = $pdo->query("SELECT DATE_SUB(CURDATE(), INTERVAL WEEKDAY(CURDATE()) + 1 DAY)")->fetchColumn();
    
    // Get all active devices (latest record per MAC)
    $devices = $pdo->query("
        SELECT a.mac_address, a.ip_address, a.hostname, 
               a.data_usage_mb, a.last_seen
        FROM active_users_log a
        INNER JOIN (
            SELECT mac_address, MAX(last_seen) as max_last_seen
            FROM active_users_log
            GROUP BY mac_address
        ) b ON a.mac_address = b.mac_address AND a.last_seen = b.max_last_seen
    ")->fetchAll(PDO::FETCH_ASSOC);

    if (empty($devices)) {
        echo "No active devices found\n";
        return;
    }

    $pdo->beginTransaction();
    
    try {
        $inserted = 0;
        $updated = 0;
        
        foreach ($devices as $device) {
            // Check if user exists in history
            $history = $pdo->prepare("
                SELECT id, current_week_data_mb, total_data_mb, last_seen 
                FROM user_history 
                WHERE mac_address = ?
            ");
            $history->execute([$device['mac_address']]);
            $existing = $history->fetch();
            
            if ($existing) {
                // Check if we're in a new week since last update
                $isNewWeek = (strtotime($existing['last_seen']) < strtotime($weekStart));
                
                // Always use the full current data_usage_mb from active log
                // (assuming active_users_log contains cumulative data for the session)
                $currentUsage = $device['data_usage_mb'];
                
                // For same week, we want to store the current active log value directly
                // since it represents the cumulative usage for the week
                $newWeeklyTotal = $currentUsage;
                
                // Calculate what to add to the total (only for new week)
                $dataToAdd = $isNewWeek ? $currentUsage : 0;
                
                $stmt = $pdo->prepare("
                    UPDATE user_history SET
                        ip_address = ?,
                        hostname = COALESCE(?, hostname),
                        last_seen = ?,
                        current_week_data_mb = ?,
                        total_data_mb = total_data_mb + ?,
                        is_active = TRUE
                    WHERE mac_address = ?
                ");
                
                $stmt->execute([
                    $device['ip_address'],
                    $device['hostname'],
                    $device['last_seen'],
                    $newWeeklyTotal,
                    $dataToAdd,
                    $device['mac_address']
                ]);
                $updated++;
                
                echo "Updated existing user: {$device['mac_address']} (Week: {$newWeeklyTotal}MB, Added: {$dataToAdd}MB)\n";
            } else {
                // New user - insert fresh record
                $stmt = $pdo->prepare("
                    INSERT INTO user_history (
                        mac_address, ip_address, hostname,
                        first_seen, last_seen,
                        total_data_mb, current_week_data_mb, is_active
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, TRUE)
                ");
                $stmt->execute([
                    $device['mac_address'],
                    $device['ip_address'],
                    $device['hostname'],
                    $device['last_seen'],
                    $device['last_seen'],
                    $device['data_usage_mb'],
                    $device['data_usage_mb']
                ]);
                $inserted++;
                
                echo "Added new user: {$device['mac_address']}\n";
            }
        }
        
        // Mark inactive users
        $inactive = $pdo->exec("
            UPDATE user_history 
            SET is_active = FALSE 
            WHERE mac_address NOT IN (
                SELECT mac_address FROM active_users_log
            ) AND is_active = TRUE
        ");
        
        echo "Marked $inactive users as inactive\n";
        
        $pdo->commit();
        echo "Migration complete. Inserted: $inserted, Updated: $updated\n";
        
    } catch (PDOException $e) {
        $pdo->rollBack();
        echo "Migration failed: " . $e->getMessage() . "\n";
    }
}

migrateAllUsers($pdo);
?>