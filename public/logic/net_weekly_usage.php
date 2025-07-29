<?php
require_once '../../src/config/Database.php';

// Enable detailed error reporting for debugging
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Create a debug log function
function debug_log($message) {
    file_put_contents('persistent_api_debug.log', date('Y-m-d H:i:s').' - '.$message.PHP_EOL, FILE_APPEND);
}

$database = new Database();
$pdo = $database->getConnection();

if (!$pdo) {
    debug_log('Database connection failed');
    header('Content-Type: application/json');
    die(json_encode(['status' => 'error', 'message' => 'Database connection failed']));
}

/**
 * Enhanced user migration function with proper disconnected status handling
 */
function migrateAllActiveUsers($pdo) {
    try {
        debug_log('Starting combined user migration');
        
        // Get current week start (Sunday 00:00:00)
        $weekStart = $pdo->query("SELECT DATE_SUB(CURDATE(), INTERVAL WEEKDAY(CURDATE()) + 1 DAY)")->fetchColumn();
        
        // Get all active devices (latest record per MAC) with status check
        $activeUsers = $pdo->query("
            SELECT a.* FROM active_users_log a
            INNER JOIN (
                SELECT mac_address, MAX(last_seen) as max_last_seen
                FROM active_users_log
                WHERE status = 'connected'  -- Only consider connected users
                GROUP BY mac_address
            ) b ON a.mac_address = b.mac_address AND a.last_seen = b.max_last_seen
            WHERE a.status = 'connected'  -- Ensure we only get connected users
        ")->fetchAll(PDO::FETCH_ASSOC);

        // Get all disconnected users (for proper offline marking)
        $disconnectedUsers = $pdo->query("
            SELECT mac_address FROM active_users_log
            WHERE status = 'disconnected'
            GROUP BY mac_address
        ")->fetchAll(PDO::FETCH_COLUMN);

        // First, mark all users not in active_users_log OR with disconnected status as offline
        $inactive = $pdo->exec("
            UPDATE user_history 
            SET is_active = FALSE 
            WHERE (
                mac_address NOT IN (
                    SELECT DISTINCT mac_address FROM active_users_log
                    WHERE status = 'connected'
                )
                OR mac_address IN (
                    SELECT mac_address FROM active_users_log
                    WHERE status = 'disconnected'
                    GROUP BY mac_address
                )
            ) AND is_active = TRUE
        ");
        debug_log("Marked $inactive users as inactive");

        if (empty($activeUsers)) {
            debug_log('No active users to migrate');
            return ['inserted' => 0, 'updated' => 0, 'inactive' => $inactive];
        }

        $inserted = 0;
        $updated = 0;
        
        foreach ($activeUsers as $user) {
            try {
                // Skip if user is disconnected (shouldn't happen due to query, but safety check)
                if ($user['status'] === 'disconnected') {
                    debug_log("Skipping disconnected user: ".$user['mac_address']);
                    continue;
                }

                debug_log("Processing user: ".$user['mac_address']);
                
                // Check if user exists in history
                $history = $pdo->prepare("
                    SELECT id, current_week_data_mb, total_data_mb, last_seen 
                    FROM user_history 
                    WHERE mac_address = ?
                ");
                $history->execute([$user['mac_address']]);
                $existing = $history->fetch();
                
                if ($existing) {
                    // Check if we're in a new week since last update
                    $isNewWeek = (strtotime($existing['last_seen']) < strtotime($weekStart));
                    
                    // For existing user, sum the current data with existing data
                    $newWeeklyTotal = $isNewWeek ? $user['data_usage_mb'] : ($user['data_usage_mb']);
                    $dataToAdd = $user['data_usage_mb'];
                    
                    $pdo->prepare("
                        UPDATE user_history SET
                            ip_address = ?,
                            hostname = COALESCE(?, hostname),
                            last_seen = ?,
                            current_week_data_mb = ?,
                            total_data_mb = total_data_mb + ?,
                            is_active = TRUE
                        WHERE mac_address = ?
                    ")->execute([
                        $user['ip_address'],
                        $user['hostname'],
                        $user['last_seen'],
                        $newWeeklyTotal,
                        $dataToAdd,
                        $user['mac_address']
                    ]);
                    $updated++;
                    
                    debug_log("Updated user: ".$user['mac_address']." (Week: {$newWeeklyTotal}MB, Added: {$dataToAdd}MB)");
                } else {
                    // Insert new user
                    $pdo->prepare("
                        INSERT INTO user_history (
                            mac_address, ip_address, hostname,
                            first_seen, last_seen,
                            total_data_mb, current_week_data_mb, is_active
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, TRUE)
                    ")->execute([
                        $user['mac_address'],
                        $user['ip_address'],
                        $user['hostname'],
                        $user['last_seen'],
                        $user['last_seen'],
                        $user['data_usage_mb'],
                        $user['data_usage_mb']
                    ]);
                    $inserted++;
                    debug_log("New user added: ".$user['mac_address']);
                }
            } catch (PDOException $e) {
                debug_log("Error processing ".$user['mac_address'].": ".$e->getMessage());
            }
        }
        
        return [
            'inserted' => $inserted,
            'updated' => $updated,
            'inactive' => $inactive
        ];
        
    } catch (PDOException $e) {
        debug_log("Migration error: " . $e->getMessage());
        throw $e;
    }
}

/**
 * Get current user data for frontend with proper status filtering
 */
function getCurrentUserData($pdo) {
    $users = $pdo->query("
        SELECT uh.*, 
            CASE WHEN uh.first_seen > NOW() - INTERVAL 1 WEEK THEN 'new' ELSE 'existing' END as user_type,
            COALESCE(aul.status, 'disconnected') as current_status
        FROM user_history uh
        LEFT JOIN (
            SELECT mac_address, status 
            FROM active_users_log 
            WHERE (mac_address, last_seen) IN (
                SELECT mac_address, MAX(last_seen) 
                FROM active_users_log 
                GROUP BY mac_address
            )
        ) aul ON uh.mac_address = aul.mac_address
        ORDER BY uh.last_seen DESC
    ")->fetchAll(PDO::FETCH_ASSOC);
    
    $stats = $pdo->query("
        SELECT 
            COUNT(*) as total_users,
            SUM(CASE WHEN is_active = TRUE THEN 1 ELSE 0 END) as active_users,
            SUM(CASE WHEN is_active = TRUE THEN current_week_data_mb ELSE 0 END) as week_usage_mb,
            SUM(total_data_mb) as total_usage_mb
        FROM user_history
    ")->fetch(PDO::FETCH_ASSOC);
    
    return [
        'users' => $users,
        'stats' => $stats,
        'timestamp' => date('Y-m-d H:i:s')
    ];
}

// Main execution - handle both AJAX and direct calls
try {
    // First run the migration
    $migrationResult = migrateAllActiveUsers($pdo);
    
    // Then get current data
    $userData = getCurrentUserData($pdo);
    
    // Combine results
    $response = [
        'status' => 'success',
        'migration' => $migrationResult,
        'data' => $userData
    ];
    
    // Return JSON response
    header('Content-Type: application/json');
    echo json_encode($response);
    
} catch (PDOException $e) {
    debug_log("API Error: " . $e->getMessage());
    header('Content-Type: application/json');
    echo json_encode([
        'status' => 'error',
        'message' => $e->getMessage()
    ]);
}
?>