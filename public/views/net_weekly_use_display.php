<?php 
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

if (!isset($_SESSION['user_id'])) {
    header('Location: ./login.php');
    exit();
}

include __DIR__ . '/../../includes/header.php';
include __DIR__ . '/../../includes/sidebar.php';
include __DIR__ . '/../../includes/navbar.php';




// Generate CSRF token if it doesn't exist
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Debug output (remove after testing)
error_log("CSRF Token: ".$_SESSION['csrf_token']);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Users Dashboard</title>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f4f4;
            margin: 0;
            padding: 70px 0 0 0;
        }

        .main-content {
            padding: 20px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            font-size: 1em;
            box-shadow: 0 0 20px rgba(0, 0, 0, 0.15);
        }

        th, td {
            padding: 12px 15px;
            text-align: left;
            border: 1px solid #ddd;
        }

        th {
            background-color: #009879;
            color: #ffffff;
        }

        tr:nth-child(even) {
            background-color: #f3f3f3;
        }

        tr:nth-child(odd) {
            background-color: #ffffff;
        }

        .status-badge {
            padding: 5px 10px;
            border-radius: 5px;
            color: white;
            font-weight: bold;
        }

        .status-online {
            background-color: #28a745;
        }

        .status-offline {
            background-color: #6c757d;
        }

        .user-new {
            background-color: #e7f5ff;
        }

        .action-btn {
            padding: 5px 10px;
            cursor: pointer;
            color: white;
            border: none;
            border-radius: 5px;
            margin-right: 5px;
        }

        .limit-btn {
            background-color: #007bff;
        }

        .throttle-btn {
            background-color: #ffc107;
        }

        .reset-btn {
            background-color: #17a2b8;
        }

        .progress-container {
        width: 100%;
        background-color: #e9ecef;
        border-radius: 5px;
        height: 20px;
        position: relative;
        }

        .progress-bar {
            height: 100%;
            border-radius: 5px;
            background-color: #28a745;
            position: absolute;
            top: 0;
            left: 0;
        }
        
        .progress-text {
            position: absolute;
            width: 100%;
            text-align: center;
            line-height: 20px;
            color: #000;
            z-index: 1;
        }

        .is-invalid {
            border-color: #dc3545;
        }

        .invalid-feedback {
            color: #dc3545;
            font-size: 0.875em;
            display: none;
        }

        .toast {
            position: fixed;
            bottom: 20px;
            right: 20px;
            z-index: 9999;
        }

        @media (max-width: 768px) {
            body {
                padding: 20px 0 0 0;
            }

            table {
                font-size: 0.9em;
            }
        }
    </style>
</head>

<body>
    <div class="d-flex">
        <?php include '../../includes/sidebar.php'; ?>
        <div class="row flex-fill main-content" style="height:90vh">
            <div class="row mt-2">
                <div class="col-md-8">
                    <div class="card">
                        <div class="card-body">
                            <div class="table-responsive">
                                <h1>Network Users</h1>
                                <table id="users-table">
                                    <thead>
                                        <tr>
                                            <th>IP Address</th>
                                            <th>MAC Address</th>
                                            <th>Hostname</th>
                                            <th>Status</th>
                                            <th>This Week</th>
                                            <th>Total</th>
                                            <th>First Seen</th>
                                            <th>Last Seen</th>
                                            <th>Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <!-- Table content populated by AJAX -->
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card mb-3">
                        <div class="card-header">
                            <h5>Network Summary</h5>
                        </div>
                        <div class="card-body">
                            <div class="row mb-3">
                                <div class="col-6">
                                    <div class="card bg-light">
                                        <div class="card-body text-center">
                                            <h4 id="weekUsage">0</h4>
                                            <small class="text-muted">This Week</small>
                                        </div>
                                    </div>
                                </div>
                                <div class="col-6">
                                    <div class="card bg-light">
                                        <div class="card-body text-center">
                                            <h4 id="totalUsage">0</h4>
                                            <small class="text-muted">All Time</small>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <div class="alert alert-info">
                                Next reset: <span id="nextReset">Sunday</span>
                            </div>
                        </div>
                    </div>
                    <div class="card">
                        <div class="card-header">
                            <h5>User Activity</h5>
                        </div>
                        <div class="card-body">
                            <canvas id="activityChart" height="200"></canvas>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Data Limit Modal -->
    <div class="modal fade" id="dataLimitModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Set Data Limit</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <input type="hidden" id="currentMac">
                    <div class="mb-3">
                        <label class="form-label">Data Limit (MB)</label>
                        <input type="number" class="form-control" id="dataLimitInput" min="1" required>
                        <div class="invalid-feedback">Please enter a valid data limit (minimum 1MB)</div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="button" class="btn btn-primary" id="saveLimitBtn">Save</button>
                </div>
            </div>
        </div>
    </div>

    <script>
        let activityChart;
        let currentMac = '';
        let refreshInterval = 5000; // 5 seconds
        let refreshTimer;

        $(document).ready(function() {
            // Initialize chart
            initActivityChart();
            
            // Initialize modal
            const dataLimitModal = new bootstrap.Modal(document.getElementById('dataLimitModal'));
            
            // Set up modal handlers
            $('#dataLimitModal').on('shown.bs.modal', function() {
                $('#dataLimitInput').trigger('focus');
            });
            
            // Save limit button handler
           $('#saveLimitBtn').click(function() {
                const csrfToken = '<?php echo $_SESSION['csrf_token']; ?>';
                console.log("Sending CSRF Token:", csrfToken); // Debug
                
                const limitInput = $('#dataLimitInput');
                const limit = limitInput.val();
                const mac = $('#currentMac').val(); // This is the correct way to get the MAC
                
                // Debug: Log the MAC address being sent
                console.log("MAC Address being sent:", mac);
                
                // Validate input
                if (!limit || isNaN(limit) || parseInt(limit) < 1) {
                    limitInput.addClass('is-invalid');
                    limitInput.next('.invalid-feedback').show();
                    return;
                }
                
                // Validate MAC address
                if (!mac) {
                    showToast('MAC address is required', 'danger');
                    return;
                }
                
                // Clear validation
                limitInput.removeClass('is-invalid');
                limitInput.next('.invalid-feedback').hide();
                
                // Show loading state
                const saveBtn = $(this);
                saveBtn.prop('disabled', true).html('<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Saving...');
                
                // Send AJAX request
                $.ajax({
                    url: '../logic/set_user_limit.php',
                    type: 'POST',
                    dataType: 'json',
                    data: {
                        mac: mac,  // Use the variable we already defined
                        limit: limit,
                        csrf_token: csrfToken
                    },
                    success: function(response) {
                        try {
                            const result = typeof response === 'string' ? JSON.parse(response) : response;
                            if (result.success) {
                                dataLimitModal.hide();
                                showToast('Limit set successfully', 'success');
                                fetchNetworkUsers(); // Refresh data
                            } else {
                                showToast(result.message || 'Error setting limit', 'danger');
                            }
                        } catch (e) {
                            console.error('Error parsing response:', e);
                            showToast('Error processing response', 'danger');
                        }
                    },
                    error: function(xhr) {
                        console.error('Error:', xhr.responseText);
                        showToast('Error setting limit: ' + (xhr.responseJSON?.message || xhr.statusText), 'danger');
                    },
                    complete: function() {
                        saveBtn.prop('disabled', false).text('Save');
                    }
                });
            });
            
            // Initial fetch
            fetchNetworkUsers();
            
            // Set up periodic refresh
            refreshTimer = setInterval(fetchNetworkUsers, refreshInterval);
        });

        function fetchNetworkUsers() {
            $.ajax({
                url: '../logic/net_weekly_usage.php', 
                type: 'GET',
                dataType: 'json',
                success: function(response) {
                    if (response.status === 'success') {
                        renderUsersTable(response.data.users);
                        renderStats(response.data.stats);
                        updateActivityChart(response.data.users);
                    } else {
                        console.error('Error:', response.message);
                        showToast('Error loading data: ' + response.message, 'danger');
                    }
                },
                error: function(xhr) {
                    console.error('AJAX error:', xhr.responseText);
                    showToast('Error loading network data', 'danger');
                    // Attempt to reconnect after a delay
                    clearInterval(refreshTimer);
                    setTimeout(function() {
                        fetchNetworkUsers();
                        refreshTimer = setInterval(fetchNetworkUsers, refreshInterval);
                    }, 10000); // Retry after 10 seconds
                }
            });
        }
        
        function renderUsersTable(users) {
            const tableBody = $('#users-table tbody');
            tableBody.empty();
            
            if (!users || users.length === 0) {
                tableBody.append('<tr><td colspan="9" class="text-center">No users found</td></tr>');
                return;
            }
            
            users.forEach(user => {
                const isNew = new Date(user.first_seen) > new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
                const statusClass = user.is_active ? 'status-online' : 'status-offline';
                const statusText = user.is_active ? 'Online' : 'Offline';
                const usagePercent = Math.min(100, (user.current_week_data_mb / (user.data_limit_mb || 1000)) * 100);
                
                const row = `
                    <tr class="${isNew ? 'user-new' : ''}">
                        <td>${user.ip_address || 'N/A'}</td>
                        <td>${user.mac_address || 'N/A'}</td>
                        <td>${user.hostname || 'Unknown'}</td>
                        <td><span class="status-badge ${statusClass}">${statusText}</span></td>
                        <td>
                            <div class="progress-container">
                                <div class="progress-bar" style="width: ${usagePercent}%"></div>
                                <div class="progress-text">
                                    ${user.current_week_data_mb?.toFixed(2) || '0'} MB
                                </div>
                            </div>
                        </td>
                        <td>${user.total_data_mb?.toFixed(2) || '0'} MB</td>
                        <td>${new Date(user.first_seen).toLocaleDateString()}</td>
                        <td>${new Date(user.last_seen).toLocaleString()}</td>
                        <td>
                            <button class="action-btn limit-btn" 
                                    onclick="showLimitModal('${user.mac_address}', ${user.data_limit_mb || 0})">
                                Set Limit
                            </button>
                            ${user.is_throttled ? `
                            <button class="action-btn reset-btn" 
                                    onclick="resetThrottle('${user.mac_address}')">
                                Unthrottle
                            </button>
                            ` : ''}
                        </td>
                    </tr>
                `;
                tableBody.append(row);
            });
        }
        
        function renderStats(stats) {
            $('#weekUsage').text(`${stats.week_usage_mb?.toFixed(2) || '0'} MB`);
            $('#totalUsage').text(`${stats.total_usage_mb?.toFixed(2) || '0'} MB`);
            
            // Calculate next reset (next Sunday)
            const today = new Date();
            const nextSunday = new Date(
                today.setDate(today.getDate() + (7 - today.getDay()))
            );
            $('#nextReset').text(nextSunday.toLocaleDateString());
        }
        
        function initActivityChart() {
            const ctx = document.getElementById('activityChart').getContext('2d');
            activityChart = new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: ['Online', 'Offline', 'New This Week'],
                    datasets: [{
                        data: [0, 0, 0],
                        backgroundColor: [
                            '#28a745',
                            '#6c757d',
                            '#17a2b8'
                        ],
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { 
                            position: 'bottom',
                            labels: {
                                padding: 20,
                                usePointStyle: true
                            }
                        }
                    }
                }
            });
        }
        
        function updateActivityChart(users) {
            const online = users.filter(u => u.is_active).length;
            const offline = users.filter(u => !u.is_active).length;
            const newUsers = users.filter(u => new Date(u.first_seen) > new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)).length;
            
            activityChart.data.datasets[0].data = [online, offline, newUsers];
            activityChart.update();
        }
        
        function showLimitModal(mac, currentLimit) {
            currentMac = mac;
            $('#currentMac').val(mac); // This sets the value in the hidden input
            const limitInput = $('#dataLimitInput');
            limitInput.val(currentLimit || '');
            limitInput.removeClass('is-invalid');
            limitInput.next('.invalid-feedback').hide();
            
            const modal = bootstrap.Modal.getInstance(document.getElementById('dataLimitModal')) || 
                        new bootstrap.Modal(document.getElementById('dataLimitModal'));
            modal.show();
        }
                
        function resetThrottle(mac) {
    if (confirm('Are you sure you want to remove throttling for this user?')) {
        // Get the current CSRF token from the session
        const csrfToken = '<?php echo $_SESSION['csrf_token']; ?>';
        
        // Debug output
        console.log("Resetting throttle for MAC:", mac);
        console.log("Using CSRF Token:", csrfToken);

        $.ajax({
            url: '../logic/reset_throttle.php',
            type: 'POST',
            dataType: 'json',
            data: { 
                mac: mac,
                csrf_token: csrfToken  // Make sure this matches what your PHP expects
            },
            success: function(response) {
                try {
                    const result = typeof response === 'string' ? JSON.parse(response) : response;
                    if (result.success) {
                        showToast('Throttle reset successfully', 'success');
                        fetchNetworkUsers();
                    } else {
                        showToast(result.message || 'Error resetting throttle', 'danger');
                    }
                } catch (e) {
                    console.error('Error parsing response:', e);
                    showToast('Error processing response', 'danger');
                }
            },
            error: function(xhr) {
                console.error('Error:', xhr.responseText);
                showToast('Error resetting throttle: ' + (xhr.responseJSON?.message || xhr.statusText), 'danger');
            }
        });
    }
}
        
        function showToast(message, type = 'success') {
            // Remove any existing toasts
            $('.toast').remove();
            
            // Create toast HTML
            const toast = $(`
                <div class="toast align-items-center text-white bg-${type} border-0" role="alert" aria-live="assertive" aria-atomic="true">
                    <div class="d-flex">
                        <div class="toast-body">
                            ${message}
                        </div>
                        <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
                    </div>
                </div>
            `);
            
            // Add to DOM and show
            $('body').append(toast);
            const bsToast = new bootstrap.Toast(toast[0]);
            bsToast.show();
            
            // Auto-hide after 5 seconds
            setTimeout(() => toast.remove(), 5000);
        }
    </script>
</body>
</html>