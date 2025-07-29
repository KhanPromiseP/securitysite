<!DOCTYPE html>
<html lang="en">
<head>
    <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png">
    <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32.png">
    <link rel="icon" type="image/png" sizes="16x16" href="/favicon-16x16.png">
    <link rel="manifest" href="/site.webmanifest">

    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Professional Security Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.7.0/chart.min.js"></script>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
   
   <style>
    /* Card Styling - Unified Whitish Background with Borders */
    .card {
        background-color: #f8f9fa; /* Whitish background */
        border: 1px solid #e0e0e0; /* Light gray border */
        border-radius: 8px;
        box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
        transition: all 0.3s ease;
        margin-bottom: 20px;
        overflow: hidden; /* Ensures border-radius works properly */
    }

    /* Card hover effect */
    .card:hover {
        box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
        transform: translateY(-3px);
    }

    /* Card body padding */
    .card-body {
        padding: 1.25rem;
    }

    /* Card title styling */
    .card-title {
        font-size: 1rem;
        font-weight: 600;
        margin-bottom: 0.75rem;
        color: #333;
    }

    /* Display numbers styling */
    .display-4 {
        font-size: 2rem;
        font-weight: 700;
        margin-bottom: 0.5rem;
        color: #333;
    }

    /* Card text styling */
    .card-text {
        font-size: 0.9rem;
        color: #666;
        margin-bottom: 0;
    }

    /* Special status cards - keep their colors but with whitish background */
    .bg-danger {
        background-color: #f8d7da !important; /* Light red background */
        border-left: 4px solid #dc3545 !important; /* Red accent border */
    }

    .bg-warning {
        background-color: #fff3cd !important; /* Light yellow background */
        border-left: 4px solid #ffc107 !important; /* Yellow accent border */
    }

    .bg-success {
        background-color: #d4edda !important; /* Light green background */
        border-left: 4px solid #28a745 !important; /* Green accent border */
    }

    .bg-white {
        background-color: #ffffff !important; /* Pure white */
        border-left: 4px solid #dee2e6 !important; /* Gray accent border */
    }

    /* Responsive adjustments */
    @media (max-width: 768px) {
        .card {
            margin-bottom: 15px;
        }
        .card-body {
            padding: 1rem;
        }
        .display-4 {
            font-size: 1.75rem;
        }
    }
</style>
</head>

<body>
    <?php 
    include_once '../includes/header.php';
    include '../includes/navbar.php';
    ?>

    <div class="d-flex">
        <?php include '../includes/sidebar.php'; ?>
        
        <div class="flex-fill main-content p-1">
            <div class="container-fluid">
                <header class="mb-2">
                    <div style='height: 40px; radius: 10px' class="h2 bg-black text-center text-white flex-fill" role="banner">
                        Welcome, <span id="username"><?php echo htmlspecialchars($_SESSION['username']); ?></span>! Here's an overview of your security status.
                    </div>
                </header>

                <div class="row g-2" role="region" aria-label="Information Cards">
                    <div class="col-md-3">
                        <div class="card text-center  text-white" role="contentinfo" aria-label="Total Data Used">
                            <div class="card-body">
                                <h5 class="card-title">Total Data Used</h5>
                                <p class="display-4" aria-live="polite"><span id="totalUsage">0.00 MB</span></p>
                                <p class="card-text">For the passed weeks</p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card text-center  text-white" role="contentinfo" aria-label="Weekly Data Used">
                            <div class="card-body">
                                <h5 class="card-title">Weekly Data Used</h5>
                                <p class="display-4" aria-live="polite"><span id="weekUsage">0.00 MB</span></p>
                                <p class="card-text">In the last week</p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card text-center  text-white" role="contentinfo" aria-label="Total Alerts">
                            <div class="card-body">
                                <h5 class="card-title">Total Alerts</h5>
                                <p class="display-4" aria-live="polite"><span id="alertCounter">0</span></p>
                                <p class="card-text">In the last week</p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card text-center text-dark" role="contentinfo" aria-label="Users Online">
                            <div class="card-body">
                                <h5 class="card-title">Users Online</h5>
                                <p class="display-4" aria-live="polite"><span id="device-count">0</span></p>
                                <p class="card-text">Active connections</p>
                            </div>
                        </div>
                    </div>
                   <div class="col-md-3">
                        <div class="card text-center  text-dark" role="contentinfo" aria-label="Highest Usage">
                            <div class="card-body">
                                <h5 class="card-title">Current Highest</h5>
                                <p class="display-4" aria-live="polite"><span id="highest-usage">0 MB</span></p>
                                <p class="card-text">Data usage per user</p>
                            </div>
                        </div>
                    </div>

                    <div class="col-md-3">
                        <div class="card text-center text-white" role="contentinfo" aria-label="Total Users">
                            <div class="card-body">
                                <h5 class="card-title">Total Users</h5>
                                <p class="display-4" aria-live="polite"><span id="total-users">0</span></p>
                                <p class="card-text">In the last week</p>
                            </div>
                        </div>
                    </div>

                <div class="col-md-3">
                    <div class="card text-center  text-white" role="contentinfo" aria-label="Total Users">
                        <div class="card-body">
                            <h5 class="card-title">Total Number</h5>
                            <p class="display-4" aria-live="polite"><?php echo $totalUsers; ?>2</p>
                            <p class="card-text">Of System users</p>
                        </div>
                    </div>
                </div>

                    <div class="col-md-3">
                        <div class="card text-center text-white" role="contentinfo" aria-label="Threats Reported">
                            <div class="card-body">
                                <h5 class="card-title">Threats Reported</h5>
                                <p class="display-4" aria-live="polite"><span id="report-count">0</span></p>
                                <p class="card-text">In the last week</p>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Network Traffic Overview -->
                <div class="card mt-2" role="region" aria-label="Network Traffic Overview">
                    <iframe src="../views/net_chart.html" class="w-100" style="height: 600px; border: none;" title="Network Traffic Overview"></iframe>
                </div>

                <!-- Website Traffic Overview -->
                <div class="card mt-2" role="region" aria-label="Website Traffic Overview">
                    <iframe src="../views/web_chart.html" class="w-100" style="height: 600px; border: none;" title="Website Traffic Overview"></iframe>
                </div>

                <!-- Real-Time Alerts Chart -->
                <div class="card mt-2" role="region" aria-label="Real-Time Alerts Chart">
                    <canvas style="background-color: #1c1c29; max-height: 500px" id="alertsChart" role="img" aria-label="Real-Time Alerts Data Visualization"></canvas> 
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="../views/alertsChart.js"></script>
    <script src="../views/displayCountAlertsPerDay.js"></script>
    <script src="../views/reportStats.js"></script>
    <script src="../views/active_device_count..js"></script>


    <script>
$(document).ready(function() {
    // Function to fetch and update dashboard stats
    function updateDashboardStats() {
        $.ajax({
            url: '../logic/net_weekly_usage.php', 
            type: 'GET',
            dataType: 'json',
            success: function(response) {
                console.log('API Response:', response); // Debugging
                
                if (response.status === 'success') {
                    // Update total users count
                    $('#total-users').text(response.data.stats.total_users || '0');
                    
                    // Calculate and display highest usage
                    if (response.data.users && response.data.users.length > 0) {
                        let highestUsage = 0;
                        response.data.users.forEach(user => {
                            if (user.current_week_data_mb > highestUsage) {
                                highestUsage = user.current_week_data_mb;
                            }
                        });
                        $('#highest-usage').text(highestUsage.toFixed(2) + ' MB');
                    } else {
                        $('#highest-usage').text('0.00 MB');
                    }
                    
                    // Update other stats if available
                    if (response.data.stats.week_usage_mb !== undefined) {
                        $('#weekUsage').text(response.data.stats.week_usage_mb.toFixed(2) + ' MB');
                    }
                    if (response.data.stats.total_usage_mb !== undefined) {
                        $('#totalUsage').text(response.data.stats.total_usage_mb.toFixed(2) + ' MB');
                    }
                    if (response.data.stats.active_users !== undefined) {
                        $('#device-count').text(response.data.stats.active_users);
                    }
                }
            },
            error: function(xhr, status, error) {
                console.error('Error fetching stats:', error);
                // Fallback values if API fails
                $('#total-users').text('0');
                $('#highest-usage').text('0.00 MB');
            }
        });
    }

    // Initial load
    updateDashboardStats();
    
    // Refresh every 30 seconds
    setInterval(updateDashboardStats, 30000);
});
</script>
    
    <script>
    $(document).ready(function() {
        // Function to fetch and update stats
        function updateStats() {
            $.ajax({
                url: '../logic/net_weekly_usage.php',
                type: 'GET',
                dataType: 'json',
                success: function(response) {
                    console.log('Stats response:', response); // Debugging
                    if (response.status === 'success') {
                        // Update weekly and total usage
                        $('#weekUsage').text((response.data.stats.week_usage_mb || 0).toFixed(2) + ' MB');
                        $('#totalUsage').text((response.data.stats.total_usage_mb || 0).toFixed(2) + ' MB');
                        
                        // Update active users count if available
                        if (response.data.stats.active_users !== undefined) {
                            $('#device-count').text(response.data.stats.active_users);
                        }
                    }
                },
                error: function(xhr) {
                    console.error('Error loading stats:', xhr.responseText);
                }
            });
        }

        // Initial load
        updateStats();
        
        // Refresh every 30 seconds
        setInterval(updateStats, 30000);
    });
    </script>
</body>
</html>