<?php
include '../src/config/middleware.php';
SimpleMiddleware::requireLogin();
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Professional Security Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="css/styles.css">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.7.0/chart.min.js"></script>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script src="../views/onlineUsers.js"></script>
</head>

<body>
    <?php 
    include_once '../includes/header.php';
    include '../includes/navbar.php';
    ?>

    <div class="d-flex">
        <?php include '../includes/sidebar.php'; ?>
        
        <div class="flex-fill main-content p-4">
            <div class="container-fluid">
                <header class="mb-4">
                    <div style='height: 60px; radius: 10px' class="h2 bg-black text-center text-white flex-fill" role="banner">
                        Welcome, <span id="username"><?php echo htmlspecialchars($_SESSION['username']); ?></span>! Here’s an overview of your security status.
                    </div>
                </header>

                <!-- Info Cards -->
                <div class="row g-4" role="region" aria-label="Information Cards">
                    <div class="col-md-4">
                        <div class="card text-center bg-danger text-white" role="contentinfo" aria-label="Total Alerts">
                            <div class="card-body">
                                <h5 class="card-title">Total Alerts</h5>
                                <p class="display-4" aria-live="polite"><span id="alertCounter">0</span></p>
                                <p>New alerts today</p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="card text-center bg-warning text-dark" role="contentinfo" aria-label="Users Online">
                            <div class="card-body">
                                <h5 class="card-title">Users Online</h5>
                                <p class="display-4" aria-live="polite"><span id="deviceCount">0</span></p>
                                <p>Active connections</p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="card text-center bg-success text-white" role="contentinfo" aria-label="Threats Reported">
                            <div class="card-body">
                                <h5 class="card-title">Threats Reported</h5>
                                <p class="display-4" aria-live="polite"><span id="report-count">0</span></p>
                                <p>In the last week</p>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Network Traffic Overview -->
                <div class="card mt-4" role="region" aria-label="Network Traffic Overview">
                    <iframe src="../views/net_chart.html" class="w-100" style="height: 600px; border: none;" title="Network Traffic Overview"></iframe>
                </div>

                <!-- Website Traffic Overview -->
                <div class="card mt-4" role="region" aria-label="Website Traffic Overview">
                    <iframe src="../views/web_chart.html" class="w-100" style="height: 600px; border: none;" title="Website Traffic Overview"></iframe>
                </div>

                <!-- Real-Time Alerts Chart -->
                <div class="card mt-4" role="region" aria-label="Real-Time Alerts Chart">
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
</body>

</html>
