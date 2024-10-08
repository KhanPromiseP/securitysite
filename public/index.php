<?php
include_once '../includes/header.php';
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


    <style>

    </style>
</head>

<body class="container-fluid " style="align-items: center  justify-content: center">
    <?php  include '../includes/navbar.php';?>

    <div class="d-flex">
        <?php  include '../includes/sidebar.php';?>

        <!-- Main Content Area -->
        <div class=" flex-fill main-content">
            <header class=" d-flex justify-content-between align-items-center p-2 bg-light border-bottom">
                <h2 class="h4"><?php echo 'Welcome to the security app dashboard, ' . $_SESSION['username'] . '!'; ?>
                </h2>
            </header>

            <div class="container-fluid mt-2">
                <div class="row mb-2">
                    <div class="col-md-4">
                        <div class="card bg-danger text-white">
                            <div class="card-body">
                                <h5 class="card-title">Total Alerts</h5>
                                <p class="display-4">
                                    <span id="alertCounter">0</span>
                                </p>
                                <p class="text-white-50">New alerts today</p>
                            </div>
                        </div>
                    </div>

                    <div class="col-md-4">
                        <div class="card bg-warning border">
                            <div class="card-body">
                                <h5 class="card-title">Users Online</h5>
                                <p class="display-4">
                                    <span id="onlineUserCount">0</span>
                                </p>
                                <p class="text-muted">Active connections</p>
                            </div>
                        </div>
                    </div>

                    <div class="col-md-4">
                        <div class="card bg-success border">
                            <div class="card-body">
                                <h5 class="card-title">Threats Report </h5>
                                <p class="display-4">
                                    <span id="reportCount">0</span>
                                </p>
                                <p class="text-muted">In the last week</p>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Real-Time Monitoring Charts -->
                <div class="col-md-12">
                    <div class="card">
                        <!-- <div class="card-header">Real-Time Security Monitoring</div> -->
                        <div class="card-body">
                            <div id="chart-container">
                                <canvas id="alertsChart" width="400" height="200"></canvas>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="row mb-4">

                    <div class="col-md-12 mt-4">
                        <div class="card">
                            <div class="card-header">Network Traffic Overview</div>
                            <div class="card-body">
                                <iframe src="../views/displayTraffic.html"
                                    style="width: 100%; height: 600px; border: none;"></iframe>
                            </div>
                        </div>
                    </div>
                </div>


                <div class="row mt-2">
                    <div class="col-md-12">
                        <div class="card">
                            <!-- <div class="card-header">Suspicious IP Addresses</div> -->
                            <div class="card-body">
                                <div class="table-responsive">
                                    <?php include '../views/suspiciousIpDashboard.php';?>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Emails -->
                <div class="row mt-4">
                    <div class="col-md-12">
                        <div class="card">
                            <div class="card-header">Emails</div>
                            <div class="card-body">
                                <!-- Emails table is responsive -->
                                <div class="table-responsive">
                                    <?php include '../views/displayEmails.php';?>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

            </div>
        </div>
    </div>


    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js">
    </script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="../views/alertsChart.js"></script>
    <script src="../alertsChart.js"></script>
    <script src="../views/displayCountAlertsPerDay.js"></script>
    <script src="../views/reportStats.js"></script>

</body>

</html>