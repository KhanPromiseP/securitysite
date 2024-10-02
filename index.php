<?php
include './src/config/middleware.php';
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
    <script src="onlineUsers.js"></script>
    <script src="reportStats.js"></script>

    <style>
    /* Sidebar Styling */
    .sidebar {
        width: 200px;
        height: 100vh;
        position: fixed;
        top: 0;
        left: 0;
        padding: 10px;
        background-color: #343a40;
        color: white;
    }

    .sidebar .nav-link {
        padding: 15px;
        font-size: 18px;
        transition: background-color 0.3s ease;
    }

    .sidebar .nav-link.active,
    .sidebar .nav-link:hover {
        background-color: #007bff;
        border-radius: 8px;
    }

    .main-content {
        margin-left: 250px;
        padding: 20px;
        background-color: #f8f9fa;
        height: 100vh;
        overflow-y: auto;
    }

    /* Table Styles */
    .table-hover tbody tr:hover {
        background-color: #f1f3f5;
    }

    .card-header {
        background-color: #007bff;
        color: white;
        padding: 15px;
        font-size: 18px;
    }

    .card-body {
        padding: 20px;
    }

    /* Responsive Design */
    @media (max-width: 992px) {
        .main-content {
            margin-left: 0;
        }

        .sidebar {
            position: static;
            width: 100%;
            height: auto;
        }
    }

    @media (max-width: 576px) {
        .main-content {
            padding: 10px;
        }

        .sidebar .nav-link {
            padding: 10px;
            font-size: 16px;
        }

        .card .card-body {
            padding: 15px;
        }
    }

    /* Highlight links and buttons */
    a.nav-link.active {
        background-color: #0056b3;
        color: #ffffff !important;
    }

    button:focus {
        outline: none;
        box-shadow: 0 0 5px #007bff;
    }

    /*some ther styls */
    /* Ensure that the main content and sidebar adjust properly on small screens */
    @media (max-width: 768px) {
        .sidebar {
            width: 100%;
            height: auto;
            position: relative;
        }

        .main-content {
            margin-left: 0;
        }

        /* Reduce padding and adjust font size for smaller screens */
        .sidebar .nav-link {
            padding: 10px;
            font-size: 16px;
        }

        .navbar-brand {
            font-size: 18px;
        }

        .navbar-nav .nav-link {
            font-size: 16px;
        }
    }

    /* For larger screens, ensure proper spacing and alignment */
    @media (min-width: 769px) {
        .main-content {
            margin-left: 250px;
        }

        .sidebar {
            width: 200px;
            height: 100vh;
        }

        .navbar-brand {
            font-size: 22px;
        }

        .navbar-nav .nav-link {
            font-size: 18px;
        }
    }

    /* Ensure buttons and links remain highlighted on focus/click */
    .nav-link:focus,
    .nav-link:active {
        background-color: #0056b3 !important;
        color: #fff !important;
        border-radius: 8px;
    }

    .btn-primary:focus,
    .btn-primary:active {
        background-color: #0056b3 !important;
        border-color: #0056b3 !important;
    }
    </style>
</head>

<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container-fluid">
            <a class="navbar-brand" href="#">MyApp</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav"
                aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav me-auto mb-2 mb-lg-0">
                    <li class="nav-item">
                        <a class="nav-link active" aria-current="page" href="#">Dashboard</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#">Projects</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#">Tasks</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#">Reports</a>
                    </li>
                </ul>
                <form class="d-flex" role="search">
                    <input class="form-control me-2" type="search" placeholder="Search" aria-label="Search">
                    <button class="btn btn-outline-success" type="submit">Search</button>
                </form>
                <ul class="navbar-nav ml-auto">
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle" href="#" id="userDropdown" role="button"
                            data-bs-toggle="dropdown" aria-expanded="false">
                            <i class="bi bi-person-circle"></i> User
                        </a>
                        <ul class="dropdown-menu dropdown-menu-end" aria-labelledby="userDropdown">
                            <li><a class="dropdown-item" href="#">Profile</a></li>
                            <li><a class="dropdown-item" href="#">Settings</a></li>
                            <li>
                                <hr class="dropdown-divider">
                            </li>
                            <li><a class="dropdown-item" href="src/config/logout.php">Logout</a></li>
                        </ul>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

    <!-- Sidebar Navigation -->
    <div class="d-flex">
        <nav class="bg-dark sidebar">
            <div class="p-3">
                <img src="assets/icons/logo.png" alt="Company Logo" class="img-fluid mb-3">
                <h3 class="text-white">Security Dashboard</h3>
                <ul class="nav flex-column">
                    <li class="nav-item"><a href="index.php" class="nav-link text-white active">Dashboard</a></li>
                    <li class="nav-item"><a href="displayAlert.js.php" class="nav-link text-white">Security Alerts</a>
                    </li>
                    <li class="nav-item"><a href="logs.php" class="nav-link text-white">System Logs</a></li>
                    <li class="nav-item"><a href="reports.php" class="nav-link text-white">Reports</a></li>
                    <li class="nav-item"><a href="users.php" class="nav-link text-white">User Management</a></li>
                    <li class="nav-item"><a href="#" class="nav-link text-white">Settings</a></li>
                </ul>
            </div>
        </nav>

        <!-- Main Content Area -->
        <div class="main-content flex-fill">
            <header class="d-flex justify-content-between align-items-center p-3 bg-light border-bottom">
                <h1 class="h3"><?php echo 'Welcome to the security app dashboard, ' . $_SESSION['username'] . '!'; ?>
                </h1>
            </header>

            <div class="container-fluid mt-4">
                <!-- Overview Cards -->
                <div class="row mb-3">
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
                        <div class="card bg-light border">
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
                        <div class="card bg-light border">
                            <div class="card-body">
                                <h5 class="card-title">Reports Generated</h5>
                                <p class="display-4">
                                    <span id="reportCount">0</span>
                                </p>
                                <p class="text-muted">In the last week</p>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Real-Time Monitoring Charts -->
                <div class="row mb-4">
                    <div class="col-md-12">
                        <div class="card">
                            <div class="card-header">Real-Time Security Monitoring</div>
                            <div class="card-body">
                                <div id="chart-container">
                                    <canvas id="alertsChart" width="400" height="200"></canvas>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-12 mt-4">
                        <div class="card">
                            <div class="card-header">Network Traffic Overview</div>
                            <div class="card-body">
                                <iframe src="./displayTraffic.html"
                                    style="width: 100%; height: 600px; border: none;"></iframe>

                            </div>
                        </div>
                    </div>
                </div>
                <!-- Latest Security Alerts Table (Responsive) -->
                <section id="securityAlertsBtn">
                    <div class="row">
                        <div class="col-md-12">
                            <div class="card">
                                <div class="card-header">Latest Security Alerts</div>
                                <div class="card-body">
                                    <!-- Responsive security alerts table -->
                                    <div class="table-responsive">
                                        <?php include 'displayAlert.js.php';?>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </section>

                <!-- System Logs Table (Responsive) -->
                <div class="row mt-4">
                    <div class="col-md-12">
                        <div class="card">
                            <div class="card-header">System Logs</div>
                            <div class="card-body">
                                <!-- Responsive system logs table -->
                                <div class="table-responsive">
                                    <table class="table table-hover">
                                        <thead>
                                            <tr>
                                                <th>Log ID</th>
                                                <th>Event</th>
                                                <th>Timestamp</th>
                                                <th>Details</th>
                                            </tr>
                                        </thead>
                                        <tbody><?php include 'api/getLogsTable.php';?></tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Blocked IP Address Section (Responsive) -->
                <div class="row mt-4">
                    <div class="col-md-12">
                        <div class="card">
                            <div class="card-header">Blocked IP Addresses</div>
                            <div class="card-body">
                                <!-- Blocked IPs table is responsive -->
                                <div class="table-responsive">
                                    <?php include 'displaySuspiciousBehavior.php';?>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Emails Section (Responsive) -->
                <div class="row mt-4">
                    <div class="col-md-12">
                        <div class="card">
                            <div class="card-header">Emails</div>
                            <div class="card-body">
                                <!-- Emails table is responsive -->
                                <div class="table-responsive">
                                    <?php include 'displayEmails.php';?>
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
    <script src="scripts.js"></script>
    <script src="alertsChart.js"></script>
    <script src="displayCountAlertsPerDay.js"></script>

</body>

</html>