<?php 

// include '../../src/config/middleware.php';
// SimpleMiddleware::requireAdmin();

// include __DIR__ . '/../../includes/header.php';
// include __DIR__ . '/../../includes/sidebar.php';
// include __DIR__ . '/../../includes/header.php';



?>




<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Real-time Report Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .report {
            background-color: #f3f5f31a;
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }

        .report h5 {
            font-size: 1.25rem;
            font-weight: bold;
        }

        .alert-type {
            text-transform: uppercase;
            color: #fff;
            padding: 5px 10px;
            border-radius: 3px;
            margin-bottom: 15px;
            font-size: 1rem;
        }

        .timestamp {
            font-size: 0.9rem;
            color: #6c757d;
        }

        .network_logs {
            background-color: #dc45;
        }

        .websites_logs {
            background-color: #ffc107;
        }

        .info {
            background-color: #171717b8;
        }

        .no-reports {
            font-size: 1.2rem;
            color: #5c757d;
            text-align: center;
            margin-top: 50px;
        }

        .main-content {
            padding: 20px;
        }
    </style>
</head>

<body>
    <?php include '../../includes/header.php'; ?>
    <?php include '../../includes/navbar.php'; ?>
    <div class="d-flex">
        <?php include '../../includes/sidebar.php'; ?>
        <div class="flex-fill main-content">
            <h1 class="text-center my-4">Real-time Security Reports</h1>

            <div id="reports" class="report-container"></div>
        </div>
    </div>

    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/js/bootstrap.bundle.min.js"></script>

    <script>
        $(document).ready(function() {
            function fetchReports() {
                $.ajax({
                    url: '../logic/fetch_reports.php',
                    method: 'GET',
                    dataType: 'json',
                    success: function(data) {
                        $('#reports').empty();

                        if (data.length === 0) {
                            $('#reports').append(
                                '<p class="no-reports">No new reports in the last hour.</p>'
                            );
                        } else {
                            data.forEach(function(report) {
                                let alertClass = 'info'; 
                                if (report.alert_type === 'network_logs') {
                                    alertClass = 'network_logs';
                                } else if (report.alert_type === 'websites_logs') {
                                    alertClass = 'websites_logs';
                                }

                                let reportHtml = `
                                    <div class="report flex-fill main-content">
                                        <div class="alert-type ${alertClass}">${report.alert_type}</div>
                                        <p>${report.report_details}</p>
                                        <p class="timestamp">Generated at: ${report.generated_at}</p>
                                    </div>
                                `;
                                $('#reports').append(reportHtml);
                            });
                        }
                    },
                    error: function(xhr, status, error) {
                        console.error("Error fetching reports:", error);
                    }
                });
            }

            setInterval(fetchReports, 5000);

            fetchReports();
        });
    </script>

</body>

</html>
