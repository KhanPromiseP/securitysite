<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Real-time Report Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>

    </style>
</head>

<body>
    <?php  include '../includes/header.php';?>
    <?php  include '../includes/navbar.php';?>
    <div class="d-flex">
        <?php  include '../includes/sidebar.php';?>
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
                            '<p class="text-center text-muted">No new reports in the last hour.</p>'
                        );
                    } else {
                        data.forEach(function(report) {
                            let reportHtml = `
                                <div class="report">
                                    <h5 class="alert-type">${report.alert_type}</h5>
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