// Function to fetch the number of weekly reports
function fetchWeeklyReportCount() {
    $.ajax({
        url: 'getWeeklyReports.php', // Path to your PHP file
        type: 'GET',
        dataType: 'json',
        success: function (data) {
            if (data.error) {
                $('#reportCount').text('Error fetching data: ' + data.error);
            } else {
                $('#reportCount').text('Reports Generated This Week: ' + data.report_count);
            }
        },
        error: function () {
            $('#reportCount').text('Error fetching data.');
        }
    });
}

// Update the report count every 30 seconds
$(document).ready(function () {
    fetchWeeklyReportCount();
    setInterval(fetchWeeklyReportCount, 30000); // 30000 ms = 30 seconds
});
