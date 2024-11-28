$(document).ready(function () {
    function fetchWeeklyCount() {
        $.ajax({
            url: '../logic/getWeeklyReports.php', // PHP file to fetch the weekly report count
            method: 'GET',
            dataType: 'json',
            success: function (data) {
                if (data.success) {
                    $('#report-count').text(data.report_count); // Update the report count in the UI
                } else {
                    console.warn(data.message || 'Unexpected response format');
                }
            },
            error: function (xhr, status, error) {
                console.error('AJAX Error: ' + error);
                console.error('Status: ' + status);
                console.error('Response: ' + xhr.responseText);
            }
        });
    }

    // Initial fetch when the page loads
    fetchWeeklyCount();

    // Periodic updates every 5 seconds
    setInterval(fetchWeeklyCount, 5000);
});
