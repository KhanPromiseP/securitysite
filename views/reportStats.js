
$(document).ready(function () {
    function fetchWeeklyCount() {
        $.ajax({
            url: '../logic/getWeeklyReports.php', 
            method: 'GET',
            dataType: 'json',
            success: function (data) {
                // Update the report count
                $('#report-count').text(data.report_count);
            }
        });
    }

   
    setInterval(fetchWeeklyCount, 10000);
    fetchWeeklyCount(); 
});

