$(document).ready(function () {
    function fetchWeeklyCount() {
        $.ajax({
            url: '../logic/getWeeklyReports.php',  
            method: 'GET',
            dataType: 'json',
            success: function (data) {
                if (data && data.report_count !== undefined) {
                    $('#report-count').text(data.report_count); 
                } else {
                    console.warn('Unexpected response format or missing report count');
                }
            },
            error: function (xhr, status, error) {
                console.error('AJAX Error: ' + error);
                console.error('Status: ' + status);
                console.error('Response: ' + xhr.responseText);
            }
        });
    }

    fetchWeeklyCount();  
    setInterval(fetchWeeklyCount, 5000);
});
