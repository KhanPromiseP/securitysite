$(document).ready(function () {
    // Function to update the total number of alerts via AJAX
    function updateAlertCount() {
        $.ajax({
            url: 'countAlertsPerDay.php?_=' + new Date().getTime(), // Prevent caching
            type: 'GET',
            dataType: 'json',
            success: function (response) {
                $('#alertCounter').text(response.total_alerts);
            },
            error: function (xhr, status, error) {
                console.error('Error fetching alert count:', error);
                console.error('XHR:', xhr.responseText);
                console.error('Status:', status);
                $('#alertCounter').text('Error fetching data.');
            }
        });
    }

    // Use setInterval to fetch data every 10 seconds
    setInterval(updateAlertCount, 5000);

    // Initial load of alert count
    updateAlertCount();

});