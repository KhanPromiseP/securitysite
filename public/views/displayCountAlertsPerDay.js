$(document).ready(function () {
    function updateAlertCount() {
        $.ajax({
            url: '../logic/countAlertsPerDay.php?_=' + new Date().getTime(), 
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

    
    setInterval(updateAlertCount, 5000);

  
    updateAlertCount();

});