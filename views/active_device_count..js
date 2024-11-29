
    function fetchActiveDeviceCount() {
        $.ajax({
            url: '../logic/active_devices_count.php', 
            type: 'GET',
            dataType: 'json', 
            success: function(data) {
                let countElement = $('#device-count');
                countElement.text(`${data.active_device_count}`);
            },
            error: function(xhr, status, error) {
                console.error('Error fetching active device count:', error);
            }
        });
    }

    function updateRealTimeCount() {
        fetchActiveDeviceCount();
    }

    setInterval(updateRealTimeCount, 5000);

    $(document).ready(function() {
        updateRealTimeCount();
    });
