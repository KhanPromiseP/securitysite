function fetchActiveDeviceCount() {
    $.ajax({
        url: '../../logic/active_devices_count.php', 
        type: 'GET',
        dataType: 'json', 
        success: function(data) {
            if (data.error) {
                console.error('Error:', data.error);
                return;
            }
            let countElement = $('#device-count');
            // Display only connected devices (total - disconnected)
            countElement.text(`${data.active_device_count}`);
            
            // display disconnected count if needed
            let disconnectedElement = $('#disconnected-count');
            disconnectedElement.text(`${data.disconnected_count}`);
        },
        error: function(xhr, status, error) {
            console.error('Error fetching active device count:', error);
        }
    });
}

function updateRealTimeCount() {
    fetchActiveDeviceCount();
}

setInterval(updateRealTimeCount, 1000);

$(document).ready(function() {
    updateRealTimeCount();
});