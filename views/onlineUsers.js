
<script>
    function fetchActiveDeviceCount() {
        $.getJSON("../scripts/active_device_count.json", function(data) {
            if (data && data.active_devices !== undefined) {
                $("#device-count").text("Active Devices: " + data.active_devices);
            } else {
                console.error("Invalid data format in JSON file.");
            }
        }).fail(function() {
            console.error("Failed to fetch active device count.");
        })
    }

    setInterval(fetchActiveDeviceCount, 1000);
</script>
