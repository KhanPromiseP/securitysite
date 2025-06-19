
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Scanner Control</title>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
</head>
<body>

<h2>Network Scanner Control Panel</h2>
<button id="startBtn">Start Scan</button>
<button id="stopBtn">Stop Scan</button>
<button id="statusBtn">Check Status</button>

<p>Status: <span id="statusText">Unknown</span></p>

<script>
    function updateStatus() {
        $.post("../logic/start_stop.php", { action: "status" }, function(data) {
            $("#statusText").text(data.status);
        }, "json");
    }

    $("#startBtn").click(function() {
        $.post("../logic/start_stop.php", { action: "start" }, function(data) {
            alert(data.status);
            updateStatus();
        }, "json");
    });

    $("#stopBtn").click(function() {
        $.post("../logic/start_stop.php", { action: "stop" }, function(data) {
            alert(data.status);
            updateStatus();
        }, "json");
    });

    $("#statusBtn").click(function() {
        updateStatus();
    });

    // Auto-update status every 5 seconds
    setInterval(updateStatus, 5000);
</script>

</body>
</html>
