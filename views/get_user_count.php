<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Active User Count</title>
</head>
<body>
    <h1>Active Users on Network: <span id="userCount">0</span></h1>
    <script>
        function fetchUserCount() {
            const xhr = new XMLHttpRequest();
            xhr.open("GET", "get_user_count.php", true);
            xhr.onload = function() {
                if (xhr.status === 200) {
                    const data = JSON.parse(xhr.responseText);
                    if (data.count !== undefined) {
                        document.getElementById("userCount").textContent = data.count;
                    } else {
                        console.error(data.error);
                    }
                }
            };
            xhr.send();
        }

        // Fetch user count every 5 seconds
        setInterval(fetchUserCount, 5000);
        fetchUserCount();  // Initial fetch
    </script>
</body>
</html>
