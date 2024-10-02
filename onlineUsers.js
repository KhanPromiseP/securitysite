$(document).ready(function() {
    function fetchOnlineUsers() {
        $.ajax({
            url: 'onlineUsers.php',
            type: 'GET',
            dataType: 'json',
            success: function(response) {
                $('#onlineUserCount').text(response.online_user_count);
            },
            error: function(xhr, status, error) {
                console.error('Error fetching online user count:', error);
            }
        });
    }

    // Fetch online users count every 30 seconds
    setInterval(fetchOnlineUsers, 5000);

    // Initial fetch
    fetchOnlineUsers();
});

