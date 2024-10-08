$(document).ready(function() {
    function fetchOnlineUsers() {
        $.ajax({
            url: '../logic/onlineUsers.php',
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

    setInterval(fetchOnlineUsers, 5000);

    fetchOnlineUsers();
});

