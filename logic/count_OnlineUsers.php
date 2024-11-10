<?php
$os = php_uname("s");
$command = "";

if (stripos($os, "Linux") !== false) {
    $command = "python3 ../scripts/count_OnlineUsers.py";
} elseif (stripos($os, "Windows") !== false) {
    $command = "python C:\\windows\\path\\to\\count_OnlineUsers.py";
}

if ($command) {
    $user_count = intval(shell_exec($command));
    echo json_encode(["count" => $user_count]);
} else {
    echo json_encode(["error" => "Unsupported OS."]);
}
?>
