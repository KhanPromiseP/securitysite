<?php

include './../../includes/header.php';

session_start();
include 'middleware.php';
SimpleMiddleware::preventLoggedInAccess();
include 'Database.php';
include 'User.php';

$database = new Database();
$db = $database->getConnection();
$user = new User($db);

$message = '';


if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];
    // $username = $_SESSION['username'];
    if ($user->login($username, $password)) {
        
        header('Location: ../../public/index.php');
        exit();
    } else {
        $message = 'Invalid username or password.';
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .password-toggle {
            cursor: pointer;
            font-size: 1.2rem;
        }
    </style>
</head>
<body>

    <div class="container mt-5">
        <h2 class="text-center">Login</h2>
        <?php if ($message): ?>
            <div class="alert alert-danger"><?php echo $message; ?></div>
        <?php endif; ?>
        <form action="login.php" method="POST" class="mx-auto" style="max-width: 400px;">
            <div class="mb-3">
                <label for="username" class="form-label">Username</label>
                <input type="text" name="username" class="form-control" required>
            </div>
            <div class="mb-3">
                <label for="password" class="form-label">Password</label>
                <div class="input-group">
                    <input type="password" name="password" class="form-control" id="password" required>
                    <span class="input-group-text password-toggle" id="togglePassword" onclick="togglePassword()">👁️</span>
                </div>
            </div>
            <div class="d-grid">
                <button type="submit" class="btn btn-primary">Login</button>
            </div>
            <div class="text-center mt-3">
                <p>Don't have an account? <a href="register.php">Register here</a></p>
            </div>
        </form>
    </div>

    <script>
        function togglePassword() {
            var passwordField = document.getElementById("password");
            var toggleIcon = document.getElementById("togglePassword");

            if (passwordField.type === "password") {
                passwordField.type = "text";
                toggleIcon.textContent = "🙈"; // Change icon to indicate password is visible
            } else {
                passwordField.type = "password";
                toggleIcon.textContent = "👁️"; // Change icon to indicate password is hidden
            }
        }
    </script>
</body>
</html>
