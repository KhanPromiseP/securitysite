<?php
include 'middleware.php';
// Prevent logged-in users from accessing login or register pages
SimpleMiddleware::preventLoggedInAccess();



include 'Database.php';
include 'User.php';

$database = new Database();
$db = $database->getConnection();

$user = new User($db);

$message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
$username = $_POST['username'];
$email = $_POST['email'];
$password = $_POST['password'];

if (filter_var($email, FILTER_VALIDATE_EMAIL) && strlen($password) >= 8) {
if ($user->register($username, $email, $password)) {
$message = 'Registration successful. <a href="login.php">Login here</a>';
} else {
$message = 'Registration failed. Username or email might already be in use.';
}
} else {
$message = 'Invalid email or password. Password must be at least 8 characters long.';
}
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>

<body>
    <div class="container mt-5">
        <h2 class="text-center">Register</h2>
        <?php if ($message): ?>
        <div class="alert alert-info"><?php echo $message; ?></div>
        <?php endif; ?>
        <form action="" method="POST" class="mx-auto" style="max-width: 400px;">
            <div class="mb-3">
                <label for="username" class="form-label">Username</label>
                <input type="text" name="username" class="form-control" required>
            </div>
            <div class="mb-3">
                <label for="email" class="form-label">Email</label>
                <input type="email" name="email" class="form-control" required>
            </div>
            <div class="mb-3">
                <label for="password" class="form-label">Password</label>
                <input type="password" name="password" class="form-control" required>
            </div>
            <div class="d-grid">
                <button type="submit" class="btn btn-primary">Register</button>
            </div>
            <div>
                <p>Already have an acount? <a class="btn btn-primary" style="decoration:none" href="login.php">Login</a>
                    now!
                </p>
            </div>
        </form>
    </div>
</body>

</html>