<?php




include 'Database.php';
include 'User.php';


$database = new Database();
$db = $database->getConnection();

$user = new User($db);

$message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];

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
                <input type="password" name="password" class="form-control" required>
            </div>
            <div class="d-grid">
                <button type="submit" class="btn btn-primary">Login</button>
            </div>
            <div>
                <br>
                <p style=" text-align:center">Don't have an acount? <a style="decoration:none"
                        href="register.php">Register</a>
                    now!
                </p>
            </div>
        </form>
    </div>
</body>

</html>