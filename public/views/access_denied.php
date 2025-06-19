<?php
session_start();
include __DIR__ . '/../../includes/header.php';
include __DIR__ . '/../../includes/sidebar.php';

?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Denied</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>

<body class="bg-light">
    <div class="container center mt-5">
        <div class="alert alert-danger text-center" role="alert">
            <h1 class="display-4">Access Denied</h1>
            <p>You do not have permission to view this page. Please contact your administrator for access.</p>
            <a href="../index.php" class="btn btn-primary mt-3" role="button" aria-label="Return to Login Page">Return to Dashboard</a>
        </div>
    </div>
</body>

</html>
