<?php

// error_reporting(E_ALL);
// ini_set('display_errors', 1);


include '../src/config/Database.php';
include '../src/config/User.php'; 
include '../includes/header.php'; 
$database = new Database();
$db = $database->getConnection();
$user = new User($db);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if ($_POST['action'] == 'create') {
        $user->register($_POST['username'], $_POST['email'], $_POST['password'], $_POST['role']);
    } elseif ($_POST['action'] == 'update') {
        $user->updateUser($_POST['id'], $_POST['username'], $_POST['email'], $_POST['role']);
    }
} elseif ($_GET['action'] == 'delete') {
    $user->deleteUser($_GET['id']);
}

$users = $user->getAllUsers();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Management</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
   
</head>
<body>
<div class="container mt-5">
    <h2>User Management</h2>
    <button class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#userModal" onclick="clearForm()">Add User</button>
    <table class="table mt-3">
        <thead>
            <tr>
                <th>Username</th>
                <th>Email</th>
                <th>Role</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($users as $user): ?>
                <tr>
                    <td><?= htmlspecialchars($user['username']); ?></td>
                    <td><?= htmlspecialchars($user['email']); ?></td>
                    <td><?= htmlspecialchars($user['role_name']); ?></td>
                    <td>
                        <button class="btn btn-info" onclick="editUser(<?= $user['id']; ?>, '<?= $user['username']; ?>', '<?= $user['email']; ?>', <?= $user['role_id']; ?>)">Edit</button>
                        <a href="user_management.php?action=delete&id=<?= $user['id']; ?>" class="btn btn-danger">Delete</a>
                    </td>
                </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
</div>

<div class="modal fade" id="userModal" tabindex="-1" aria-labelledby="userModalLabel" aria-hidden="true">
    <div class="modal-dialog">
        <form method="post" action="user_management.php">
            <input type="hidden" name="action" id="action" value="create">
            <input type="hidden" name="id" id="userId">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="userModalLabel">User Form</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <div class="form-group">
                        <label for="username">Username</label>
                        <input type="text" name="username" id="username" class="form-control" required>
                    </div>
                    <div class="form-group">
                        <label for="email">Email</label>
                        <input type="email" name="email" id="email" class="form-control" required>
                    </div>
                    <div class="form-group">
                        <label for="role">Role</label>
                        <select name="role" id="role" class="form-control" required>
                            <option value="1">Admin</option>
                            <option value="2">User</option>
                        </select>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="submit" class="btn btn-primary">Save</button>
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                </div>
            </div>
        </form>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
<script>
function clearForm() {
    document.getElementById('userId').value = '';
    document.getElementById('username').value = '';
    document.getElementById('email').value = '';
    document.getElementById('role').value = '2';
    document.getElementById('action').value = 'create';
}

function editUser(id, username, email, role_id) {
    document.getElementById('userId').value = id;
    document.getElementById('username').value = username;
    document.getElementById('email').value = email;
    document.getElementById('role').value = role_id;
    document.getElementById('action').value = 'update';
    new bootstrap.Modal(document.getElementById('userModal')).show();
}
</script>
</body>
</html>
