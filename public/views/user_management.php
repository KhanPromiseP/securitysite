<?php
include __DIR__ . '/../../src/config/Database.php';
include __DIR__ . '/../../src/config/User.php'; 
include __DIR__ . '/../../includes/header.php';
include __DIR__ . '/../../includes/sidebar.php';

$database = new Database();
$db = $database->getConnection();
$user = new User($db);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if ($_POST['action'] == 'create') {
        $user->register($_POST['username'], $_POST['email'], $_POST['password'], $_POST['role']);
    } elseif ($_POST['action'] == 'update') {
        $user->updateUser($_POST['id'], $_POST['username'], $_POST['email'], $_POST['password'], $_POST['role']);
        header("Location: user_management.php"); // Redirect to avoid resubmission
        exit();
    }
} elseif (isset($_GET['action']) && $_GET['action'] == 'delete') {
    $user->deleteUser($_GET['id']);
    header("Location: user_management.php"); // Redirect after deleting to avoid resubmission
    exit();
}

$users = $user->getAllUsers();

// Fetch user info for editing if an edit action is being performed
$editUser = null;
if (isset($_GET['edit_id'])) {
    $editUser = $user->getUserById($_GET['edit_id']);
}
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
    <?php include '../includes/navbar.php'; ?>
    <div class="d-flex" style="height:90vh">
        <?php include '../includes/sidebar.php'; ?>
        <div class="row flex-fill main-content">
            <div class="row mt-2">
                <div class="col-md-12">
                    <div class="card flex-fill main-content">
                        <div class="card-body">
                            <div class="table-responsive">
                                <h2>User Management</h2>
                                <button class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#userModal" onclick="clearForm()">Add User</button>
                                <table class="table mt-3">
                                    <thead>
                                        <tr>
                                            <th>Username</th>
                                            <th>Email</th>
                                            <th>Password</th>
                                            <th>Role</th>
                                            <th>Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($users as $user): ?>
                                            <tr>
                                                <td><?= htmlspecialchars($user['username']); ?></td>
                                                <td><?= htmlspecialchars($user['email']); ?></td>
                                                <td><?= htmlspecialchars($user['password']); ?></td>
                                                <td><?= htmlspecialchars($user['role_name']); ?></td>
                                                <td>
                                                    <button class="btn btn-info" onclick="editUser(<?= $user['id']; ?>, '<?= $user['username']; ?>', '<?= $user['email']; ?>','<?= $user['password_hash']; ?>', <?= $user['role_id']; ?>)">Edit</button>
                                                    <a href="javascript:void(0);" class="btn btn-danger" onclick="confirmDelete(<?= $user['id']; ?>)">Delete</a>
                                                </td>
                                            </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>

                            <!-- Modal for creating/updating a user -->
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
                                                    <label for="password">Password</label>
                                                    <div class="input-group">
                                                        <input type="password" name="password" id="password" class="form-control">
                                                        <button type="button" class="btn btn-outline-secondary" id="togglePassword">Show</button>
                                                    </div>
                                                </div>

                                                <div class="form-group">
                                                    <label for="role">Role</label>
                                                    <select name="role" id="role" class="form-control" required>
                                                        <option value="1" id="adminRole">Admin</option>
                                                        <option value="2" id="userRole">User</option>
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
                                    document.getElementById('password').value = '';
                                    document.getElementById('password').removeAttribute('placeholder'); 
                                    document.getElementById('role').setAttribute('placeholder', 'select user privilege');
                                    document.getElementById('action').value = 'create';
                                }

                                function editUser(id, username, email, password_hash, role_id) {
                                    document.getElementById('userId').value = id;
                                    document.getElementById('username').value = username;
                                    document.getElementById('email').value = email;
                                    document.getElementById('password').value = ''; 
                                    document.getElementById('password').setAttribute('placeholder', 'Change or maintain password');
                                    document.getElementById('role').value = role_id;
                                    document.getElementById('action').value = 'update'; 
                                    new bootstrap.Modal(document.getElementById('userModal')).show();
                                }

                                function confirmDelete(userId) {
                                    const confirmDelete = confirm("Are you sure you want to delete this user?");
                                    if (confirmDelete) {
                                        window.location.href = "user_management.php?action=delete&id=" + userId;
                                    }
                                }

                                document.getElementById('togglePassword').addEventListener('click', function (e) {
                                    const passwordField = document.getElementById('password');
                                    const type = passwordField.type === "password" ? "text" : "password";
                                    passwordField.type = type;
                                    e.target.textContent = type === "password" ? "Show" : "Hide";
                                });
                            </script>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
