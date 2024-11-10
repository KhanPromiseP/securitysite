<!-- Sidebar -->
<nav class="sidebar bg-dark" id="sidebar">
    <div class="sidebar-header p-3 mt-4">
        <a href="../views/startsystem.html" class="btn btn-danger w-100 mb-4">Start System</a>
    </div>
    <ul class="nav flex-column">
        <li class="nav-item">
            <a href="../public/index.php" class="nav-link <?= basename($_SERVER['PHP_SELF']) == 'index.php' ? 'active' : '' ?>">Dashboard</a>
        </li>
        <li class="nav-item">
            <a href="../views/net.php" class="nav-link <?= basename($_SERVER['PHP_SELF']) == 'net.php' ? 'active' : '' ?>">Network</a>
        </li>
        <li class="nav-item">
            <a href="../views/web.php" class="nav-link <?= basename($_SERVER['PHP_SELF']) == 'web.php' ? 'active' : '' ?>">Website</a>
        </li>
        <li class="nav-item">
            <a href="../views/report_dashboard.php" class="nav-link <?= basename($_SERVER['PHP_SELF']) == 'report_dashboard.php' ? 'active' : '' ?>">Reports</a>
        </li>
        <li class="nav-item">
            <a href="users.php" class="nav-link <?= basename($_SERVER['PHP_SELF']) == 'users.php' ? 'active' : '' ?>">User Management</a>
        </li>
        <li class="nav-item">
            <a href="settings.php" class="nav-link <?= basename($_SERVER['PHP_SELF']) == 'settings.php' ? 'active' : '' ?>">Settings</a>
        </li>
    </ul>
</nav>
