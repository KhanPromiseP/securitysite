<!-- Sidebar -->
<nav class="sidebar bg-dark" id="sidebar">
    <!-- <div class="sidebar-header p-3 mt-4">
        <a href="../views/buttonDasboard.php" class="btn btn-danger w-100 mb-4">Start System</a>
    </div> -->
    <ul class="nav flex-column">
        <li class="nav-item">
            <a href="../index.php" class="nav-link <?= basename($_SERVER['PHP_SELF']) == 'index.php' ? 'active' : '' ?>">Dashboard</a>
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
            <a href="../views/active_devices_display.php" class="nav-link <?= basename($_SERVER['PHP_SELF']) == 'active_devices_display.php' ? 'active' : '' ?>">Users Online</a>
        </li>
        <li class="nav-item">
            <a href="../views/network_monitor.php" class="nav-link <?= basename($_SERVER['PHP_SELF']) == 'network_monitor.php' ? 'active' : '' ?>">Logs/System</a>
        </li>
        <li class="nav-item">
            <a href="../views/user_management.php" class="nav-link <?= basename($_SERVER['PHP_SELF']) == 'user_management.php' ? 'active' : '' ?>">User Management</a>
        </li>
        <li class="nav-item">
            <a href="../views/settings.php" class="nav-link <?= basename($_SERVER['PHP_SELF']) == 'settings.php' ? 'active' : '' ?>">Settings</a>
        </li>
    </ul>
</nav>
