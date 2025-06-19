<?php
// public/logout.php
require_once '../src/config/middleware.php'; // Path to SimpleMiddleware class

// Call the static logout method
SimpleMiddleware::logout();
// This will handle session destruction and redirect to views/login.php
?>