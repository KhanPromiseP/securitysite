<?php
include 'Database.php';
include 'User.php';

// Initialize DB connection
$database = new Database();
$db = $database->getConnection();

// Create a new User object
$user = new User($db);

// Log the user out
$user->logout();
header('Location: login.php');