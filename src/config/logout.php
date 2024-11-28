<?php
session_start();
include 'Database.php';
include 'User.php';


$database = new Database();
$db = $database->getConnection();

$user = new User($db);

$user->logout();
header('Location: login.php');