<?php
class SimpleMiddleware
{
    // Check if the user is logged in
    public static function requireLogin()
    {
        session_start(); // Start session

        // If user is not logged in, redirect to the login page
        if (!isset($_SESSION['user_id'])) {
            header('Location: ./src/config/login.php');
            exit(); // Stop further execution
        }
    }

    // Method to prevent logged-in users from accessing public pages (e.g., login, register)
    public static function preventLoggedInAccess()
    {
        session_start(); // Start session

        // If user is already logged in, redirect to the dashboard
        if (isset($_SESSION['user_id'])) {
            header('Location: ../../index.php');
            exit(); // Stop further execution
        }
    }

    // Simple logout function to destroy the session
    public static function logout()
    {
        session_start(); // Start session
        session_destroy(); // Destroy the session
        header('Location: ../login.php'); // Redirect to the login page
        exit(); // Stop further execution
    }
}