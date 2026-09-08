<?php
/**
 * SuperShield Security — Central Platform Configuration
 * 
 * @package    SuperShield_Portal
 * @author     Ghulam Rasool <grwebdevs.com>
 * @version    2.2.1
 */

defined('SSS_ACCESS') or define('SSS_ACCESS', true);

return array(
    'app_name'        => 'SuperShield Security Central Hub',
    'app_version'     => '2.2.1',
    'site_url'        => 'https://sss.grwebdevs.com',
    'agency_url'      => 'https://grwebdevs.com',
    'author_name'     => 'Ghulam Rasool',
    
    // Master Admin Notification Email (Receives feedback, bug reports & 2FA codes)
    'admin_email'     => 'grwebdevs5@gmail.com',
    'admin_email_alt' => 'support@grwebdevs.com',
    'system_from_email' => 'support@grwebdevs.com',
    
    // Admin Panel Credentials
    'admin_user'      => 'ghulam',
    'admin_user_alt'  => 'admin',
    'admin_pass'      => 'SuperShield2026!GR',
    
    // Database Configuration (SQLite, zero-maintenance)
    'db_path'         => __DIR__ . '/database/supershield.sqlite',
    
    // GitHub Releases Integration
    'github_repo'     => 'grwebdevs/supershield-security',
    'github_releases' => 'https://api.github.com/repos/grwebdevs/supershield-security/releases/latest',
    'fallback_download_url' => 'https://github.com/grwebdevs/supershield-security/archive/refs/heads/main.zip',
);
