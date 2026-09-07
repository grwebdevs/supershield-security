<?php
/**
 * Fired when the plugin is uninstalled.
 *
 * @package SuperShield_Security
 */

// If uninstall not called from WordPress, exit.
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

global $wpdb;

// 1. Delete plugin settings
delete_option( 'supershield_settings' );

// 2. Drop custom tables
$tables = array(
	$wpdb->prefix . 'supershield_events',
	$wpdb->prefix . 'supershield_blocked_ips',
	$wpdb->prefix . 'supershield_scan_issues',
);

foreach ( $tables as $table ) {
	$wpdb->query( "DROP TABLE IF EXISTS $table" );
}

// 3. Clean up any leftover transients
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_supershield_%' OR option_name LIKE '_transient_timeout_supershield_%'" );
