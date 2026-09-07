<?php
/**
 * Fired during plugin deactivation.
 *
 * @package    SuperShield_Security
 * @subpackage SuperShield_Security/includes
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SuperShield_Deactivator {

	/**
	 * Run deactivation tasks.
	 */
	public static function deactivate() {
		// Clear cron jobs
		$timestamp = wp_next_scheduled( 'supershield_daily_maintenance' );
		if ( $timestamp ) {
			wp_unschedule_event( $timestamp, 'supershield_daily_maintenance' );
		}

		// Log deactivation
		SuperShield_DB::log_event( 'admin_action', 'SuperShield Security deactivated.' );
	}
}
