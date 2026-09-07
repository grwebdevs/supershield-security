<?php
/**
 * Fired during plugin activation.
 *
 * @package    SuperShield_Security
 * @subpackage SuperShield_Security/includes
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SuperShield_Activator {

	/**
	 * Run activation tasks.
	 */
	public static function activate() {
		// 1. Create Database Tables
		SuperShield_DB::create_tables();

		// 2. Initialize Default Settings
		$default_settings = array(
			'waf_enabled'               => 1,
			'waf_bypass_admin'          => 1,
			'auto_block_waf_violators'  => 1,
			'waf_lockout_duration'      => 86400,
			'bruteforce_protection'     => 1,
			'max_login_retries'         => 5,
			'login_lockout_duration'    => 3600,
			'enable_login_honeypot'     => 1,
			'custom_login_slug'         => '',
			'block_uploads_php'         => 1,
			'disable_xmlrpc'            => 1,
			'hide_wp_version'           => 1,
			'block_user_enumeration'    => 1,
			'security_headers'          => 1,
			'disallow_file_edit'        => 1,
			'block_hidden_files'        => 1,
			'protect_config_files'      => 1,
			'trust_proxy_headers'       => 0,
			'whitelist_loopback'        => 1,
			'ip_whitelist'              => array( '127.0.0.1', '::1' ),
			'ip_blacklist'              => array(),
			'geoip_enabled'             => 0,
			'geoip_mode'                => 'blacklist',
			'geoip_countries'           => array( 'RU', 'CN', 'KP' ),
			'geoip_protect_login_only'  => 0,
			'2fa_enabled'               => 0,
			'2fa_roles'                 => array( 'administrator' ),
			'2fa_grace_period_days'     => 3,
			'telemetry_enabled'         => 0,
			'antitamper_tamper_detected'=> 0,
		);

		$existing = get_option( 'supershield_settings', false );
		if ( false === $existing ) {
			// Auto-whitelist current activating user's IP
			$admin_ip = SuperShield_Utils::get_client_ip();
			if ( ! in_array( $admin_ip, $default_settings['ip_whitelist'], true ) ) {
				$default_settings['ip_whitelist'][] = $admin_ip;
			}
			update_option( 'supershield_settings', $default_settings );
		}

		// 3. Write initial Uploads directory .htaccess protection
		SuperShield_Hardening::ensure_uploads_htaccess_immunity();

		// 4. Deploy persistent MU watchdog & generate cryptographic baseline manifest if missing
		if ( class_exists( 'SuperShield_AntiTamper' ) ) {
			SuperShield_AntiTamper::ensure_watchdog_installed();
			if ( defined( 'SUPERSHIELD_PLUGIN_DIR' ) && ! file_exists( SUPERSHIELD_PLUGIN_DIR . 'manifest.sig' ) ) {
				SuperShield_AntiTamper::generate_manifest();
			}
		}

		// 5. Schedule daily maintenance cron
		if ( ! wp_next_scheduled( 'supershield_daily_maintenance' ) ) {
			wp_schedule_event( time(), 'daily', 'supershield_daily_maintenance' );
		}

		// Log activation event
		SuperShield_DB::log_event( 'admin_action', 'SuperShield Security activated successfully.', 'Version: ' . SUPERSHIELD_VERSION );
	}
}
