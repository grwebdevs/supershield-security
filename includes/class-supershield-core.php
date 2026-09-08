<?php
/**
 * Core Orchestrator for SuperShield Security.
 *
 * @package    SuperShield_Security
 * @subpackage SuperShield_Security/includes
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SuperShield_Core {

	/**
	 * Singleton instance.
	 *
	 * @var SuperShield_Core|null
	 */
	private static $instance = null;

	/**
	 * Get singleton instance.
	 *
	 * @return SuperShield_Core
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Constructor.
	 */
	private function __construct() {}

	/**
	 * Launch the plugin hooks and services.
	 */
	public function run() {
		// Run WAF inspection early (priority -999999 executes prior to third-party plugins per PRD §5.1)
		add_action( 'plugins_loaded', array( $this, 'run_waf' ), -999999 );

		// Initialize hardening and login defense
		add_action( 'init', array( $this, 'init_services' ) );

		// Initialize GitHub releases auto-updater
		if ( class_exists( 'SuperShield_Updater' ) ) {
			SuperShield_Updater::init();
		}

		// Initialize email notification engine
		if ( class_exists( 'SuperShield_Notifier' ) ) {
			SuperShield_Notifier::init();
		}

		// Scheduled daily maintenance cron hook
		add_action( 'supershield_daily_maintenance', array( $this, 'run_daily_maintenance' ) );

		// Admin hooks
		if ( is_admin() ) {
			$admin = new SuperShield_Admin();
			$admin->init();

			// Verify plugin self-integrity on admin requests
			if ( class_exists( 'SuperShield_AntiTamper' ) ) {
				SuperShield_AntiTamper::verify_plugin_integrity();
			}
		}
	}

	/**
	 * Execute early WAF inspection.
	 */
	public function run_waf() {
		SuperShield_WAF::inspect_request();
	}

	/**
	 * Initialize security subsystems.
	 */
	public function init_services() {
		SuperShield_Hardening::init();
		SuperShield_Login_Security::init();

		if ( class_exists( 'SuperShield_Scanner' ) ) {
			SuperShield_Scanner::init();
		}

		// Deploy persistent MU watchdog
		if ( class_exists( 'SuperShield_AntiTamper' ) ) {
			SuperShield_AntiTamper::ensure_watchdog_installed();
		}
	}

	/**
	 * Daily cron maintenance.
	 */
	public function run_daily_maintenance() {
		SuperShield_DB::cleanup_old_logs( 30 );
		SuperShield_Hardening::ensure_uploads_htaccess_immunity();

		if ( class_exists( 'SuperShield_AntiTamper' ) ) {
			SuperShield_AntiTamper::verify_plugin_integrity();
		}
	}
}
