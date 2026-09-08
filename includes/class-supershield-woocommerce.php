<?php
/**
 * WooCommerce Anti-Carding & E-Commerce Shield for SuperShield Security.
 *
 * Protects WooCommerce storefronts from automated credit card stuffing attacks,
 * checkout transaction spam, fake order bots, and payment gateway chargebacks.
 *
 * @package    SuperShield_Security
 * @subpackage SuperShield_Security/includes
 * @author     Ghulam Rasool <grwebdevs.com>
 * @version    2.5.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SuperShield_WooCommerce {

	/**
	 * Initialize WooCommerce security hooks.
	 */
	public static function init() {
		// Only run if WooCommerce is active
		if ( ! class_exists( 'WooCommerce' ) ) {
			return;
		}

		// 1. Invisible Checkout Honeypot Field
		if ( SuperShield_Utils::get_option( 'wc_honeypot_enabled', 1 ) ) {
			add_action( 'woocommerce_after_order_notes', array( __CLASS__, 'render_checkout_honeypot' ) );
			add_action( 'woocommerce_after_checkout_validation', array( __CLASS__, 'validate_checkout_honeypot' ), 10, 2 );
		}

		// 2. Anti-Carding Transaction Velocity Limiter
		if ( SuperShield_Utils::get_option( 'wc_anti_carding_enabled', 1 ) ) {
			add_action( 'woocommerce_checkout_order_exception', array( __CLASS__, 'handle_failed_payment' ), 10, 1 );
			add_action( 'woocommerce_after_checkout_validation', array( __CLASS__, 'check_pre_checkout_velocity' ), 5, 2 );
		}
	}

	/**
	 * Render invisible decoy honeypot on WooCommerce checkout form.
	 *
	 * @param WC_Checkout $checkout
	 */
	public static function render_checkout_honeypot( $checkout ) {
		echo '<div style="position: absolute !important; left: -9999px !important; top: -9999px !important; opacity: 0 !important; pointer-events: none !important;" aria-hidden="true">';
		echo '<label for="sss_wc_company_tax_id">Company Tax Reference (Leave Empty)</label>';
		echo '<input type="text" name="sss_wc_company_tax_id" id="sss_wc_company_tax_id" tabindex="-1" autocomplete="off" value="" />';
		echo '</div>';
	}

	/**
	 * Validate checkout honeypot field.
	 *
	 * @param array    $data
	 * @param WP_Error $errors
	 */
	public static function validate_checkout_honeypot( $data, $errors ) {
		if ( ! empty( $_POST['sss_wc_company_tax_id'] ) ) {
			$client_ip = SuperShield_Utils::get_client_ip();
			SuperShield_DB::block_ip(
				$client_ip,
				'WooCommerce Honeypot Trap: Automated bot transaction blocked',
				'bot',
				86400
			);
			SuperShield_DB::log_event(
				'waf_block',
				'Automated bot trapped by WooCommerce Checkout Honeypot',
				'Field: sss_wc_company_tax_id',
				$client_ip
			);
			$errors->add( 'bot_detected', '<strong>Security Verification Failed:</strong> Transaction rejected.' );
		}
	}

	/**
	 * Check checkout velocity before payment gateway executes.
	 *
	 * @param array    $data
	 * @param WP_Error $errors
	 */
	public static function check_pre_checkout_velocity( $data, $errors ) {
		$client_ip = SuperShield_Utils::get_client_ip();
		if ( SuperShield_IP_Manager::is_whitelisted( $client_ip ) ) {
			return;
		}

		$transient_key = 'sss_wc_fails_' . md5( $client_ip );
		$failed_count = (int) get_transient( $transient_key );

		$max_fails = (int) SuperShield_Utils::get_option( 'wc_max_failed_checkouts', 3 );
		if ( $failed_count >= $max_fails ) {
			// Lock out IP address
			SuperShield_DB::block_ip(
				$client_ip,
				"Carding Bot Defense: Exceeded {} failed checkout attempts",
				'bruteforce',
				86400
			);
			SuperShield_DB::log_event(
				'waf_block',
				"WooCommerce checkout lockout: {} failed payment probes",
				'Target: /checkout/',
				$client_ip
			);
			$errors->add( 'carding_locked', '<strong>Transaction Denied:</strong> Too many failed attempts. Please contact store support.' );
		}
	}

	/**
	 * Record failed checkout payment attempt to count carding velocity.
	 *
	 * @param Exception|WP_Error $exception
	 */
	public static function handle_failed_payment( $exception ) {
		$client_ip = SuperShield_Utils::get_client_ip();
		if ( SuperShield_IP_Manager::is_whitelisted( $client_ip ) ) {
			return;
		}

		$transient_key = 'sss_wc_fails_' . md5( $client_ip );
		$fails = (int) get_transient( $transient_key );
		$fails++;

		// 10-minute tracking window for rapid carding attempts
		set_transient( $transient_key, $fails, 600 );

		SuperShield_DB::log_event(
			'admin_action',
			"WooCommerce failed payment attempt #{} recorded",
			is_object( $exception ) && method_exists( $exception, 'getMessage' ) ? $exception->getMessage() : 'Payment Gateway Failure',
			$client_ip
		);
	}
}
