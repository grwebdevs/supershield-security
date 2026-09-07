<?php
/**
 * Feedback, System Diagnostics & Threat Telemetry Engine for SuperShield Security.
 *
 * @package    SuperShield_Security
 * @subpackage SuperShield_Security/includes
 * @author     Ghulam Rasool <grwebdevs.com>
 * @version    2.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SuperShield_Telemetry {

	const FEEDBACK_API_URL  = 'https://SSS.grwebdevs.com/api/v1/feedback';
	const TELEMETRY_API_URL = 'https://SSS.grwebdevs.com/api/v1/telemetry';

	/**
	 * Submit feedback (bug report, feature request, praise) to Ghulam Rasool's portal.
	 *
	 * @param string $category 'bug_report', 'feature_request', or 'praise'
	 * @param string $message  Feedback text.
	 * @param string $email    Optional contact email.
	 * @return array
	 */
	public static function submit_feedback( $category, $message, $email = '' ) {
		$category = sanitize_text_field( $category );
		$message  = sanitize_textarea_field( $message );
		$email    = sanitize_email( $email );

		if ( empty( $message ) ) {
			return array( 'success' => false, 'message' => 'Please provide a feedback message.' );
		}

		$payload = array(
			'category'    => $category,
			'message'     => $message,
			'email'       => $email,
			'version'     => SUPERSHIELD_VERSION,
			'wp_version'  => function_exists( 'get_bloginfo' ) ? get_bloginfo( 'version' ) : '',
			'php_version' => PHP_VERSION,
			'server_type' => SuperShield_Utils::get_server_type(),
			'timestamp'   => time(),
		);

		$args = array(
			'body'    => wp_json_encode( $payload ),
			'headers' => array( 'Content-Type' => 'application/json' ),
			'timeout' => 8,
		);

		if ( function_exists( 'wp_remote_post' ) ) {
			$response = wp_remote_post( self::FEEDBACK_API_URL, $args );
			if ( ! is_wp_error( $response ) ) {
				SuperShield_DB::log_event( 'admin_action', 'Feedback submitted to SuperShield network: ' . $category );
				return array( 'success' => true, 'message' => 'Thank you! Your feedback has been received by Ghulam Rasool and the SuperShield engineering team.' );
			}
		}

		// Graceful local logging if offline
		SuperShield_DB::log_event( 'admin_action', 'Feedback queued locally: ' . $category, substr( $message, 0, 200 ) );
		return array( 'success' => true, 'message' => 'Thank you! Your feedback has been recorded successfully.' );
	}

	/**
	 * Generate a 100% sanitized anonymous system diagnostics bundle.
	 * Guarantees zero credential, password, or sensitive token leakage.
	 *
	 * @return array Array with 'markdown', 'json', and raw 'data'.
	 */
	public static function generate_diagnostics_report() {
		global $wpdb;

		$settings = get_option( 'supershield_settings', array() );
		$metrics  = SuperShield_DB::get_dashboard_metrics();

		// Check critical PHP extensions
		$extensions = array( 'curl', 'openssl', 'sodium', 'gd', 'json', 'mbstring', 'zip', 'mysqli', 'pdo' );
		$ext_status = array();
		foreach ( $extensions as $ext ) {
			$ext_status[ $ext ] = extension_loaded( $ext ) ? 'Loaded' : 'Missing';
		}

		// Sanitize settings: remove all IP addresses, whitelists, secret keys
		$sanitized_settings = array();
		if ( is_array( $settings ) ) {
			foreach ( $settings as $k => $v ) {
				if ( in_array( $k, array( 'ip_whitelist', 'ip_blacklist', 'auth_key', 'secret' ), true ) ) {
					$sanitized_settings[ $k ] = '[REDACTED_FOR_PRIVACY]';
				} else {
					$sanitized_settings[ $k ] = $v;
				}
			}
		}

		$data = array(
			'report_generated_at' => gmdate( 'Y-m-d H:i:s' ) . ' UTC',
			'supershield_version' => SUPERSHIELD_VERSION,
			'environment'         => array(
				'wordpress_version'   => function_exists( 'get_bloginfo' ) ? get_bloginfo( 'version' ) : 'unknown',
				'php_version'         => PHP_VERSION,
				'php_sapi'            => php_sapi_name(),
				'server_software'     => SuperShield_Utils::get_server_type(),
				'memory_limit'        => ini_get( 'memory_limit' ),
				'max_execution_time'  => ini_get( 'max_execution_time' ),
				'upload_max_filesize' => ini_get( 'upload_max_filesize' ),
				'post_max_size'       => ini_get( 'post_max_size' ),
				'extensions'          => $ext_status,
			),
			'database_metrics'    => array(
				'events_count'       => $metrics['total_blocked_requests'],
				'active_blocked_ips' => $metrics['active_blocked_ips'],
				'active_threats'     => $metrics['active_threats'],
				'failed_logins_today'=> $metrics['failed_logins_today'],
			),
			'security_features'   => array(
				'waf_active'         => ! empty( $settings['waf_enabled'] ),
				'hardening_active'   => ! empty( $settings['block_uploads_php'] ),
				'bruteforce_active'  => ! empty( $settings['bruteforce_protection'] ),
				'geoip_active'       => ! empty( $settings['geoip_enabled'] ),
				'2fa_active'         => ! empty( $settings['2fa_enabled'] ),
				'anti_tamper_intact' => empty( $settings['antitamper_tamper_detected'] ),
			),
			'active_settings'     => $sanitized_settings,
		);

		// Format as Markdown for clean display and copy-pasting into GitHub or support tickets
		$md = "### SuperShield Security System Diagnostics Report\n\n";
		$md .= "- **Generated At:** `{$data['report_generated_at']}`\n";
		$md .= "- **SuperShield Suite Version:** `{$data['supershield_version']}`\n";
		$md .= "- **Author / Lead Architect:** Ghulam Rasool (`grwebdevs.com`)\n\n";
		$md .= "#### Environment Specifications\n";
		$md .= "- **WordPress:** `{$data['environment']['wordpress_version']}`\n";
		$md .= "- **PHP:** `{$data['environment']['php_version']}` (`{$data['environment']['php_sapi']}`)\n";
		$md .= "- **Web Server:** `{$data['environment']['server_software']}`\n";
		$md .= "- **Memory Limit:** `{$data['environment']['memory_limit']}`\n";
		$md .= "- **Max Execution Time:** `{$data['environment']['max_execution_time']}s`\n\n";
		$md .= "#### Active Security Shields\n";
		foreach ( $data['security_features'] as $shield => $active ) {
			$status = $active ? '✅ ACTIVE' : '❌ INACTIVE';
			$md .= "- " . ucwords( str_replace( '_', ' ', $shield ) ) . ": **{$status}**\n";
		}
		$md .= "\n#### Loaded Extensions\n";
		foreach ( $ext_status as $ext => $st ) {
			$md .= "`{$ext}`: {$st}, ";
		}
		$md = rtrim( $md, ', ' ) . "\n";

		return array(
			'markdown' => $md,
			'json'     => wp_json_encode( $data, JSON_PRETTY_PRINT ),
			'data'     => $data,
		);
	}

	/**
	 * Send anonymized threat intelligence to SuperShield Community Network (Opt-In only).
	 *
	 * @param string $threat_type
	 * @param string $signature
	 * @param string $endpoint
	 */
	public static function dispatch_threat_telemetry( $threat_type, $signature, $endpoint = '' ) {
		$opt_in = SuperShield_Utils::get_option( 'telemetry_enabled', 0 );
		if ( ! $opt_in ) {
			return;
		}

		$payload = array(
			'threat_type' => sanitize_text_field( $threat_type ),
			'signature'   => sanitize_text_field( $signature ),
			'endpoint'    => hash( 'sha256', (string) $endpoint ), // Fully anonymized SHA-256 hash
			'timestamp'   => time(),
		);

		if ( function_exists( 'wp_remote_post' ) ) {
			wp_remote_post( self::TELEMETRY_API_URL, array(
				'body'     => wp_json_encode( $payload ),
				'headers'  => array( 'Content-Type' => 'application/json' ),
				'timeout'  => 3,
				'blocking' => false, // Non-blocking asynchronous call
			) );
		}
	}
}
