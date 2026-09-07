<?php
/**
 * Database schema and operations for SuperShield Security.
 *
 * @package    SuperShield_Security
 * @subpackage SuperShield_Security/includes
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SuperShield_DB {

	/**
	 * Table names.
	 */
	public static function get_events_table() {
		global $wpdb;
		return $wpdb->prefix . 'supershield_events';
	}

	public static function get_blocked_ips_table() {
		global $wpdb;
		return $wpdb->prefix . 'supershield_blocked_ips';
	}

	public static function get_scan_issues_table() {
		global $wpdb;
		return $wpdb->prefix . 'supershield_scan_issues';
	}

	/**
	 * Create or update plugin database tables.
	 */
	public static function create_tables() {
		global $wpdb;

		$charset_collate = $wpdb->get_charset_collate();

		$events_table = self::get_events_table();
		$blocked_ips_table = self::get_blocked_ips_table();
		$scan_issues_table = self::get_scan_issues_table();

		$sql = "CREATE TABLE $events_table (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			event_type varchar(50) NOT NULL,
			ip_address varchar(45) NOT NULL,
			request_uri text,
			request_method varchar(10) DEFAULT 'GET',
			user_agent text,
			payload text,
			details text,
			created_at datetime DEFAULT CURRENT_TIMESTAMP NOT NULL,
			PRIMARY KEY  (id),
			KEY ip_address (ip_address),
			KEY event_type (event_type),
			KEY created_at (created_at)
		) $charset_collate;

		CREATE TABLE $blocked_ips_table (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			ip_address varchar(45) NOT NULL,
			reason text NOT NULL,
			block_type varchar(30) DEFAULT 'waf' NOT NULL,
			blocked_at datetime DEFAULT CURRENT_TIMESTAMP NOT NULL,
			expires_at datetime DEFAULT NULL,
			hits int(11) DEFAULT 1 NOT NULL,
			PRIMARY KEY  (id),
			UNIQUE KEY ip_address (ip_address),
			KEY expires_at (expires_at)
		) $charset_collate;

		CREATE TABLE $scan_issues_table (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			file_path text NOT NULL,
			issue_type varchar(50) NOT NULL,
			severity varchar(20) DEFAULT 'high' NOT NULL,
			details text,
			signature_name varchar(100),
			status varchar(30) DEFAULT 'active' NOT NULL,
			created_at datetime DEFAULT CURRENT_TIMESTAMP NOT NULL,
			updated_at datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP NOT NULL,
			PRIMARY KEY  (id),
			KEY issue_type (issue_type),
			KEY severity (severity),
			KEY status (status)
		) $charset_collate;";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );
		update_option( 'supershield_db_version', defined( 'SUPERSHIELD_VERSION' ) ? SUPERSHIELD_VERSION : '2.0.0' );
	}

	/**
	 * Insert an audit / firewall event into the log.
	 *
	 * @param string $event_type Event type.
	 * @param string $details Brief description or reasoning.
	 * @param string $payload Offending payload or suspicious query.
	 * @param string $ip Optional IP (defaults to client IP).
	 * @return int|false
	 */
	public static function log_event( $event_type, $details = '', $payload = '', $ip = null ) {
		global $wpdb;

		$ip = ( null !== $ip ) ? $ip : SuperShield_Utils::get_client_ip();
		$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		$request_method = isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : 'GET';
		$user_agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';

		// Trim payload to prevent DB bloat
		if ( strlen( $payload ) > 1000 ) {
			$payload = substr( $payload, 0, 1000 ) . '... [TRUNCATED]';
		}

		$table = self::get_events_table();

		return $wpdb->insert(
			$table,
			array(
				'event_type'     => sanitize_text_field( $event_type ),
				'ip_address'     => sanitize_text_field( $ip ),
				'request_uri'    => $request_uri,
				'request_method' => $request_method,
				'user_agent'     => $user_agent,
				'payload'        => $payload,
				'details'        => sanitize_text_field( $details ),
				'created_at'     => current_time( 'mysql' ),
			),
			array( '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s' )
		);
	}

	/**
	 * Block an IP address for a specific duration or permanently.
	 *
	 * @param string $ip IP address to block.
	 * @param string $reason Reason for blocking.
	 * @param string $block_type 'waf', 'bruteforce', or 'manual'.
	 * @param int    $duration_seconds Lockout duration in seconds (0 for permanent).
	 * @return bool
	 */
	public static function block_ip( $ip, $reason, $block_type = 'waf', $duration_seconds = 86400 ) {
		global $wpdb;

		$table = self::get_blocked_ips_table();
		$expires_at = ( $duration_seconds > 0 ) ? date( 'Y-m-d H:i:s', time() + $duration_seconds ) : null;

		// Check if already blocked
		$existing = $wpdb->get_row( $wpdb->prepare( "SELECT id, hits FROM $table WHERE ip_address = %s", $ip ) );

		if ( $existing ) {
			if ( null === $expires_at ) {
				return false !== $wpdb->query(
					$wpdb->prepare(
						"UPDATE $table SET reason = %s, block_type = %s, blocked_at = %s, expires_at = NULL, hits = %d WHERE id = %d",
						sanitize_text_field( $reason ),
						sanitize_text_field( $block_type ),
						current_time( 'mysql' ),
						(int) $existing->hits + 1,
						(int) $existing->id
					)
				);
			}
			return false !== $wpdb->update(
				$table,
				array(
					'reason'     => sanitize_text_field( $reason ),
					'block_type' => sanitize_text_field( $block_type ),
					'blocked_at' => current_time( 'mysql' ),
					'expires_at' => $expires_at,
					'hits'       => (int) $existing->hits + 1,
				),
				array( 'id' => $existing->id ),
				array( '%s', '%s', '%s', '%s', '%d' ),
				array( '%d' )
			);
		}

		if ( null === $expires_at ) {
			return false !== $wpdb->query(
				$wpdb->prepare(
					"INSERT INTO $table (ip_address, reason, block_type, blocked_at, expires_at, hits) VALUES (%s, %s, %s, %s, NULL, 1)",
					sanitize_text_field( $ip ),
					sanitize_text_field( $reason ),
					sanitize_text_field( $block_type ),
					current_time( 'mysql' )
				)
			);
		}

		return false !== $wpdb->insert(
			$table,
			array(
				'ip_address' => sanitize_text_field( $ip ),
				'reason'     => sanitize_text_field( $reason ),
				'block_type' => sanitize_text_field( $block_type ),
				'blocked_at' => current_time( 'mysql' ),
				'expires_at' => $expires_at,
				'hits'       => 1,
			),
			array( '%s', '%s', '%s', '%s', '%s', '%d' )
		);
	}

	/**
	 * Check if an IP address is currently blocked.
	 *
	 * @param string $ip Client IP.
	 * @return object|false
	 */
	public static function get_active_ip_block( $ip ) {
		global $wpdb;

		$table = self::get_blocked_ips_table();
		$now = current_time( 'mysql' );

		$result = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM $table WHERE ip_address = %s AND (expires_at IS NULL OR expires_at > %s)",
				$ip,
				$now
			)
		);

		return $result ? $result : false;
	}

	/**
	 * Unblock an IP address.
	 *
	 * @param string $ip IP address.
	 * @return bool
	 */
	public static function unblock_ip( $ip ) {
		global $wpdb;
		$table = self::get_blocked_ips_table();
		return (bool) $wpdb->delete( $table, array( 'ip_address' => $ip ), array( '%s' ) );
	}

	/**
	 * Track active issue IDs for the current scan run.
	 *
	 * @var array<int>
	 */
	private static $current_run_saved_ids = array();

	public static function reset_scan_run_ids() {
		self::$current_run_saved_ids = array();
	}

	public static function get_current_run_saved_ids() {
		return self::$current_run_saved_ids;
	}

	/**
	 * Store or update a detected scan issue.
	 *
	 * @param string $file_path File path or identifier.
	 * @param string $issue_type Issue classification.
	 * @param string $severity Critical, high, medium, low.
	 * @param string $details Detailed description.
	 * @param string $signature_name Identifier of matched signature.
	 * @return int|false
	 */
	public static function save_scan_issue( $file_path, $issue_type, $severity = 'high', $details = '', $signature_name = '' ) {
		global $wpdb;
		$table = self::get_scan_issues_table();

		// Check if active issue exists for this file
		$existing = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT id FROM $table WHERE file_path = %s AND status = 'active'",
				$file_path
			)
		);

		if ( $existing ) {
			$wpdb->update(
				$table,
				array(
					'issue_type'     => sanitize_text_field( $issue_type ),
					'severity'       => sanitize_text_field( $severity ),
					'details'        => sanitize_text_field( $details ),
					'signature_name' => sanitize_text_field( $signature_name ),
					'updated_at'     => current_time( 'mysql' ),
				),
				array( 'id' => $existing ),
				array( '%s', '%s', '%s', '%s', '%s' ),
				array( '%d' )
			);
			$id = (int) $existing;
			self::$current_run_saved_ids[] = $id;
			return $id;
		}

		$inserted = $wpdb->insert(
			$table,
			array(
				'file_path'      => sanitize_text_field( $file_path ),
				'issue_type'     => sanitize_text_field( $issue_type ),
				'severity'       => sanitize_text_field( $severity ),
				'details'        => sanitize_text_field( $details ),
				'signature_name' => sanitize_text_field( $signature_name ),
				'status'         => 'active',
				'created_at'     => current_time( 'mysql' ),
				'updated_at'     => current_time( 'mysql' ),
			),
			array( '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s' )
		);

		if ( $inserted ) {
			$id = (int) $wpdb->insert_id;
			self::$current_run_saved_ids[] = $id;
			return $id;
		}

		return false;
	}

	/**
	 * Purge old false positive entries from issues table.
	 */
	public static function purge_false_positives() {
		global $wpdb;
		$table = self::get_scan_issues_table();
		// Delete any issues referring to SuperShield plugin files or admin user ID 1
		$wpdb->query(
			"DELETE FROM $table 
			 WHERE file_path LIKE '%SSSECURITY%' 
			    OR file_path LIKE '%supershield%' 
			    OR file_path LIKE '%ID #1%'"
		);
	}

	/**
	 * Retrieve dashboard statistics.
	 *
	 * @return array
	 */
	public static function get_dashboard_metrics() {
		global $wpdb;

		$events_table = self::get_events_table();
		$blocked_table = self::get_blocked_ips_table();
		$issues_table = self::get_scan_issues_table();
		$now = current_time( 'mysql' );

		$total_blocked_requests = (int) $wpdb->get_var( "SELECT COUNT(*) FROM $events_table WHERE event_type = 'waf_block'" );
		$active_blocked_ips = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM $blocked_table WHERE expires_at IS NULL OR expires_at > %s", $now ) );
		$active_threats = (int) $wpdb->get_var( "SELECT COUNT(*) FROM $issues_table WHERE status = 'active'" );
		$failed_logins_today = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM $events_table WHERE event_type = 'login_fail' AND created_at >= %s", date( 'Y-m-d 00:00:00' ) ) );

		return array(
			'total_blocked_requests' => $total_blocked_requests,
			'active_blocked_ips'     => $active_blocked_ips,
			'active_threats'         => $active_threats,
			'failed_logins_today'    => $failed_logins_today,
		);
	}

	/**
	 * Purge old log events older than X days.
	 *
	 * @param int $days Retention days.
	 */
	public static function cleanup_old_logs( $days = 30 ) {
		global $wpdb;
		$table = self::get_events_table();
		$cutoff = date( 'Y-m-d H:i:s', strtotime( "-{$days} days" ) );
		$wpdb->query( $wpdb->prepare( "DELETE FROM $table WHERE created_at < %s", $cutoff ) );
	}
}
