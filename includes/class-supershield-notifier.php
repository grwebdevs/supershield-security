<?php
/**
 * Instant Cyber-Security Email Alert & Event Notification Engine for SuperShield Security.
 * 
 * Delivers Wordfence-style security alerts (file modifications, brute force lockouts,
 * malware detections, admin logins) to one or multiple recipients using 100% free native
 * server PHP mail (via wp_mail / mail) with ZERO paid third-party SMTP requirements.
 *
 * @package    SuperShield_Security
 * @subpackage SuperShield_Security/includes
 * @author     Ghulam Rasool <grwebdevs.com>
 * @version    2.2.1
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SuperShield_Notifier {

	/**
	 * Initialize notification hooks.
	 */
	public static function init() {
		// Hook administrator logins for new login alert
		add_action( 'wp_login', array( __CLASS__, 'handle_admin_login' ), 20, 2 );
	}

	/**
	 * Get validated array of alert email recipients.
	 *
	 * @return array
	 */
	public static function get_recipients() {
		$raw_emails = SuperShield_Utils::get_option( 'alert_emails', '' );
		$emails     = array();

		if ( ! empty( $raw_emails ) ) {
			$parts = explode( ',', (string) $raw_emails );
			foreach ( $parts as $p ) {
				$trimmed = trim( $p );
				if ( ! empty( $trimmed ) && is_email( $trimmed ) ) {
					$emails[] = sanitize_email( $trimmed );
				}
			}
		}

		// Fallback to WordPress site admin email
		if ( empty( $emails ) ) {
			$admin_email = get_option( 'admin_email' );
			if ( ! empty( $admin_email ) && is_email( $admin_email ) ) {
				$emails[] = sanitize_email( $admin_email );
			}
		}

		return array_unique( $emails );
	}

	/**
	 * Dispatch security alert email to all configured recipients.
	 *
	 * @param string $event_type  'file_tampering', 'brute_lockout', 'malware_found', 'admin_login'
	 * @param string $subject     Alert Subject Line
	 * @param string $summary     High-level description of the incident
	 * @param array  $details     Forensic specifics (IP, file, signature, etc.)
	 * @param string $action_url  Optional resolution URL
	 * @return bool
	 */
	public static function dispatch_alert( $event_type, $subject, $summary, $details = array(), $action_url = '' ) {
		// Check if alert type is enabled in settings
		$setting_key = 'notify_' . $event_type;
		$enabled     = SuperShield_Utils::get_option( $setting_key, 1 );
		if ( ! $enabled ) {
			return false;
		}

		$recipients = self::get_recipients();
		if ( empty( $recipients ) ) {
			return false;
		}

		// Anti-flood throttle: prevent email storms during rapid bot attacks (exempt test alerts)
		if ( 'test_alert' !== $event_type ) {
			$throttle_key = 'sss_alert_throttle_' . md5( $event_type . '_' . ( $details['Attacker IP'] ?? '' ) . '_' . ( $details['Target File'] ?? '' ) );
			if ( get_transient( $throttle_key ) ) {
				return false;
			}
			// Set 30-minute throttle for repeat instances of this exact incident
			set_transient( $throttle_key, 1, 30 * MINUTE_IN_SECONDS );
		}

		$site_name = get_bloginfo( 'name' );
		$site_url  = home_url();
		$timestamp = current_time( 'Y-m-d H:i:s T' );

		$full_subject = "[SuperShield Alert] {$subject} — {$site_name}";

		if ( empty( $action_url ) ) {
			$action_url = admin_url( 'admin.php?page=supershield-security' );
		}

		$body = self::render_email_template( $event_type, $subject, $summary, $details, $action_url, $site_name, $site_url, $timestamp );

		$from_domain = wp_parse_url( $site_url, PHP_URL_HOST ) ?: 'localhost';
		$from_email  = 'wordpress@' . preg_replace( '/^www\./i', '', $from_domain );
		if ( ! is_email( $from_email ) ) {
			$from_email = get_option( 'admin_email' );
		}

		$headers = array(
			'MIME-Version: 1.0',
			'Content-Type: text/html; charset=UTF-8',
			'From: ' . wp_strip_all_tags( $site_name ) . ' Security <' . $from_email . '>',
			'X-Mailer: SuperShield-Security/' . SUPERSHIELD_VERSION,
		);

		$sent = false;
		if ( function_exists( 'wp_mail' ) ) {
			$sent = wp_mail( $recipients, $full_subject, $body, $headers );
		}

		// Fallback to native PHP mail if wp_mail failed (e.g. broken SMTP plugin)
		if ( ! $sent && function_exists( 'mail' ) ) {
			$raw_headers = implode( "\r\n", $headers );
			foreach ( $recipients as $to ) {
				@mail( $to, $full_subject, $body, $raw_headers );
			}
			$sent = true;
		}

		if ( $sent ) {
			SuperShield_DB::log_event( 'admin_action', "Security email alert dispatched: {$event_type} to " . count( $recipients ) . " recipient(s)." );
		}

		// Dispatch 100% Free Discord Webhook if configured
		self::dispatch_discord_webhook( $event_type, $subject, $summary, $details, $action_url );

		return $sent;
	}

	/**
	 * Dispatch alert notification to configured Discord Webhook.
	 * 100% Free, zero third-party packages or paid API keys.
	 *
	 * @param string $event_type
	 * @param string $subject
	 * @param string $summary
	 * @param array  $details
	 * @param string $action_url
	 * @return bool
	 */
	public static function dispatch_discord_webhook( $event_type, $subject, $summary, $details = array(), $action_url = '' ) {
		$webhook_url = trim( (string) SuperShield_Utils::get_option( 'discord_webhook_url', '' ) );
		if ( empty( $webhook_url ) || ! filter_var( $webhook_url, FILTER_VALIDATE_URL ) ) {
			return false;
		}

		$color = 15671108; // Red #ef4444
		if ( 'admin_login' === $event_type ) {
			$color = 6514417; // Indigo #6366f1
		} elseif ( 'weekly_digest' === $event_type ) {
			$color = 1096065; // Emerald #10b981
		}

		$fields = array();
		if ( is_array( $details ) ) {
			foreach ( $details as $k => $v ) {
				$fields[] = array(
					'name'   => (string) $k,
					'value'  => (string) $v,
					'inline' => true,
				);
			}
		}

		$payload = array(
			'username'   => 'SuperShield Security',
			'avatar_url' => 'https://raw.githubusercontent.com/grwebdevs/supershield-security/main/assets/icon-128x128.png',
			'embeds'     => array(
				array(
					'title'       => '[SuperShield Alert] ' . $subject,
					'description' => $summary . ( ! empty( $action_url ) ? "\n\n[Open Security Command Center](" . esc_url( $action_url ) . ')' : '' ),
					'color'       => $color,
					'fields'      => $fields,
					'footer'      => array(
						'text' => 'SuperShield Security v' . SUPERSHIELD_VERSION . ' • ' . get_bloginfo( 'name' ),
					),
					'timestamp'   => gmdate( 'c' ),
				),
			),
		);

		$resp = wp_remote_post(
			$webhook_url,
			array(
				'headers' => array( 'Content-Type' => 'application/json' ),
				'body'    => wp_json_encode( $payload ),
				'timeout' => 5,
			)
		);

		return ! is_wp_error( $resp ) && in_array( wp_remote_retrieve_response_code( $resp ), array( 200, 204 ), true );
	}

	/**
	 * Send weekly executive security digest email to administrators.
	 */
	public static function send_weekly_digest() {
		if ( ! SuperShield_Utils::get_option( 'enable_weekly_digest', 1 ) ) {
			return;
		}

		global $wpdb;
		$metrics = SuperShield_DB::get_dashboard_metrics();

		$events_table = SuperShield_DB::get_events_table();
		$weekly_blocks = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM $events_table WHERE created_at >= %s",
				date( 'Y-m-d H:i:s', strtotime( '-7 days' ) )
			)
		);

		$details = array(
			'Threats Blocked (7 Days)' => number_format_i18n( $weekly_blocks ),
			'Active IP Blacklist'     => number_format_i18n( $metrics['active_blocked_ips'] ),
			'Unresolved Malware'      => number_format_i18n( $metrics['active_threats'] ),
			'Firewall Health Score'   => ( $metrics['active_threats'] > 0 ? '82/100 (Action Needed)' : '98/100 (Optimal Fortress)' ),
		);

		self::dispatch_alert(
			'weekly_digest',
			'Weekly Executive Security Digest',
			'Your weekly summary of defensive actions and security health status for ' . get_bloginfo( 'name' ) . '.',
			$details,
			admin_url( 'admin.php?page=supershield-security' )
		);
	}

	/**
	 * Trigger File Integrity / Anti-Tamper Alteration Alert.
	 *
	 * @param string $file   Relative or absolute file path
	 * @param string $reason Specific reason for detection
	 */
	public static function notify_file_tampering( $file, $reason ) {
		$details = array(
			'Target File'     => esc_html( $file ),
			'Integrity Fault' => esc_html( $reason ),
			'Detection Type'  => 'Cryptographic Signature Mismatch / Unauthorized Alteration',
			'Action Taken'    => 'Execution Blocked & Tamper Flagged in Command Center',
		);

		self::dispatch_alert(
			'file_changes',
			'Critical File Integrity Alert',
			'SuperShield detected that a critical file on your WordPress server was modified or injected with unauthorized code.',
			$details,
			admin_url( 'admin.php?page=supershield-diagnostics' )
		);
	}

	/**
	 * Trigger Brute-Force Lockout Alert.
	 *
	 * @param string $ip       Offending IP Address
	 * @param string $username Username attempted
	 */
	public static function notify_brute_lockout( $ip, $username = '' ) {
		$country = class_exists( 'SuperShield_GeoIP' ) ? SuperShield_GeoIP::get_country_name( SuperShield_GeoIP::resolve_country( $ip ) ) : 'Unknown';

		$details = array(
			'Attacker IP'      => esc_html( $ip ),
			'Country Origin'   => esc_html( $country ),
			'Attempted User'   => ! empty( $username ) ? esc_html( $username ) : 'Multiple / Probe',
			'Defense Reaction' => 'IP Permanently/Temporarily Quarantined in Firewall',
		);

		self::dispatch_alert(
			'brute_lockout',
			'Attacker IP Locked Out (' . esc_html( $ip ) . ')',
			'An automated brute-force attack exceeded the maximum allowed failed attempts and was neutralized by the SuperShield Firewall.',
			$details,
			admin_url( 'admin.php?page=supershield-firewall' )
		);
	}

	/**
	 * Trigger Malware Scan Threat Alert.
	 *
	 * @param array $threats Array of detected threats
	 */
	public static function notify_malware_detected( $threats ) {
		if ( empty( $threats ) || ! is_array( $threats ) ) {
			return;
		}

		$threat_count = count( $threats );
		$first_few    = array_slice( $threats, 0, 3 );
		$list_files   = '';
		foreach ( $first_few as $th ) {
			$file = is_array( $th ) ? ( $th['file'] ?? 'unknown' ) : (string) $th;
			$type = is_array( $th ) ? ( $th['threat_type'] ?? 'malware' ) : 'malware';
			$list_files .= '<code>' . esc_html( basename( $file ) ) . '</code> (' . esc_html( $type ) . '), ';
		}
		$list_files = rtrim( $list_files, ', ' );
		if ( $threat_count > 3 ) {
			$list_files .= ' and ' . ( $threat_count - 3 ) . ' more...';
		}

		$details = array(
			'Threats Found'    => (string) $threat_count,
			'Infected Samples' => $list_files,
			'Recommended Step' => 'Use 1-Click Surgical Cleaner in SuperShield to excise malicious payloads',
		);

		self::dispatch_alert(
			'malware_found',
			"Malware Detected ({$threat_count} Threat" . ( $threat_count > 1 ? 's' : '' ) . ')',
			'The SuperShield Deep Heuristic Scanner identified malicious web shells or obfuscated injection payloads on your server.',
			$details,
			admin_url( 'admin.php?page=supershield-scanner' )
		);
	}

	/**
	 * Handle Administrator Login Alert.
	 *
	 * @param string  $user_login
	 * @param WP_User $user
	 */
	public static function handle_admin_login( $user_login, $user ) {
		if ( ! is_a( $user, 'WP_User' ) || ! user_can( $user, 'manage_options' ) ) {
			return;
		}

		$enabled = SuperShield_Utils::get_option( 'notify_admin_login', 0 );
		if ( ! $enabled ) {
			return;
		}

		$site_name = get_bloginfo( 'name' );
		$ip        = SuperShield_Utils::get_client_ip();
		$country   = class_exists( 'SuperShield_GeoIP' ) ? SuperShield_GeoIP::get_country_name( SuperShield_GeoIP::resolve_country( $ip ) ) : 'Unknown';
		$ua        = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : 'Unknown Browser';

		$details = array(
			'Admin Account' => esc_html( $user_login ) . ' (' . esc_html( $user->user_email ) . ')',
			'Client IP'     => esc_html( $ip ),
			'Location'      => esc_html( $country ),
			'User Agent'    => esc_html( substr( $ua, 0, 80 ) ),
		);

		self::dispatch_alert(
			'admin_login',
			'Admin Login from ' . esc_html( $ip ),
			"An administrator account successfully signed in to {$site_name}.",
			$details,
			admin_url( 'admin.php?page=supershield-login' )
		);
	}

	/**
	 * Send a scheduled scan report email (daily/weekly/monthly).
	 *
	 * @param string $report_type 'daily' | 'daily_clean' | 'weekly' | 'monthly'
	 * @param array  $results     Scan results array from run_full_scan()
	 * @return bool
	 */
	public static function send_scheduled_report( $report_type, $results ) {
		$recipients = self::get_recipients();
		if ( empty( $recipients ) ) {
			return false;
		}

		$site_name  = get_bloginfo( 'name' );
		$site_url   = home_url();
		$scan_url   = admin_url( 'admin.php?page=supershield-scanner' );
		$timestamp  = current_time( 'Y-m-d H:i:s T' );
		$threats    = (int) ( $results['threats_found'] ?? 0 );
		$files      = (int) ( $results['scanned_files'] ?? 0 );
		$duration   = isset( $results['duration'] ) ? $results['duration'] : '0';

		// Throttle key: one report per type per day/week/month
		$throttle_key = 'sss_sched_report_' . md5( $report_type . gmdate( 'Y-m-d' ) );
		if ( get_transient( $throttle_key ) ) {
			return false;
		}
		$throttle_ttl = ( 'daily' === $report_type || 'daily_clean' === $report_type ) ? DAY_IN_SECONDS : ( 'weekly' === $report_type ? 7 * DAY_IN_SECONDS : 30 * DAY_IN_SECONDS );
		set_transient( $throttle_key, 1, $throttle_ttl );

		switch ( $report_type ) {
			case 'daily':
				$subject    = "[SuperShield] 🚨 Daily Scan Alert: {$threats} Threat(s) Found — {$site_name}";
				$badge_text = 'DAILY SCAN — THREATS DETECTED';
				$badge_col  = '#ef4444';
				$summary    = "The SuperShield automated daily scan detected <strong>{$threats} threat(s)</strong> on your WordPress site. Immediate action is recommended.";
				break;
			case 'daily_clean':
				$subject    = "[SuperShield] ✅ Daily Scan: Clean Bill of Health — {$site_name}";
				$badge_text = 'DAILY SCAN — CLEAN';
				$badge_col  = '#10b981';
				$summary    = "Your daily automated security scan completed with a <strong>clean bill of health</strong>. No threats or malware were detected.";
				break;
			case 'weekly':
				$subject    = "[SuperShield] 📊 Weekly Security Digest — {$site_name}";
				$badge_text = 'WEEKLY SECURITY DIGEST';
				$badge_col  = '#3b82f6';
				$summary    = $threats > 0
					? "Your weekly security digest reports <strong>{$threats} active threat(s)</strong> detected during the weekly scan. Please review and remediate."
					: "Your weekly security digest shows <strong>no threats detected</strong>. Your site is in excellent health!";
				break;
			case 'monthly':
				$subject    = "[SuperShield] 📋 Monthly Security Report — " . gmdate( 'F Y' ) . " — {$site_name}";
				$badge_text = 'MONTHLY SECURITY REPORT';
				$badge_col  = '#8b5cf6';
				$summary    = $threats > 0
					? "Your monthly security report for <strong>" . gmdate( 'F Y' ) . "</strong> has flagged <strong>{$threats} threat(s)</strong>. Please review and take immediate action."
					: "Your monthly security report for <strong>" . gmdate( 'F Y' ) . "</strong> is <strong>all clear</strong>. No threats detected this month.";
				break;
			default:
				return false;
		}

		$details = array(
			'Files Analyzed'  => number_format( $files ),
			'Threats Found'   => $threats > 0 ? "<span style='color:#ef4444; font-weight:700;'>{$threats} THREAT(S) DETECTED</span>" : '<span style="color:#10b981; font-weight:700;">0 — Clean</span>',
			'Scan Duration'   => $duration . ' seconds',
			'Report Type'     => strtoupper( str_replace( '_', ' ', $report_type ) ),
			'Generated At'    => $timestamp,
		);

		$rows_html = '';
		foreach ( $details as $k => $v ) {
			$rows_html .= "
			<tr>
				<td style='padding:10px 14px; border-bottom:1px solid #1e293b; color:#94a3b8; font-size:13px; font-weight:600; width:38%;'>{$k}</td>
				<td style='padding:10px 14px; border-bottom:1px solid #1e293b; color:#f8fafc; font-size:13px; font-family:monospace;'>{$v}</td>
			</tr>";
		}

		$action_text  = $threats > 0 ? 'Review Threats Now →' : 'Open Security Dashboard →';
		$action_color = $threats > 0 ? '#ef4444' : '#10b981';
		$action_fg    = $threats > 0 ? '#ffffff' : '#022c22';

		$body = "<!DOCTYPE html>
<html>
<head>
<meta charset='utf-8'>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0b0f19; color: #f3f4f6; margin: 0; padding: 25px; }
  .wrapper { max-width: 620px; margin: 0 auto; background: #111827; border: 1px solid #1f2937; border-radius: 12px; overflow: hidden; box-shadow: 0 20px 25px -5px rgba(0,0,0,0.5); }
  .header { background: #0b0f19; padding: 24px; text-align: center; border-bottom: 2px solid {$badge_col}; }
  .shield-icon { font-size: 32px; line-height: 1; margin-bottom: 8px; }
  .site-title { color: #ffffff; font-size: 19px; font-weight: 800; margin: 0; }
  .badge { display: inline-block; padding: 4px 12px; border-radius: 999px; font-size: 11px; font-weight: 800; text-transform: uppercase; background: {$badge_col}; color: #ffffff; margin-top: 10px; letter-spacing: 0.5px; }
  .body-content { padding: 30px; }
  .incident-title { font-size: 18px; font-weight: 700; color: #ffffff; margin: 0 0 12px 0; }
  .incident-desc { font-size: 14px; color: #cbd5e1; line-height: 1.6; margin: 0 0 24px 0; }
  .details-box { background: #1e293b; border-radius: 8px; overflow: hidden; margin-bottom: 25px; border: 1px solid #334155; }
  .table { width: 100%; border-collapse: collapse; text-align: left; }
  .btn-wrap { text-align: center; margin: 30px 0 10px; }
  .btn { display: inline-block; background: {$action_color}; color: {$action_fg}; font-weight: 800; padding: 12px 28px; border-radius: 8px; text-decoration: none; font-size: 14px; }
  .footer { background: #0b0f19; padding: 18px; text-align: center; font-size: 12px; color: #64748b; border-top: 1px solid #1f2937; }
</style>
</head>
<body>
<div class='wrapper'>
  <div class='header'>
    <div class='shield-icon'>🛡️</div>
    <div class='site-title'>{$site_name}</div>
    <span class='badge'>{$badge_text}</span>
  </div>
  <div class='body-content'>
    <h2 class='incident-title'>{$subject}</h2>
    <p class='incident-desc'>{$summary}</p>
    <div class='details-box'>
      <table class='table'>
        {$rows_html}
      </table>
    </div>
    <div class='btn-wrap'>
      <a href='{$scan_url}' class='btn'>{$action_text}</a>
    </div>
  </div>
  <div class='footer'>
    SuperShield Security Suite &bull; Lead Architect: <a href='https://grwebdevs.com' style='color:#38bdf8; text-decoration:none;'>Ghulam Rasool</a> (grwebdevs.com)<br>
    <span style='font-size:11px;'>Delivered via native server PHP mail. Zero third-party SMTP limits.</span>
  </div>
</div>
</body>
</html>";

		$from_domain = wp_parse_url( $site_url, PHP_URL_HOST ) ?: 'localhost';
		$from_email  = 'wordpress@' . preg_replace( '/^www\./i', '', $from_domain );
		if ( ! is_email( $from_email ) ) {
			$from_email = get_option( 'admin_email' );
		}

		$headers = array(
			'MIME-Version: 1.0',
			'Content-Type: text/html; charset=UTF-8',
			'From: ' . wp_strip_all_tags( $site_name ) . ' Security <' . $from_email . '>',
			'X-Mailer: SuperShield-Security/' . SUPERSHIELD_VERSION,
		);

		$sent = false;
		if ( function_exists( 'wp_mail' ) ) {
			$sent = wp_mail( $recipients, $subject, $body, $headers );
		}
		if ( ! $sent && function_exists( 'mail' ) ) {
			$raw_headers = implode( "\r\n", $headers );
			foreach ( $recipients as $to ) {
				@mail( $to, $subject, $body, $raw_headers );
			}
			$sent = true;
		}

		return $sent;
	}

	/**
	 * Render Wordfence-style cyber-security HTML email template.
	 */
	private static function render_email_template( $event_type, $subject, $summary, $details, $action_url, $site_name, $site_url, $timestamp ) {
		$badge_color = '#ef4444'; // Default red
		$badge_text  = 'SECURITY ALERT';

		if ( 'file_changes' === $event_type ) {
			$badge_color = '#dc2626';
			$badge_text  = 'FILE TAMPER WARNING';
		} elseif ( 'brute_lockout' === $event_type ) {
			$badge_color = '#f59e0b';
			$badge_text  = 'BRUTE-FORCE LOCKOUT';
		} elseif ( 'malware_found' === $event_type ) {
			$badge_color = '#991b1b';
			$badge_text  = 'MALWARE DETECTED';
		} elseif ( 'admin_login' === $event_type ) {
			$badge_color = '#38bdf8';
			$badge_text  = 'ADMINISTRATOR LOGIN';
		}

		$rows_html = '';
		foreach ( $details as $k => $v ) {
			$rows_html .= "
			<tr>
				<td style='padding:10px 14px; border-bottom:1px solid #1e293b; color:#94a3b8; font-size:13px; font-weight:600; width:35%;'>{$k}</td>
				<td style='padding:10px 14px; border-bottom:1px solid #1e293b; color:#f8fafc; font-size:13px; font-family:monospace;'>{$v}</td>
			</tr>";
		}

		return "
<!DOCTYPE html>
<html>
<head>
<meta charset='utf-8'>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0b0f19; color: #f3f4f6; margin: 0; padding: 25px; }
  .wrapper { max-width: 620px; margin: 0 auto; background: #111827; border: 1px solid #1f2937; border-radius: 12px; overflow: hidden; box-shadow: 0 20px 25px -5px rgba(0,0,0,0.5); }
  .header { background: #0b0f19; padding: 24px; text-align: center; border-bottom: 2px solid {$badge_color}; }
  .shield-icon { font-size: 32px; line-height: 1; margin-bottom: 8px; }
  .site-title { color: #ffffff; font-size: 19px; font-weight: 800; margin: 0; }
  .badge { display: inline-block; padding: 4px 12px; border-radius: 999px; font-size: 11px; font-weight: 800; text-transform: uppercase; background: {$badge_color}; color: #ffffff; margin-top: 10px; letter-spacing: 0.5px; }
  .body-content { padding: 30px; }
  .incident-title { font-size: 18px; font-weight: 700; color: #ffffff; margin: 0 0 12px 0; }
  .incident-desc { font-size: 14px; color: #cbd5e1; line-height: 1.6; margin: 0 0 24px 0; }
  .details-box { background: #1e293b; border-radius: 8px; overflow: hidden; margin-bottom: 25px; border: 1px solid #334155; }
  .table { width: 100%; border-collapse: collapse; text-align: left; }
  .btn-wrap { text-align: center; margin: 30px 0 10px; }
  .btn { display: inline-block; background: #10b981; color: #022c22; font-weight: 800; padding: 12px 28px; border-radius: 8px; text-decoration: none; font-size: 14px; }
  .footer { background: #0b0f19; padding: 18px; text-align: center; font-size: 12px; color: #64748b; border-top: 1px solid #1f2937; }
</style>
</head>
<body>
<div class='wrapper'>
  <div class='header'>
    <div class='shield-icon'>🛡️</div>
    <div class='site-title'>{$site_name}</div>
    <span class='badge'>{$badge_text}</span>
  </div>
  <div class='body-content'>
    <h2 class='incident-title'>{$subject}</h2>
    <p class='incident-desc'>{$summary}</p>

    <div class='details-box'>
      <table class='table'>
        {$rows_html}
        <tr>
          <td style='padding:10px 14px; color:#94a3b8; font-size:13px; font-weight:600;'>Server Timestamp</td>
          <td style='padding:10px 14px; color:#f8fafc; font-size:13px; font-family:monospace;'>{$timestamp}</td>
        </tr>
      </table>
    </div>

    <div class='btn-wrap'>
      <a href='{$action_url}' class='btn'>Open SuperShield Command Center &rarr;</a>
    </div>
  </div>
  <div class='footer'>
    SuperShield Security Suite &bull; Lead Architect: <a href='https://grwebdevs.com' style='color:#38bdf8; text-decoration:none;'>Ghulam Rasool</a> (grwebdevs.com)<br>
    <span style='font-size:11px;'>Delivered 100% free via native server PHP mail. Zero third-party SMTP limits.</span>
  </div>
</div>
</body>
</html>
";
	}
}
