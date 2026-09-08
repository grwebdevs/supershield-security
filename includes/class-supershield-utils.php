<?php
/**
 * Utility functions for SuperShield Security.
 *
 * @package    SuperShield_Security
 * @subpackage SuperShield_Security/includes
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SuperShield_Utils {

	/**
	 * Retrieve client IP address with protection against header spoofing.
	 *
	 * Only trusts proxy headers (Cloudflare / X-Forwarded-For) if trust_proxy_headers
	 * is enabled or REMOTE_ADDR is an established internal proxy.
	 *
	 * @return string Validated IP address or '127.0.0.1' fallback.
	 */
	/**
	 * Official Cloudflare IPv4 & IPv6 CIDR Subnet Ranges.
	 *
	 * @var array<string>
	 */
	private static $cloudflare_ranges = array(
		'173.245.48.0/20',
		'103.21.244.0/22',
		'103.22.200.0/22',
		'103.31.4.0/22',
		'141.101.64.0/18',
		'108.162.192.0/18',
		'190.93.240.0/20',
		'188.114.96.0/20',
		'197.234.240.0/22',
		'198.41.128.0/17',
		'162.158.0.0/15',
		'104.16.0.0/13',
		'104.24.0.0/14',
		'172.64.0.0/13',
		'131.0.72.0/22',
		'2400:cb00::/32',
		'2606:4700::/32',
		'2803:f800::/32',
		'2405:b500::/32',
		'2405:8100::/32',
		'2a06:98c0::/29',
		'2c0f:f248::/32',
	);

	/**
	 * Check if an IP address belongs to Cloudflare's edge proxy network.
	 *
	 * @param string $ip
	 * @return bool
	 */
	public static function is_cloudflare_ip( $ip ) {
		$ip = trim( (string) $ip );
		if ( empty( $ip ) ) {
			return false;
		}
		foreach ( self::$cloudflare_ranges as $range ) {
			if ( self::ip_in_range( $ip, $range ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Check if an IP is a local loopback or private subnet.
	 *
	 * @param string $ip
	 * @return bool
	 */
	public static function is_loopback_or_private( $ip ) {
		$ip = trim( (string) $ip );
		if ( '127.0.0.1' === $ip || '::1' === $ip ) {
			return true;
		}
		return ( ! filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) );
	}

	/**
	 * Retrieve real client IP address with protection against header spoofing.
	 *
	 * Only trusts proxy headers (Cloudflare / X-Forwarded-For) if trust_proxy_headers
	 * is enabled, REMOTE_ADDR is an established internal proxy, or REMOTE_ADDR
	 * belongs to Cloudflare's verified network ranges.
	 *
	 * @return string Validated IP address or '127.0.0.1' fallback.
	 */
	public static function get_client_ip() {
		$remote_addr = isset( $_SERVER['REMOTE_ADDR'] ) ? trim( (string) $_SERVER['REMOTE_ADDR'] ) : '127.0.0.1';

		// Determine if proxy headers can be trusted
		$trust_proxy = self::get_option( 'trust_proxy_headers', 0 );
		$is_private_remote = ! filter_var( $remote_addr, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE );
		$is_cloudflare_remote = self::is_cloudflare_ip( $remote_addr );

		if ( $trust_proxy || $is_private_remote || $is_cloudflare_remote ) {
			$headers = array(
				'HTTP_CF_CONNECTING_IP',
				'HTTP_X_REAL_IP',
				'HTTP_X_FORWARDED_FOR',
				'HTTP_CLIENT_IP',
			);

			foreach ( $headers as $header ) {
				if ( ! empty( $_SERVER[ $header ] ) ) {
					$raw_ip = sanitize_text_field( wp_unslash( $_SERVER[ $header ] ) );
					$ip_list = explode( ',', $raw_ip );
					foreach ( $ip_list as $ip ) {
						$ip = trim( $ip );
						if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
							return $ip;
						}
					}
				}
			}
		}

		if ( filter_var( $remote_addr, FILTER_VALIDATE_IP ) ) {
			return $remote_addr;
		}

		return '127.0.0.1';
	}

	/**
	 * Check if an IP matches a CIDR subnet or single IP (supports IPv4 & IPv6).
	 *
	 * @param string $ip Client IP.
	 * @param string $range IP range (e.g. 192.168.1.0/24 or 2001:db8::/32 or single IP).
	 * @return bool
	 */
	public static function ip_in_range( $ip, $range ) {
		$ip = trim( (string) $ip );
		$range = trim( (string) $range );

		if ( empty( $ip ) || empty( $range ) ) {
			return false;
		}

		// Single IP exact match
		if ( strpos( $range, '/' ) === false ) {
			if ( $ip === $range ) {
				return true;
			}
			$ip_bin = @inet_pton( $ip );
			$range_bin = @inet_pton( $range );
			return ( false !== $ip_bin && false !== $range_bin && $ip_bin === $range_bin );
		}

		list( $subnet, $bits ) = explode( '/', $range, 2 );
		$bits = (int) $bits;

		$ip_bin = @inet_pton( $ip );
		$subnet_bin = @inet_pton( $subnet );

		if ( false === $ip_bin || false === $subnet_bin ) {
			return false;
		}

		// Ensure both are same address family
		if ( strlen( $ip_bin ) !== strlen( $subnet_bin ) ) {
			return false;
		}

		// IPv4
		if ( 4 === strlen( $ip_bin ) ) {
			if ( $bits < 0 || $bits > 32 ) {
				return false;
			}
			if ( 0 === $bits ) {
				return true;
			}
			$ip_dec = ip2long( $ip );
			$subnet_dec = ip2long( $subnet );
			$mask = -1 << ( 32 - $bits );
			return ( ( $ip_dec & $mask ) === ( $subnet_dec & $mask ) );
		}

		// IPv6
		if ( 16 === strlen( $ip_bin ) ) {
			if ( $bits < 0 || $bits > 128 ) {
				return false;
			}
			if ( 0 === $bits ) {
				return true;
			}
			$bytes = (int) floor( $bits / 8 );
			$remainder = $bits % 8;

			if ( $bytes > 0 && substr( $ip_bin, 0, $bytes ) !== substr( $subnet_bin, 0, $bytes ) ) {
				return false;
			}

			if ( $remainder > 0 ) {
				$mask = 0xFF << ( 8 - $remainder );
				$ip_byte = ord( $ip_bin[ $bytes ] );
				$subnet_byte = ord( $subnet_bin[ $bytes ] );
				if ( ( $ip_byte & $mask ) !== ( $subnet_byte & $mask ) ) {
					return false;
				}
			}

			return true;
		}

		return false;
	}

	/**
	 * Safely retrieve plugin options with fallback defaults.
	 *
	 * @param string $key Option key.
	 * @param mixed  $default Default value.
	 * @return mixed
	 */
	public static function get_option( $key, $default = null ) {
		$options = get_option( 'supershield_settings', array() );
		if ( is_array( $options ) && isset( $options[ $key ] ) ) {
			return $options[ $key ];
		}
		return $default;
	}

	/**
	 * Update single setting key.
	 *
	 * @param string $key Option key.
	 * @param mixed  $value Value.
	 * @return bool
	 */
	public static function update_option( $key, $value ) {
		$options = get_option( 'supershield_settings', array() );
		if ( ! is_array( $options ) ) {
			$options = array();
		}
		$options[ $key ] = $value;
		return update_option( 'supershield_settings', $options );
	}

	/**
	 * Detect Web Server environment.
	 *
	 * @return string 'apache', 'nginx', 'litespeed', 'iis', or 'unknown'
	 */
	public static function get_server_type() {
		$software = isset( $_SERVER['SERVER_SOFTWARE'] ) ? strtolower( $_SERVER['SERVER_SOFTWARE'] ) : '';

		if ( strpos( $software, 'litespeed' ) !== false ) {
			return 'litespeed';
		} elseif ( strpos( $software, 'nginx' ) !== false ) {
			return 'nginx';
		} elseif ( strpos( $software, 'apache' ) !== false ) {
			return 'apache';
		} elseif ( strpos( $software, 'microsoft-iis' ) !== false ) {
			return 'iis';
		}

		return 'unknown';
	}

	/**
	 * Compute overall site security score (0 - 100%).
	 *
	 * @return array Array with score (int), grade (string), and checklist breakdown.
	 */
	public static function calculate_security_score() {
		$points = 0;
		$checks = array();

		// 1. WAF Enabled (15 pts)
		$waf_enabled = self::get_option( 'waf_enabled', 1 );
		if ( $waf_enabled ) {
			$points += 15;
			$checks['waf'] = array( 'label' => 'Web Application Firewall Active', 'status' => 'pass', 'pts' => 15 );
		} else {
			$checks['waf'] = array( 'label' => 'Web Application Firewall Disabled', 'status' => 'fail', 'pts' => 0 );
		}

		// 2. Uploads PHP Execution Blocked (10 pts) - Layer 1
		$uploads_blocked = self::get_option( 'block_uploads_php', 1 );
		if ( $uploads_blocked ) {
			$points += 10;
			$checks['uploads_php'] = array( 'label' => 'PHP Execution Blocked in Uploads (Layer 1)', 'status' => 'pass', 'pts' => 10 );
		} else {
			$checks['uploads_php'] = array( 'label' => 'Uploads Directory PHP Execution Allowed', 'status' => 'fail', 'pts' => 0 );
		}

		// 3. XML-RPC Disabled (8 pts) - Layer 2
		$xmlrpc_blocked = self::get_option( 'disable_xmlrpc', 1 );
		if ( $xmlrpc_blocked ) {
			$points += 8;
			$checks['xmlrpc'] = array( 'label' => 'XML-RPC Attack Surface Disabled (Layer 2)', 'status' => 'pass', 'pts' => 8 );
		} else {
			$checks['xmlrpc'] = array( 'label' => 'XML-RPC Enabled (Brute-force risk)', 'status' => 'fail', 'pts' => 0 );
		}

		// 4. Anti-User Enumeration (8 pts) - Layer 3
		$anti_enum = self::get_option( 'block_user_enumeration', 1 );
		if ( $anti_enum ) {
			$points += 8;
			$checks['anti_enum'] = array( 'label' => 'User Enumeration Blocked (Layer 3)', 'status' => 'pass', 'pts' => 8 );
		} else {
			$checks['anti_enum'] = array( 'label' => 'Usernames Exposed via REST/Author queries', 'status' => 'fail', 'pts' => 0 );
		}

		// 5. Admin File Editor Lockdown (8 pts) - Layer 4
		$disallow_editor = self::get_option( 'disallow_file_edit', 1 ) || ( defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT );
		if ( $disallow_editor ) {
			$points += 8;
			$checks['file_editor'] = array( 'label' => 'Theme/Plugin File Editor Disabled (Layer 4)', 'status' => 'pass', 'pts' => 8 );
		} else {
			$checks['file_editor'] = array( 'label' => 'Theme/Plugin File Editor Enabled in Admin', 'status' => 'fail', 'pts' => 0 );
		}

		// 6. Security Headers (8 pts) - Layer 5
		$sec_headers = self::get_option( 'security_headers', 1 );
		if ( $sec_headers ) {
			$points += 8;
			$checks['sec_headers'] = array( 'label' => 'HTTP Security Headers Enforced (Layer 5)', 'status' => 'pass', 'pts' => 8 );
		} else {
			$checks['sec_headers'] = array( 'label' => 'Missing Security Headers (Clickjacking/XSS risk)', 'status' => 'fail', 'pts' => 0 );
		}

		// 7. WordPress Version Hidden (5 pts) - Layer 6
		$hide_version = self::get_option( 'hide_wp_version', 1 );
		if ( $hide_version ) {
			$points += 5;
			$checks['hide_version'] = array( 'label' => 'WP Version Meta Tags Removed (Layer 6)', 'status' => 'pass', 'pts' => 5 );
		} else {
			$checks['hide_version'] = array( 'label' => 'WP Version Exposed in Source', 'status' => 'fail', 'pts' => 0 );
		}

		// 8. Protect wp-config.php and Sensitive System Files (10 pts) - Layer 7
		$protect_config = self::get_option( 'protect_config_files', 1 );
		if ( $protect_config ) {
			$points += 10;
			$checks['protect_config'] = array( 'label' => 'wp-config.php & System Files Protected (Layer 7)', 'status' => 'pass', 'pts' => 10 );
		} else {
			$checks['protect_config'] = array( 'label' => 'Sensitive Configuration Files Exposed', 'status' => 'fail', 'pts' => 0 );
		}

		// 9. Stealth Dropper & Hidden File Rules (8 pts) - Layer 8
		$anti_dropper = self::get_option( 'block_hidden_files', 1 );
		if ( $anti_dropper ) {
			$points += 8;
			$checks['anti_dropper'] = array( 'label' => 'Stealth Dot & Hex Dropper Defense Active (Layer 8)', 'status' => 'pass', 'pts' => 8 );
		} else {
			$checks['anti_dropper'] = array( 'label' => 'Stealth Dropper Defense Inactive', 'status' => 'fail', 'pts' => 0 );
		}

		// 10. Brute-Force Login Lockout (10 pts)
		$login_lockout = self::get_option( 'bruteforce_protection', 1 );
		if ( $login_lockout ) {
			$points += 10;
			$checks['bruteforce'] = array( 'label' => 'Brute-Force Login Lockout Active', 'status' => 'pass', 'pts' => 10 );
		} else {
			$checks['bruteforce'] = array( 'label' => 'Brute-Force Protection Disabled', 'status' => 'fail', 'pts' => 0 );
		}

		// 11. Two-Factor Authentication (2FA) (5 pts)
		$twofa_enabled = self::get_option( '2fa_enabled', 0 );
		if ( $twofa_enabled ) {
			$points += 5;
			$checks['2fa'] = array( 'label' => 'Enterprise TOTP 2FA Enforced', 'status' => 'pass', 'pts' => 5 );
		} else {
			$checks['2fa'] = array( 'label' => 'Two-Factor Authentication Inactive', 'status' => 'optional', 'pts' => 0 );
		}

		// 12. GeoIP Country Blocking (5 pts)
		$geoip_enabled = self::get_option( 'geoip_enabled', 0 );
		if ( $geoip_enabled ) {
			$points += 5;
			$checks['geoip'] = array( 'label' => 'GeoIP Country Filtering Active', 'status' => 'pass', 'pts' => 5 );
		} else {
			$checks['geoip'] = array( 'label' => 'GeoIP Country Filtering Disabled', 'status' => 'optional', 'pts' => 0 );
		}

		$points = min( 100, max( 0, $points ) );

		$grade = 'F';
		if ( $points >= 90 ) {
			$grade = 'A+';
		} elseif ( $points >= 80 ) {
			$grade = 'A';
		} elseif ( $points >= 70 ) {
			$grade = 'B';
		} elseif ( $points >= 55 ) {
			$grade = 'C';
		}

		return array(
			'score'  => $points,
			'grade'  => $grade,
			'checks' => $checks,
		);
	}
}
