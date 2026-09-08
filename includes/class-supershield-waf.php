<?php
/**
 * Web Application Firewall (WAF) Engine for SuperShield Security.
 *
 * @package    SuperShield_Security
 * @subpackage SuperShield_Security/includes
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SuperShield_WAF {

	/**
	 * Run WAF inspection on current request.
	 */
	public static function inspect_request() {
		// Check if WAF is enabled
		if ( ! SuperShield_Utils::get_option( 'waf_enabled', 1 ) ) {
			return;
		}

		$client_ip = SuperShield_Utils::get_client_ip();

		// Whitelist check
		if ( SuperShield_IP_Manager::is_whitelisted( $client_ip ) ) {
			return;
		}

		// Blocklist check
		$block_data = SuperShield_IP_Manager::is_blocked( $client_ip );
		if ( false !== $block_data ) {
			self::block_request( 'IP Blocked: ' . $block_data['reason'], 'ip_blocked', $client_ip );
		}

		// Anti-DDoS Volumetric Rate Limiter
		if ( SuperShield_Utils::get_option( 'rate_limit_enabled', 0 ) ) {
			self::inspect_rate_limit( $client_ip );
		}

		// GeoIP Country Inspection
		if ( class_exists( 'SuperShield_GeoIP' ) ) {
			SuperShield_GeoIP::inspect_request( $client_ip );
		}

		// Register SSRF Interceptor on outgoing requests
		if ( function_exists( 'add_filter' ) ) {
			add_filter( 'pre_http_request', array( __CLASS__, 'intercept_ssrf' ), 10, 3 );
		}

		// Don't inspect requests from logged-in administrators if configured
		if ( SuperShield_Utils::get_option( 'waf_bypass_admin', 1 ) ) {
			if ( function_exists( 'is_user_logged_in' ) && is_user_logged_in() && function_exists( 'current_user_can' ) && current_user_can( 'manage_options' ) ) {
				return;
			}
			// If before pluggable.php, check if auth cookie is present and validate once available
			if ( ! empty( $_COOKIE ) ) {
				foreach ( array_keys( $_COOKIE ) as $cookie_name ) {
					if ( 0 === strpos( $cookie_name, 'wordpress_logged_in_' ) ) {
						if ( function_exists( 'wp_validate_auth_cookie' ) ) {
							$user_id = wp_validate_auth_cookie( $_COOKIE[ $cookie_name ], 'logged_in' );
							if ( $user_id && user_can( $user_id, 'manage_options' ) ) {
								return;
							}
						}
						break;
					}
				}
			}
		}

		// 1. Inspect Sensitive File Probing (e.g. .env, wp-config.php.bak, .git)
		self::check_sensitive_file_probes( $client_ip );

		// 2. Inspect User Agent for Scanners & Exploit Tools
		self::check_user_agent( $client_ip );

		// 3. Inspect Uploaded Files & Polyglot Images ($_FILES)
		self::inspect_uploaded_files( $client_ip );

		// 4. Inspect Query Parameters, Request Path & URI (GET)
		self::inspect_payloads( $_GET, 'GET_PARAM', $client_ip );
		if ( isset( $_SERVER['QUERY_STRING'] ) && ! empty( $_SERVER['QUERY_STRING'] ) ) {
			self::inspect_payloads( rawurldecode( $_SERVER['QUERY_STRING'] ), 'QUERY_STRING', $client_ip );
		}
		if ( isset( $_SERVER['REQUEST_URI'] ) && ! empty( $_SERVER['REQUEST_URI'] ) ) {
			$req_path = parse_url( $_SERVER['REQUEST_URI'], PHP_URL_PATH );
			if ( ! empty( $req_path ) ) {
				self::inspect_payloads( rawurldecode( $req_path ), 'REQUEST_PATH', $client_ip );
			}
		}

		// 5. Inspect POST Body
		if ( ! empty( $_POST ) ) {
			self::inspect_payloads( $_POST, 'POST_PARAM', $client_ip );
		}

		// 6. Inspect JSON and Raw Request Bodies (REST API / Webhooks)
		$content_type = isset( $_SERVER['CONTENT_TYPE'] ) ? strtolower( $_SERVER['CONTENT_TYPE'] ) : '';
		$req_method = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( $_SERVER['REQUEST_METHOD'] ) : 'GET';
		if ( strpos( $content_type, 'application/json' ) !== false || ( empty( $_POST ) && in_array( $req_method, array( 'POST', 'PUT', 'PATCH' ), true ) ) ) {
			$raw_input = @file_get_contents( 'php://input' );
			if ( ! empty( $raw_input ) ) {
				$json_data = json_decode( $raw_input, true );
				if ( is_array( $json_data ) ) {
					self::inspect_payloads( $json_data, 'JSON_BODY', $client_ip );
				} else {
					self::inspect_payloads( $raw_input, 'RAW_BODY', $client_ip );
				}
			}
		}

		// 7. Inspect Cookies
		if ( ! empty( $_COOKIE ) ) {
			self::inspect_payloads( $_COOKIE, 'COOKIE', $client_ip );
		}
	}

	/**
	 * Detect probes for sensitive environment or configuration files.
	 *
	 * @param string $ip
	 */
	private static function check_sensitive_file_probes( $ip ) {
		$raw_uri = isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '';
		$path = parse_url( $raw_uri, PHP_URL_PATH );
		$path = $path ? strtolower( rawurldecode( $path ) ) : '';
		$uri = strtolower( rawurldecode( $raw_uri ) );

		// Multi-decode normalization for nested probe evasion
		$multi_uri = $uri;
		for ( $i = 0; $i < 3; $i++ ) {
			$next_dec = rawurldecode( $multi_uri );
			if ( $next_dec === $multi_uri ) {
				break;
			}
			$multi_uri = $next_dec;
		}

		$prohibited_patterns = array(
			'/(?:^|\/)\.env(?:\.|$)/i',
			'/\.git(?:\/|$)/i',
			'/wp-config\.php\.(?:bak|old|save|txt|orig|temp|swp)/i',
			'/\.(?:aws|ssh)\/(?:credentials|config|id_rsa|id_dsa)/i',
			'/(?:^|\/)composer\.(?:json|lock)(?:\?|$)/i',
			'/(?:^|\/)debug\.log(?:\?|$)/i',
			'/eval-stdin\.php/i',
			'/\.(?:sql|sqlite|dump|tar|gz|zip|bz2|7z)(?:\.gz)?(?:\?|$)/i',
		);

		foreach ( $prohibited_patterns as $pattern ) {
			if ( preg_match( $pattern, $path ) || preg_match( $pattern, $uri ) || preg_match( $pattern, $multi_uri ) ) {
				self::record_violation_and_block(
					'Sensitive File Probe',
					'Attempted access to protected environment or backup file',
					$raw_uri,
					$ip
				);
			}
		}
	}

	/**
	 * Detect known malicious vulnerability scanner user agents.
	 *
	 * @param string $ip
	 */
	private static function check_user_agent( $ip ) {
		$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? strtolower( $_SERVER['HTTP_USER_AGENT'] ) : '';
		if ( empty( $ua ) ) {
			return;
		}

		$bad_bots = array(
			'sqlmap',
			'nikto',
			'acunetix',
			'havij',
			'masscan',
			'nmap',
			'netsparker',
			'dirbuster',
			'gobuster',
			'wpscan',
		);

		foreach ( $bad_bots as $bot ) {
			if ( strpos( $ua, $bot ) !== false ) {
				self::record_violation_and_block(
					'Malicious Tool / Scanner User-Agent',
					'Known vulnerability scanner tool signature detected: ' . $bot,
					$ua,
					$ip
				);
			}
		}
	}

	/**
	 * Inspect file uploads for polyglot malware, executable extensions, and embedded PHP headers.
	 *
	 * @param string $ip
	 */
	public static function inspect_uploaded_files( $ip = '' ) {
		$ip = ! empty( $ip ) ? $ip : SuperShield_Utils::get_client_ip();
		if ( empty( $_FILES ) || ! is_array( $_FILES ) ) {
			return;
		}

		$dangerous_exts = array( 'php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phps', 'phar', 'shtml', 'suspected', 'pl', 'cgi' );

		foreach ( $_FILES as $field => $file_info ) {
			if ( empty( $file_info['name'] ) ) {
				continue;
			}

			$names = is_array( $file_info['name'] ) ? $file_info['name'] : array( $file_info['name'] );
			$tmp_names = is_array( $file_info['tmp_name'] ) ? $file_info['tmp_name'] : array( $file_info['tmp_name'] );

			foreach ( $names as $idx => $orig_name ) {
				$name = strtolower( (string) $orig_name );
				$tmp_path = isset( $tmp_names[ $idx ] ) ? $tmp_names[ $idx ] : '';

				// Check null byte in filename
				if ( strpos( $name, "\0" ) !== false || strpos( $name, '%00' ) !== false ) {
					self::record_violation_and_block( 'Malicious File Upload', 'Null-byte poisoned filename in upload', $orig_name, $ip );
				}

				// Check double extension (e.g. shell.php.jpg)
				if ( preg_match( '/\.(php|phtml|phar)\.[a-z0-9]+$/i', $name ) ) {
					self::record_violation_and_block( 'Malicious File Upload', 'Double extension executable upload attempt: ' . $orig_name, $orig_name, $ip );
				}

				// Check dangerous extension
				$ext = pathinfo( $name, PATHINFO_EXTENSION );
				if ( in_array( $ext, $dangerous_exts, true ) ) {
					self::record_violation_and_block( 'Executable Script Upload', 'Executable script upload denied: ' . $orig_name, $orig_name, $ip );
				}

				// Hex / Header inspection for embedded PHP opening tags in image / media uploads (Polyglots)
				if ( ! empty( $tmp_path ) && file_exists( $tmp_path ) && is_readable( $tmp_path ) ) {
					$handle = @fopen( $tmp_path, 'rb' );
					if ( $handle ) {
						$chunk = @fread( $handle, 65536 ); // Read first 64KB
						@fclose( $handle );
						if ( false !== $chunk && ( strpos( $chunk, '<?php' ) !== false || strpos( $chunk, '<?=' ) !== false || preg_match( '/<script\s+language\s*=\s*["\']?php["\']?/i', $chunk ) || strpos( $chunk, '__HALT_COMPILER' ) !== false ) ) {
							self::record_violation_and_block( 'Polyglot Malware Upload', 'Embedded executable PHP tag discovered in uploaded media header: ' . $orig_name, $orig_name, $ip );
						}
					}
				}
			}
		}
	}

	/**
	 * Intercept outgoing HTTP requests to prevent Server-Side Request Forgery (SSRF).
	 *
	 * @param false|array|WP_Error $preempt
	 * @param array                $args
	 * @param string               $url
	 * @return false|array|WP_Error
	 */
	public static function intercept_ssrf( $preempt, $args, $url ) {
		if ( empty( $url ) || ! is_string( $url ) ) {
			return $preempt;
		}

		$parsed = parse_url( $url );
		$host = isset( $parsed['host'] ) ? strtolower( trim( $parsed['host'] ) ) : '';

		if ( empty( $host ) ) {
			return $preempt;
		}

		// Cloud metadata endpoint protection (AWS, GCP, DigitalOcean, Azure)
		if ( '169.254.169.254' === $host || 'metadata.google.internal' === $host || 'fd00:ec2::254' === $host ) {
			$client_ip = SuperShield_Utils::get_client_ip();
			SuperShield_DB::log_event( 'waf_block', 'SSRF: Blocked cloud metadata probe to ' . $url, 'Host: ' . $host, $client_ip );
			if ( class_exists( 'WP_Error' ) ) {
				return new WP_Error( 'supershield_ssrf_blocked', 'Outgoing HTTP request blocked: Destination matches protected cloud metadata service.' );
			}
			return false;
		}

		// RFC 1918 Private IP subnets check
		$resolved_ip = filter_var( $host, FILTER_VALIDATE_IP ) ? $host : @gethostbyname( $host );
		if ( filter_var( $resolved_ip, FILTER_VALIDATE_IP ) ) {
			if ( ! filter_var( $resolved_ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
				$client_ip = SuperShield_Utils::get_client_ip();
				SuperShield_DB::log_event( 'waf_block', 'SSRF: Blocked internal network request to ' . $resolved_ip, 'Target: ' . $url, $client_ip );
				if ( class_exists( 'WP_Error' ) ) {
					return new WP_Error( 'supershield_ssrf_blocked', 'Outgoing HTTP request blocked: Target resolves to internal/private RFC 1918 network.' );
				}
				return false;
			}
		}

		return $preempt;
	}

	/**
	 * Recursively inspect payloads against attack vectors.
	 *
	 * @param mixed  $data Data array or string.
	 * @param string $source Source label (GET, POST, COOKIE).
	 * @param string $ip Client IP.
	 */
	private static function inspect_payloads( $data, $source, $ip ) {
		if ( is_array( $data ) ) {
			foreach ( $data as $key => $val ) {
				self::inspect_payloads( $key, $source . '_KEY', $ip );
				self::inspect_payloads( $val, $source . '_VAL', $ip );
			}
			return;
		}

		if ( ! is_string( $data ) || strlen( $data ) < 3 ) {
			return;
		}

		$str = $data;

		// Multi-decode iterative normalization (resolves %252e%252e%252f -> ../ and nested obfuscations)
		$multi_decoded = $str;
		for ( $i = 0; $i < 3; $i++ ) {
			$next_decode = rawurldecode( $multi_decoded );
			if ( $next_decode === $multi_decoded ) {
				break;
			}
			$multi_decoded = $next_decode;
		}

		// Null-byte and control character normalization
		$stripped_nulls = str_replace( array( "\0", "%00" ), '', $str );
		$stripped_nulls_decoded = str_replace( array( "\0", "%00" ), '', $multi_decoded );

		// SQL comment normalization (flattens /*...*/ into whitespace)
		$normalized_str = preg_replace( '/\/\*.*?\*\//', ' ', $str );
		$normalized_decoded = preg_replace( '/\/\*.*?\*\//', ' ', $multi_decoded );

		$inspect_targets = array_unique( array(
			$str,
			$multi_decoded,
			$stripped_nulls,
			$stripped_nulls_decoded,
			$normalized_str,
			$normalized_decoded,
		) );

		// 1. SQL Injection (SQLi) Signatures
		$sqli_patterns = array(
			'/(\bunion\b[\s\/\*]+(all[\s\/\*]+)?\bselect\b)/i',
			'/(\bselect\b[\s\/\*]+[a-zA-Z0-9_,\.\*\(\)\s\'"\-]{1,80}[\s\/\*]+\bfrom\b[\s\/\*]+(information_schema|wp_users|sys\.)\b)/i',
			'/(\b(benchmark|sleep)[\s\/\*]*\([\s\/\*]*\d+[\s\/\*]*\))/i',
			'/(\b(load_file|into[\s\/\*]+(out|dump)file)\b)/i',
			'/((?:\'|\"|(?:\b\d+\b))[\s\/\*]+(or|and)[\s\/\*]+(?:\'|\"|(?:\b\d+\b))[\s\/\*]*=[\s\/\*]*(?:\'|\"|(?:\b\d+\b)))/i',
			'/(\bor\b[\s\/\*]+1\s*=\s*1\b)/i',
			'/(\bwaitfor[\s\/\*]+\bdelay\b[\s\/\*]+[\'"]\d+)/i',
			'/(\b(drop|truncate|alter)\s+(table|database)\s+[a-zA-Z0-9_]+)/i',
			'/\/\*!\d{5}\s*(select|union|insert|update|delete|drop)/i',
		);

		foreach ( $inspect_targets as $target ) {
			foreach ( $sqli_patterns as $pattern ) {
				if ( preg_match( $pattern, $target ) ) {
					self::record_violation_and_block( 'SQL Injection (SQLi)', "Matched pattern in $source", $str, $ip );
				}
			}
		}

		// 2. Cross-Site Scripting (XSS) Signatures
		$xss_patterns = array(
			'/<script\b[^>]*>(.*?)<\/script>/is',
			'/(javascript|vbscript|data):[^\n]*?(script|alert|prompt|confirm)/i',
			'/(<\s*img\b[^>]*\bonerror\s*=\s*[\'"]?[^\s>]+)/i',
			'/(<\s*body\b[^>]*\bonload\s*=\s*[\'"]?[^\s>]+)/i',
			'/(<\s*svg\b[^>]*\bonload\s*=\s*[\'"]?[^\s>]+)/i',
			'/(<\s*iframe\b[^>]*\bsrc\s*=\s*[\'"]?javascript:)/i',
			'/(\b(document\.cookie|window\.location|eval\s*\()\b)/i',
		);

		foreach ( $inspect_targets as $target ) {
			foreach ( $xss_patterns as $pattern ) {
				if ( preg_match( $pattern, $target ) ) {
					self::record_violation_and_block( 'Cross-Site Scripting (XSS)', "Matched signature in $source", $str, $ip );
				}
			}
		}

		// 3. Path Traversal & LFI / RFI
		$lfi_patterns = array(
			'/(\.\.[\/\\\\])/',
			'/((?:%2e%2e|\.\.)(?:\/|\\|%2f|%5c))/i',
			'/(\/etc\/(passwd|shadow|hosts|issue))/i',
			'/(win\.ini|boot\.ini|system32\/config)/i',
			'/(php:\/\/(filter|input|data))/i',
			'/(?:phar|zip|expect|data):\/\//i',
		);

		foreach ( $inspect_targets as $target ) {
			foreach ( $lfi_patterns as $pattern ) {
				if ( preg_match( $pattern, $target ) ) {
					self::record_violation_and_block( 'Directory Traversal / LFI', "Matched signature in $source", $str, $ip );
				}
			}
		}

		// 4. Remote Code Execution (RCE)
		$rce_patterns = array(
			'/(\b(passthru|shell_exec|exec|popen|proc_open)\s*\(.*?\))/i',
			'/(\bbase64_decode\s*\(\s*[\'"][a-zA-Z0-9+\/=]{16,}[\'"]\s*\))/i',
			'/(\b(gzinflate|gzuncompress|str_rot13)\s*\(\s*base64_decode\s*\()/i',
			'/(\bassert\s*\(\s*\$_(POST|GET|REQUEST|COOKIE))/i',
		);

		foreach ( $inspect_targets as $target ) {
			foreach ( $rce_patterns as $pattern ) {
				if ( preg_match( $pattern, $target ) ) {
					self::record_violation_and_block( 'Remote Code Execution (RCE)', "Matched signature in $source", $str, $ip );
				}
			}
		}

		// 5. PHP Object Injection & Deserialization
		$obj_patterns = array(
			'/(\b[OC]:\+?[0-9]+:\s*\"[^\"]+\")/i',
			'/(\ba:[0-9]+:\{.*?[OC]:\+?[0-9]+:)/is',
		);

		foreach ( $inspect_targets as $target ) {
			foreach ( $obj_patterns as $pattern ) {
				if ( preg_match( $pattern, $target ) ) {
					self::record_violation_and_block( 'PHP Object Injection (Deserialization)', "Matched signature in $source", $str, $ip );
				}
			}
		}

		// 6. HTTP Response Splitting / CRLF Header Injection
		foreach ( $inspect_targets as $target ) {
			if ( preg_match( '/(?:%0d|%0a|\r|\n)(?:content-type|set-cookie|location)\s*:/i', $target ) ) {
				self::record_violation_and_block( 'HTTP Response Splitting', "CRLF Header Injection detected in $source", $str, $ip );
			}
		}
	}

	/**
	 * Log violation and trigger block.
	 *
	 * @param string $threat_type
	 * @param string $details
	 * @param string $payload
	 * @param string $ip
	 */
	private static function record_violation_and_block( $threat_type, $details, $payload, $ip ) {
		$waf_mode = SuperShield_Utils::get_option( 'waf_mode', 'block' ); // 'block', 'simulate', 'learning'

		// 1. Learning Mode: If enabled and request originates from authenticated or trusted session
		if ( 'learning' === $waf_mode ) {
			if ( ( function_exists( 'is_user_logged_in' ) && is_user_logged_in() ) || ! empty( $_COOKIE ) ) {
				self::learn_benign_rule( $threat_type, $details, $payload );
				SuperShield_DB::log_event( 'waf_learned', "Learning Mode Auto-Whitelisted: $threat_type ($details)", $payload, $ip );
				return;
			}
		}

		// 2. Check if rule pattern was previously learned/whitelisted
		if ( self::is_rule_learned( $threat_type, $payload ) ) {
			return;
		}

		// 3. Simulation / Monitor Mode: Log violation and emit header but DO NOT terminate request
		if ( 'simulate' === $waf_mode ) {
			SuperShield_DB::log_event( 'waf_block', "[SIMULATED] $threat_type: $details", $payload, $ip );
			if ( ! headers_sent() ) {
				header( 'X-SuperShield-Action: Simulated-Block' );
			}
			return;
		}

		// 4. Active Enforcement Mode: Log event, record telemetry, and block
		SuperShield_DB::log_event( 'waf_block', "$threat_type: $details", $payload, $ip );

		// Opt-in Community Threat Telemetry
		if ( class_exists( 'SuperShield_Telemetry' ) ) {
			SuperShield_Telemetry::dispatch_threat_telemetry( $threat_type, $details, isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '' );
		}

		// Auto-block IP if enabled
		$auto_block = SuperShield_Utils::get_option( 'auto_block_waf_violators', 1 );
		if ( $auto_block ) {
			$lockout_time = (int) SuperShield_Utils::get_option( 'waf_lockout_duration', 86400 );
			SuperShield_DB::block_ip( $ip, "WAF Violation: $threat_type", 'waf', $lockout_time );
		}

		self::block_request( $threat_type, 'waf_block', $ip );
	}

	/**
	 * Save a benign rule into learned rules catalog during WAF Learning Mode.
	 *
	 * @param string $threat_type
	 * @param string $details
	 * @param string $payload
	 */
	public static function learn_benign_rule( $threat_type, $details, $payload ) {
		$learned = SuperShield_Utils::get_option( 'supershield_waf_learned_rules', array() );
		if ( ! is_array( $learned ) ) {
			$learned = array();
		}

		$uri = isset( $_SERVER['REQUEST_URI'] ) ? parse_url( $_SERVER['REQUEST_URI'], PHP_URL_PATH ) : '';
		$key = md5( $threat_type . '|' . $uri );

		$learned[ $key ] = array(
			'threat_type' => sanitize_text_field( $threat_type ),
			'path'        => sanitize_text_field( $uri ),
			'learned_at'  => current_time( 'mysql' ),
		);

		// Keep up to 200 learned rules
		if ( count( $learned ) > 200 ) {
			$learned = array_slice( $learned, -200, 200, true );
		}

		SuperShield_Utils::update_option( 'supershield_waf_learned_rules', $learned );
	}

	/**
	 * Check if a threat pattern has been auto-whitelisted in learning mode.
	 *
	 * @param string $threat_type
	 * @param string $payload
	 * @return bool
	 */
	public static function is_rule_learned( $threat_type, $payload ) {
		$learned = SuperShield_Utils::get_option( 'supershield_waf_learned_rules', array() );
		if ( empty( $learned ) || ! is_array( $learned ) ) {
			return false;
		}

		$uri = isset( $_SERVER['REQUEST_URI'] ) ? parse_url( $_SERVER['REQUEST_URI'], PHP_URL_PATH ) : '';
		$key = md5( $threat_type . '|' . $uri );

		return isset( $learned[ $key ] );
	}

	/**
	 * Render high-grade 403 Forbidden Shield Block Screen.
	 *
	 * @param string $reason
	 * @param string $code
	 * @param string $ip
	 */
	public static function block_request( $reason, $code = 'forbidden', $ip = '' ) {
		if ( defined( 'SUPERSHIELD_TESTING' ) && SUPERSHIELD_TESTING ) {
			throw new RuntimeException( "WAF_BLOCK: $reason ($code)" );
		}

		$ip = ! empty( $ip ) ? $ip : SuperShield_Utils::get_client_ip();
		$ref_id = '#SSS-SEC-' . strtoupper( substr( md5( $ip . microtime() ), 0, 8 ) );

		if ( ! headers_sent() ) {
			if ( function_exists( 'status_header' ) ) {
				status_header( 403 );
			} elseif ( function_exists( 'http_response_code' ) ) {
				http_response_code( 403 );
			}
			if ( function_exists( 'nocache_headers' ) ) {
				nocache_headers();
			}
			header( 'Content-Type: text/html; charset=utf-8' );
			header( 'X-Frame-Options: SAMEORIGIN' );
			header( 'X-Content-Type-Options: nosniff' );
		}

		?>
		<!DOCTYPE html>
		<html lang="en">
		<head>
			<meta charset="UTF-8">
			<meta name="viewport" content="width=device-width, initial-scale=1.0">
			<title>403 Forbidden — SuperShield Security</title>
			<style>
				* { margin: 0; padding: 0; box-sizing: border-box; }
				body {
					background-color: #0b0f19;
					color: #e2e8f0;
					font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
					display: flex;
					align-items: center;
					justify-content: center;
					min-height: 100vh;
					padding: 20px;
				}
				.shield-card {
					background: #111827;
					border: 1px solid #1f2937;
					border-radius: 14px;
					padding: 44px;
					max-width: 600px;
					width: 100%;
					box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.7);
					text-align: center;
					position: relative;
				}
				.shield-icon {
					width: 72px;
					height: 72px;
					background: rgba(239, 68, 68, 0.12);
					border: 2px solid #ef4444;
					border-radius: 50%;
					display: inline-flex;
					align-items: center;
					justify-content: center;
					margin-bottom: 24px;
					color: #ef4444;
					box-shadow: 0 0 20px rgba(239, 68, 68, 0.25);
				}
				.shield-icon svg { width: 40px; height: 40px; fill: none; stroke: currentColor; stroke-width: 2; }
				h1 { font-size: 24px; font-weight: 700; color: #f8fafc; margin-bottom: 12px; letter-spacing: -0.5px; }
				p.desc { font-size: 15px; color: #94a3b8; line-height: 1.6; margin-bottom: 26px; }
				.info-box {
					background: #0b0f19;
					border: 1px solid #1f2937;
					border-radius: 10px;
					padding: 18px 20px;
					font-size: 13px;
					text-align: left;
					color: #cbd5e1;
					margin-bottom: 26px;
					line-height: 1.9;
				}
				.info-box strong { color: #f1f5f9; }
				.info-box code { color: #38bdf8; font-family: "JetBrains Mono", "Fira Code", monospace; font-size: 12px; }
				.footer { font-size: 12px; color: #64748b; line-height: 1.6; }
				.footer a { color: #6366f1; text-decoration: none; font-weight: 600; }
				.footer a:hover { text-decoration: underline; }
			</style>
		</head>
		<body>
			<div class="shield-card">
				<div class="shield-icon">
					<svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
				</div>
				<h1>Access Denied by SuperShield Security</h1>
				<p class="desc">The Web Application Firewall has identified this request as potentially malicious or policy-violating and neutralized it to protect server integrity.</p>
				<div class="info-box">
					<div><strong>Incident ID:</strong> <code><?php echo esc_html( $ref_id ); ?></code></div>
					<div><strong>Reason:</strong> <?php echo esc_html( $reason ); ?></div>
					<div><strong>Client IP:</strong> <code><?php echo esc_html( $ip ); ?></code></div>
					<div><strong>Timestamp:</strong> <?php echo esc_html( gmdate( 'Y-m-d H:i:s' ) . ' UTC' ); ?></div>
				</div>
				<div class="footer">
					Protected by <strong>SuperShield Security Suite v<?php echo esc_html( defined( 'SUPERSHIELD_VERSION' ) ? SUPERSHIELD_VERSION : '2.5.0' ); ?></strong><br>
					Engineering Lead: <a href="https://grwebdevs.com" target="_blank" rel="noopener">Ghulam Rasool</a> &bull; <a href="https://SSS.grwebdevs.com" target="_blank" rel="noopener">SSS.grwebdevs.com</a>
				</div>
			</div>
		</body>
		</html>
		<?php
		exit;
	}

	/**
	 * Inspect request frequency and apply anti-DDoS / volumetric rate limiting.
	 *
	 * @param string $ip Client IP.
	 */
	public static function inspect_rate_limit( $ip ) {
		if ( empty( $ip ) || SuperShield_Utils::is_loopback_or_private( $ip ) || SuperShield_Utils::is_cloudflare_ip( $ip ) ) {
			return;
		}

		if ( SuperShield_IP_Manager::is_whitelisted( $ip ) ) {
			return;
		}

		$window = 60; // 60 seconds rolling window
		$max_requests = (int) SuperShield_Utils::get_option( 'rate_limit_max_requests', 120 );
		if ( $max_requests <= 0 ) {
			$max_requests = 120;
		}

		$transient_key = 'ss_rl_' . md5( $ip );
		$bucket = function_exists( 'get_transient' ) ? get_transient( $transient_key ) : false;
		$now = time();

		if ( false === $bucket || ! is_array( $bucket ) || ! isset( $bucket['start'] ) || ! isset( $bucket['count'] ) ) {
			$bucket = array(
				'start' => $now,
				'count' => 1,
			);
			if ( function_exists( 'set_transient' ) ) {
				set_transient( $transient_key, $bucket, $window );
			}
			return;
		}

		$bucket['count']++;
		$elapsed = $now - $bucket['start'];
		$remaining_time = max( 1, $window - $elapsed );

		if ( $bucket['count'] > $max_requests ) {
			// Throttle violation
			if ( class_exists( 'SuperShield_DB' ) ) {
				SuperShield_DB::log_event(
					'RATE_LIMIT',
					"Volumetric rate limit exceeded: {$bucket['count']} requests in {$elapsed}s (threshold: {$max_requests}/min)",
					isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '',
					$ip
				);
			}

			if ( class_exists( 'SuperShield_Telemetry' ) ) {
				SuperShield_Telemetry::dispatch_threat_telemetry(
					'Anti-DDoS Volumetric Throttling',
					"IP {$ip} exceeded threshold of {$max_requests} req/min",
					isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : ''
				);
			}

			self::drop_rate_limit( $ip, $remaining_time );
		} else {
			if ( function_exists( 'set_transient' ) ) {
				set_transient( $transient_key, $bucket, $remaining_time );
			}
		}
	}

	/**
	 * Send 429 Too Many Requests response with Retry-After header.
	 *
	 * @param string $ip Client IP.
	 * @param int    $retry_after Cooldown in seconds.
	 */
	public static function drop_rate_limit( $ip, $retry_after = 60 ) {
		if ( defined( 'SUPERSHIELD_TESTING' ) && SUPERSHIELD_TESTING ) {
			throw new RuntimeException( "RATE_LIMIT_BLOCK: Rate limit exceeded ($retry_after)" );
		}

		$ref_id = '#SSS-RL-' . strtoupper( substr( md5( $ip . microtime() ), 0, 8 ) );

		if ( ! headers_sent() ) {
			if ( function_exists( 'status_header' ) ) {
				status_header( 429 );
			} elseif ( function_exists( 'http_response_code' ) ) {
				http_response_code( 429 );
			}
			header( 'Retry-After: ' . (int) $retry_after );
			if ( function_exists( 'nocache_headers' ) ) {
				nocache_headers();
			}
			header( 'Content-Type: text/html; charset=utf-8' );
			header( 'X-Frame-Options: SAMEORIGIN' );
			header( 'X-Content-Type-Options: nosniff' );
		}
		?>
		<!DOCTYPE html>
		<html lang="en">
		<head>
			<meta charset="UTF-8">
			<meta name="viewport" content="width=device-width, initial-scale=1.0">
			<title>429 Too Many Requests — SuperShield Security</title>
			<style>
				* { margin: 0; padding: 0; box-sizing: border-box; }
				body {
					background-color: #0b0f19;
					color: #e2e8f0;
					font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
					display: flex;
					align-items: center;
					justify-content: center;
					min-height: 100vh;
					padding: 20px;
				}
				.shield-card {
					background: #111827;
					border: 1px solid #1f2937;
					border-radius: 14px;
					padding: 44px;
					max-width: 600px;
					width: 100%;
					box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.7);
					text-align: center;
					position: relative;
				}
				.shield-icon {
					width: 72px;
					height: 72px;
					background: rgba(245, 158, 11, 0.12);
					border: 2px solid #f59e0b;
					border-radius: 50%;
					display: inline-flex;
					align-items: center;
					justify-content: center;
					margin-bottom: 24px;
					color: #f59e0b;
					box-shadow: 0 0 20px rgba(245, 158, 11, 0.25);
				}
				.shield-icon svg { width: 40px; height: 40px; fill: none; stroke: currentColor; stroke-width: 2; }
				h1 { font-size: 24px; font-weight: 700; color: #f8fafc; margin-bottom: 12px; letter-spacing: -0.5px; }
				p.desc { font-size: 15px; color: #94a3b8; line-height: 1.6; margin-bottom: 26px; }
				.info-box {
					background: #0b0f19;
					border: 1px solid #1f2937;
					border-radius: 10px;
					padding: 18px 20px;
					font-size: 13px;
					text-align: left;
					color: #cbd5e1;
					margin-bottom: 26px;
					line-height: 1.9;
				}
				.info-box strong { color: #f1f5f9; }
				.info-box code { color: #f59e0b; font-family: "JetBrains Mono", "Fira Code", monospace; font-size: 12px; }
				.footer { font-size: 12px; color: #64748b; line-height: 1.6; }
				.footer a { color: #6366f1; text-decoration: none; font-weight: 600; }
				.footer a:hover { text-decoration: underline; }
			</style>
		</head>
		<body>
			<div class="shield-card">
				<div class="shield-icon">
					<svg viewBox="0 0 24 24"><path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
				</div>
				<h1>Too Many Requests (Rate Limit Exceeded)</h1>
				<p class="desc">Volumetric flood protection has temporarily throttled your connection due to unusually high request frequency. Please wait a moment before refreshing.</p>
				<div class="info-box">
					<div><strong>Incident ID:</strong> <code><?php echo esc_html( $ref_id ); ?></code></div>
					<div><strong>Client IP:</strong> <code><?php echo esc_html( $ip ); ?></code></div>
					<div><strong>Cool-down Window:</strong> <code><?php echo (int) $retry_after; ?> seconds</code></div>
					<div><strong>Timestamp:</strong> <?php echo esc_html( gmdate( 'Y-m-d H:i:s' ) . ' UTC' ); ?></div>
				</div>
				<div class="footer">
					Protected by <strong>SuperShield Security Suite v<?php echo esc_html( defined( 'SUPERSHIELD_VERSION' ) ? SUPERSHIELD_VERSION : '2.5.0' ); ?></strong><br>
					Engineering Lead: <a href="https://grwebdevs.com" target="_blank" rel="noopener">Ghulam Rasool</a> &bull; <a href="https://SSS.grwebdevs.com" target="_blank" rel="noopener">SSS.grwebdevs.com</a>
				</div>
			</div>
		</body>
		</html>
		<?php
		exit;
	}

	/**
	 * Track 404 scans and ban automated vulnerability probers.
	 */
	public static function track_404_probes() {
		if ( ! function_exists( 'is_404' ) || ! is_404() || ( function_exists( 'is_admin' ) && is_admin() ) ) {
			return;
		}

		if ( ! SuperShield_Utils::get_option( 'prober_404_trap_enabled', 1 ) ) {
			return;
		}

		$client_ip = SuperShield_Utils::get_client_ip();
		if ( empty( $client_ip ) || SuperShield_IP_Manager::is_whitelisted( $client_ip ) || SuperShield_Utils::is_loopback_or_private( $client_ip ) ) {
			return;
		}

		$transient_key = 'sss_404_' . md5( $client_ip );
		$hits = (int) get_transient( $transient_key );
		$hits++;

		$max_404s = (int) SuperShield_Utils::get_option( 'max_404_probes', 20 );
		if ( $hits >= $max_404s ) {
			delete_transient( $transient_key );
			$lockout = 86400; // 24 hours
			SuperShield_DB::block_ip(
				$client_ip,
				"404 Prober Trap: Exceeded {$max_404s} 404 errors in 60s (vulnerability scan)",
				'bot',
				$lockout
			);
			SuperShield_DB::log_event(
				'waf_block',
				"404 Scanner Trapped: {$hits} non-existent endpoint probes",
				isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '',
				$client_ip
			);
			self::block_request( '404 Vulnerability Prober Trap', 'prober_blocked', $client_ip );
		} else {
			set_transient( $transient_key, $hits, 60 );
		}
	}
}
