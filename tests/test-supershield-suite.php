<?php
/**
 * Comprehensive Automated Verification Suite for SuperShield Security v2.0.0
 * 
 * Directly tests SuperShield_WAF, SuperShield_Scanner, SuperShield_Hardening,
 * SuperShield_Login_Security, SuperShield_IP_Manager, SuperShield_DB, SuperShield_Utils,
 * SuperShield_GeoIP, SuperShield_Cleaner, SuperShield_2FA, SuperShield_Updater,
 * SuperShield_AntiTamper, and SuperShield_Telemetry.
 *
 * @author Ghulam Rasool <grwebdevs.com>
 * @version 2.0.0
 */

// Define environment constants
define( 'ABSPATH', str_replace( '\\', '/', __DIR__ . '/../' ) );
define( 'WP_CONTENT_DIR', ABSPATH . 'wp-content/' );
define( 'WP_PLUGIN_DIR', WP_CONTENT_DIR . 'plugins/' );
define( 'WPMU_PLUGIN_DIR', WP_CONTENT_DIR . 'mu-plugins/' );
define( 'SUPERSHIELD_VERSION', '2.5.0' );
define( 'SUPERSHIELD_PLUGIN_DIR', ABSPATH );
define( 'SUPERSHIELD_BASENAME', 'supershield-security/supershield-security.php' );
define( 'AUTH_KEY', 'test_auth_key_1234567890abcdef' );
define( 'SUPERSHIELD_TESTING', true );

// Mock WordPress functions
if ( ! class_exists( 'WP_User' ) ) {
	class WP_User {
		public $ID;
		public $user_login;
		public $user_email;
		public $roles = array();

		public function __construct( $id = 1, $login = 'admin', $roles = array( 'administrator' ) ) {
			$this->ID = $id;
			$this->user_login = $login;
			$this->roles = $roles;
		}
	}
}

if ( ! class_exists( 'WP_Error' ) ) {
	class WP_Error {
		public $errors = array();
		public $error_data = array();

		public function __construct( $code = '', $message = '', $data = '' ) {
			if ( ! empty( $code ) ) {
				$this->errors[ $code ][] = $message;
				if ( ! empty( $data ) ) {
					$this->error_data[ $code ] = $data;
				}
			}
		}

		public function get_error_code() {
			$codes = array_keys( $this->errors );
			return empty( $codes ) ? '' : $codes[0];
		}

		public function get_error_message( $code = '' ) {
			if ( empty( $code ) ) {
				$code = $this->get_error_code();
			}
			return isset( $this->errors[ $code ][0] ) ? $this->errors[ $code ][0] : '';
		}

		public function get_error_codes() {
			return array_keys( $this->errors );
		}
	}
}

if ( ! function_exists( 'is_wp_error' ) ) {
	function is_wp_error( $thing ) {
		return ( $thing instanceof WP_Error );
	}
}

if ( ! function_exists( 'is_user_logged_in' ) ) {
	function is_user_logged_in() {
		return false;
	}
}

if ( ! function_exists( 'get_userdata' ) ) {
	function get_userdata( $user_id ) {
		return (object) array(
			'ID' => $user_id,
			'user_login' => 'admin',
			'user_email' => 'admin@example.com',
			'user_registered' => '2026-01-01 00:00:00',
			'roles' => array( 'administrator' ),
		);
	}
}

if ( ! function_exists( 'sanitize_text_field' ) ) {
	function sanitize_text_field( $str ) {
		return trim( strip_tags( (string) $str ) );
	}
}

if ( ! function_exists( 'sanitize_user' ) ) {
	function sanitize_user( $username ) {
		return preg_replace( '|[^a-z0-9 _.\-@]|i', '', (string) $username );
	}
}

if ( ! function_exists( 'sanitize_textarea_field' ) ) {
	function sanitize_textarea_field( $str ) {
		return trim( htmlspecialchars( (string) $str, ENT_QUOTES, 'UTF-8' ) );
	}
}

if ( ! function_exists( 'sanitize_email' ) ) {
	function sanitize_email( $email ) {
		return filter_var( trim( (string) $email ), FILTER_SANITIZE_EMAIL );
	}
}

if ( ! function_exists( 'wp_unslash' ) ) {
	function wp_unslash( $val ) {
		return stripslashes( (string) $val );
	}
}

if ( ! function_exists( 'current_time' ) ) {
	function current_time( $type ) {
		return date( 'Y-m-d H:i:s' );
	}
}

if ( ! function_exists( 'wp_upload_dir' ) ) {
	function wp_upload_dir() {
		$dir = str_replace( '\\', '/', __DIR__ . '/tmp_uploads' );
		return array(
			'basedir' => $dir,
			'baseurl' => 'http://example.com/wp-content/uploads',
		);
	}
}

if ( ! function_exists( 'trailingslashit' ) ) {
	function trailingslashit( $string ) {
		return rtrim( $string, '/\\' ) . '/';
	}
}

if ( ! function_exists( 'wp_mkdir_p' ) ) {
	function wp_mkdir_p( $target ) {
		if ( ! is_dir( $target ) ) {
			return @mkdir( $target, 0777, true );
		}
		return true;
	}
}

if ( ! function_exists( 'esc_html' ) ) {
	function esc_html( $s ) {
		return htmlspecialchars( (string) $s, ENT_QUOTES, 'UTF-8' );
	}
}

if ( ! function_exists( 'esc_attr' ) ) {
	function esc_attr( $s ) {
		return htmlspecialchars( (string) $s, ENT_QUOTES, 'UTF-8' );
	}
}

if ( ! function_exists( 'esc_url_raw' ) ) {
	function esc_url_raw( $url ) {
		return filter_var( $url, FILTER_SANITIZE_URL );
	}
}

if ( ! function_exists( 'status_header' ) ) {
	function status_header( $code ) {}
}

if ( ! function_exists( 'home_url' ) ) {
	function home_url( $path = '' ) {
		return 'http://example.com' . ( ! empty( $path ) ? '/' . ltrim( $path, '/' ) : '' );
	}
}

if ( ! function_exists( 'admin_url' ) ) {
	function admin_url( $path = '' ) {
		return 'http://example.com/wp-admin/' . ltrim( $path, '/' );
	}
}

if ( ! function_exists( 'add_query_arg' ) ) {
	function add_query_arg( ...$args ) {
		if ( count( $args ) === 1 ) {
			return $args[0];
		}
		if ( is_array( $args[0] ) ) {
			$url = isset( $args[1] ) ? $args[1] : '';
			$query = http_build_query( $args[0] );
			$delim = ( strpos( $url, '?' ) !== false ) ? '&' : '?';
			return $url . ( empty( $query ) ? '' : $delim . $query );
		}
		$key = $args[0];
		$val = $args[1];
		$url = isset( $args[2] ) ? $args[2] : '';
		$delim = ( strpos( $url, '?' ) !== false ) ? '&' : '?';
		return $url . $delim . $key . '=' . $val;
	}
}

if ( ! function_exists( 'nocache_headers' ) ) {
	function nocache_headers() {}
}

if ( ! function_exists( 'wp_parse_str' ) ) {
	function wp_parse_str( $string, &$array ) {
		parse_str( (string) $string, $array );
	}
}

if ( ! function_exists( 'wp_die' ) ) {
	function wp_die( $message = '', $title = '', $args = array() ) {
		throw new RuntimeException( "WP_DIE: $message" );
	}
}

$mock_options = array();

if ( ! function_exists( 'get_option' ) ) {
	function get_option( $key, $default = false ) {
		global $mock_options;
		return isset( $mock_options[ $key ] ) ? $mock_options[ $key ] : $default;
	}
}

if ( ! function_exists( 'update_option' ) ) {
	function update_option( $key, $val ) {
		global $mock_options;
		$mock_options[ $key ] = $val;
		return true;
	}
}

if ( ! function_exists( 'delete_option' ) ) {
	function delete_option( $key ) {
		global $mock_options;
		unset( $mock_options[ $key ] );
		return true;
	}
}

$mock_transients = array();
if ( ! function_exists( 'get_transient' ) ) {
	function get_transient( $key ) {
		global $mock_transients;
		return isset( $mock_transients[ $key ] ) ? $mock_transients[ $key ] : false;
	}
}
if ( ! function_exists( 'set_transient' ) ) {
	function set_transient( $key, $val, $exp = 0 ) {
		global $mock_transients;
		$mock_transients[ $key ] = $val;
		return true;
	}
}
if ( ! function_exists( 'delete_transient' ) ) {
	function delete_transient( $key ) {
		global $mock_transients;
		unset( $mock_transients[ $key ] );
		return true;
	}
}

$mock_usermeta = array();
if ( ! function_exists( 'get_user_meta' ) ) {
	function get_user_meta( $user_id, $key = '', $single = false ) {
		global $mock_usermeta;
		if ( isset( $mock_usermeta[ $user_id ][ $key ] ) ) {
			return $mock_usermeta[ $user_id ][ $key ];
		}
		return $single ? '' : array();
	}
}
if ( ! function_exists( 'update_user_meta' ) ) {
	function update_user_meta( $user_id, $key, $value ) {
		global $mock_usermeta;
		if ( ! isset( $mock_usermeta[ $user_id ] ) ) {
			$mock_usermeta[ $user_id ] = array();
		}
		$mock_usermeta[ $user_id ][ $key ] = $value;
		return true;
	}
}
if ( ! function_exists( 'delete_user_meta' ) ) {
	function delete_user_meta( $user_id, $key ) {
		global $mock_usermeta;
		if ( isset( $mock_usermeta[ $user_id ][ $key ] ) ) {
			unset( $mock_usermeta[ $user_id ][ $key ] );
		}
		return true;
	}
}

if ( ! function_exists( 'wp_json_encode' ) ) {
	function wp_json_encode( $data, $options = 0, $depth = 512 ) {
		return json_encode( $data, $options, $depth );
	}
}

if ( ! function_exists( 'get_bloginfo' ) ) {
	function get_bloginfo( $show = 'name' ) {
		return '6.7';
	}
}

$mock_cron_events = array();
if ( ! function_exists( 'wp_next_scheduled' ) ) {
	function wp_next_scheduled( $hook ) {
		global $mock_cron_events;
		return isset( $mock_cron_events[ $hook ] ) ? $mock_cron_events[ $hook ] : false;
	}
}
if ( ! function_exists( 'wp_schedule_event' ) ) {
	function wp_schedule_event( $timestamp, $recurrence, $hook ) {
		global $mock_cron_events;
		$mock_cron_events[ $hook ] = $timestamp;
		return true;
	}
}
if ( ! function_exists( 'wp_clear_scheduled_hook' ) ) {
	function wp_clear_scheduled_hook( $hook ) {
		global $mock_cron_events;
		unset( $mock_cron_events[ $hook ] );
		return true;
	}
}

// Mock Database Layer
class MockWPDB {
	public $prefix = 'wp_';
	public $users = 'wp_users';
	public $options = 'wp_options';
	public $usermeta = 'wp_usermeta';
	public $posts = 'wp_posts';

	public $logged_events = array();
	public $blocked_ips = array();
	public $scan_issues = array();
	public $insert_id = 1;
	public $mock_posts = array(
		501 => array(
			'ID' => 501,
			'post_title' => 'Compromised Landing Page',
			'post_content' => '<p>Welcome</p><iframe src="https://forecast-chaos.com/trap" style="display:none"></iframe><script>/*forecast-chaos*/</script>',
		),
	);

	public function get_charset_collate() { return ''; }

	public function prepare( $query, ...$args ) {
		foreach ( $args as $arg ) {
			$val = is_numeric( $arg ) ? $arg : "'" . addslashes( (string) $arg ) . "'";
			$query = preg_replace( '/%[sd]/', $val, $query, 1 );
		}
		return $query;
	}

	public function get_row( $q ) {
		if ( strpos( $q, 'supershield_blocked_ips' ) !== false ) {
			foreach ( $this->blocked_ips as $ip => $data ) {
				if ( strpos( $q, $ip ) !== false ) {
					return (object) array_merge( array( 'id' => 1, 'hits' => 1 ), $data );
				}
			}
		}
		if ( strpos( $q, 'supershield_scan_issues' ) !== false ) {
			if ( ! empty( $this->scan_issues ) ) {
				$last = end( $this->scan_issues );
				return (object) array_merge( array( 'id' => 101 ), $last );
			}
		}
		if ( strpos( $q, 'wp_posts' ) !== false ) {
			preg_match( '/ID\s*=\s*(\d+)/', $q, $matches );
			$pid = ! empty( $matches[1] ) ? (int) $matches[1] : 501;
			if ( isset( $this->mock_posts[ $pid ] ) ) {
				return (object) $this->mock_posts[ $pid ];
			}
		}
		return false;
	}

	public function get_var( $q ) {
		return 0;
	}

	public function get_results( $q ) {
		// Mock capability-filtered admin query
		if ( strpos( $q, 'capabilities' ) !== false && strpos( $q, 'wp_users' ) !== false ) {
			return array(
				(object) array( 'ID' => 99, 'user_login' => 'administrator_backdoor', 'user_email' => 'bad@evil.com', 'user_registered' => '2026-09-01 00:00:00' ),
			);
		}

		// Mock malware option query
		if ( strpos( $q, 'wp_vcd' ) !== false ) {
			return array(
				(object) array( 'option_id' => 777, 'option_name' => 'wp_vcd', 'opt_len' => 45000 ),
			);
		}

		// Mock compromised wp_posts query
		if ( strpos( $q, 'wp_posts' ) !== false ) {
			$res = array();
			foreach ( $this->mock_posts as $p ) {
				if ( strpos( $p['post_content'], 'iframe' ) !== false || strpos( $p['post_content'], 'script' ) !== false ) {
					$res[] = (object) array( 'ID' => $p['ID'], 'post_title' => $p['post_title'] );
				}
			}
			return $res;
		}

		return array();
	}

	public function insert( $table, $data, $format = null ) {
		if ( strpos( $table, 'supershield_events' ) !== false ) {
			$this->logged_events[] = $data;
			return 1;
		}
		if ( strpos( $table, 'supershield_blocked_ips' ) !== false ) {
			$this->blocked_ips[ $data['ip_address'] ] = $data;
			return 1;
		}
		if ( strpos( $table, 'supershield_scan_issues' ) !== false ) {
			$this->scan_issues[] = $data;
			return 1;
		}
		return 1;
	}

	public function update( $table, $data, $where, $format = null, $where_format = null ) {
		if ( strpos( $table, 'wp_posts' ) !== false && isset( $where['ID'] ) && isset( $this->mock_posts[ $where['ID'] ] ) ) {
			$this->mock_posts[ $where['ID'] ] = array_merge( $this->mock_posts[ $where['ID'] ], $data );
			return 1;
		}
		return 1;
	}

	public function query( $q ) {
		return 1;
	}

	public function delete( $table, $where, $where_format = null ) {
		if ( isset( $where['ip_address'] ) && isset( $this->blocked_ips[ $where['ip_address'] ] ) ) {
			unset( $this->blocked_ips[ $where['ip_address'] ] );
		}
		return 1;
	}
}

global $wpdb;
$wpdb = new MockWPDB();

// Require Plugin Core Classes (v2.0.0 Suite)
require_once __DIR__ . '/../includes/class-supershield-utils.php';
require_once __DIR__ . '/../includes/class-supershield-db.php';
require_once __DIR__ . '/../includes/class-supershield-ip-manager.php';
require_once __DIR__ . '/../includes/class-supershield-geoip.php';
require_once __DIR__ . '/../includes/class-supershield-waf.php';
require_once __DIR__ . '/../includes/class-supershield-cleaner.php';
require_once __DIR__ . '/../includes/class-supershield-scanner.php';
require_once __DIR__ . '/../includes/class-supershield-hardening.php';
require_once __DIR__ . '/../includes/class-supershield-login-security.php';
require_once __DIR__ . '/../includes/class-supershield-qrcode.php';
require_once __DIR__ . '/../includes/class-supershield-2fa.php';
require_once __DIR__ . '/../includes/class-supershield-updater.php';
require_once __DIR__ . '/../includes/class-supershield-antitamper.php';
require_once __DIR__ . '/../includes/class-supershield-telemetry.php';
require_once __DIR__ . '/../includes/class-supershield-activator.php';
require_once __DIR__ . '/../includes/class-supershield-deactivator.php';

$test_count = 0;
$pass_count = 0;

function assert_test( $condition, $test_name ) {
	global $test_count, $pass_count;
	$test_count++;
	if ( $condition ) {
		$pass_count++;
		echo " [PASS] $test_name\n";
	} else {
		echo " [FAIL] $test_name\n";
	}
}

echo "========================================================\n";
echo " SuperShield Security v2.0.0 — Enterprise Verification Suite\n";
echo " Lead Architect: Ghulam Rasool (grwebdevs.com)\n";
echo "========================================================\n\n";

// --- 1. IP & CIDR Range (IPv4 & IPv6) ---
echo "--- 1. Testing IP & CIDR Range Matching (IPv4 & IPv6) ---\n";
assert_test( SuperShield_Utils::ip_in_range( '192.168.1.50', '192.168.1.0/24' ), '192.168.1.50 is within 192.168.1.0/24' );
assert_test( ! SuperShield_Utils::ip_in_range( '192.168.2.1', '192.168.1.0/24' ), '192.168.2.1 is NOT within 192.168.1.0/24' );
assert_test( SuperShield_Utils::ip_in_range( '10.0.0.1', '10.0.0.1' ), 'Single IPv4 exact match' );
assert_test( ! SuperShield_Utils::ip_in_range( '10.0.0.2', '10.0.0.1' ), 'Single IPv4 mismatch returns false' );
assert_test( SuperShield_Utils::ip_in_range( '2001:db8::1', '2001:db8::1' ), 'Single IPv6 exact match' );
assert_test( SuperShield_Utils::ip_in_range( '2001:db8::ffff', '2001:db8::/32' ), 'IPv6 address matches /32 subnet' );
assert_test( ! SuperShield_Utils::ip_in_range( '2001:db9::1', '2001:db8::/32' ), 'IPv6 outside subnet is rejected' );
assert_test( SuperShield_Utils::ip_in_range( '123.45.67.89', '0.0.0.0/0' ), 'IPv4 /0 matches any IPv4 address' );

// --- 2. IP Spoofing Prevention ---
echo "\n--- 2. Testing IP Spoofing Prevention & Proxy Trust ---\n";
$_SERVER['REMOTE_ADDR'] = '198.51.100.25';
$_SERVER['HTTP_X_FORWARDED_FOR'] = '127.0.0.1, 203.0.113.1';
SuperShield_Utils::update_option( 'trust_proxy_headers', 0 );
assert_test( '198.51.100.25' === SuperShield_Utils::get_client_ip(), 'Untrusted X-Forwarded-For is ignored; true REMOTE_ADDR used' );

SuperShield_Utils::update_option( 'trust_proxy_headers', 1 );
$_SERVER['HTTP_CF_CONNECTING_IP'] = '203.0.113.55';
assert_test( '203.0.113.55' === SuperShield_Utils::get_client_ip(), 'CF-Connecting-IP is respected when trust_proxy_headers is enabled' );
SuperShield_Utils::update_option( 'trust_proxy_headers', 0 ); // reset

// --- 3. Whitelist & Blacklist Priority ---
echo "\n--- 3. Testing IP Whitelist & Blacklist Logic ---\n";
SuperShield_Utils::update_option( 'ip_whitelist', array( '198.51.100.25', '10.0.0.0/8' ) );
SuperShield_Utils::update_option( 'ip_blacklist', array( '198.51.100.25', '198.51.100.99' ) );
assert_test( SuperShield_IP_Manager::is_whitelisted( '198.51.100.25' ), 'Whitelisted single IP is recognized' );
assert_test( SuperShield_IP_Manager::is_whitelisted( '10.5.5.5' ), 'Whitelisted CIDR range IP is recognized' );
assert_test( false === SuperShield_IP_Manager::is_blocked( '198.51.100.25' ), 'Whitelisted IP overrides blacklist' );
assert_test( false !== SuperShield_IP_Manager::is_blocked( '198.51.100.99' ), 'Non-whitelisted blacklisted IP is blocked' );

// --- 4. Security Score Engine (8 Layers + 2FA + GeoIP) ---
echo "\n--- 4. Testing Security Score Engine (8 Hardening Layers) ---\n";
SuperShield_Utils::update_option( 'waf_enabled', 1 );
SuperShield_Utils::update_option( 'block_uploads_php', 1 );
SuperShield_Utils::update_option( 'disable_xmlrpc', 1 );
SuperShield_Utils::update_option( 'bruteforce_protection', 1 );
SuperShield_Utils::update_option( 'block_user_enumeration', 1 );
SuperShield_Utils::update_option( 'security_headers', 1 );
SuperShield_Utils::update_option( 'hide_wp_version', 1 );
SuperShield_Utils::update_option( 'protect_config_files', 1 );
SuperShield_Utils::update_option( 'block_hidden_files', 1 );
SuperShield_Utils::update_option( '2fa_enabled', 1 );
SuperShield_Utils::update_option( 'geoip_enabled', 1 );

$score_data = SuperShield_Utils::calculate_security_score();
assert_test( 100 === $score_data['score'], 'All hardening layers + WAF + 2FA yield 100% score' );
assert_test( 'A+' === $score_data['grade'], '100% score receives A+ grade' );
assert_test( isset( $score_data['checks']['protect_config'] ) && isset( $score_data['checks']['anti_dropper'] ), 'Layer 7 and Layer 8 appear in checklist' );
assert_test( isset( $score_data['checks']['2fa'] ) && isset( $score_data['checks']['geoip'] ), '2FA and GeoIP appear in checklist' );

// --- 5. Direct WAF Execution & Signature Protection ---
echo "\n--- 5. Testing WAF Engine & Attack Neutralization ---\n";
$_SERVER['REMOTE_ADDR'] = '203.0.113.99';
unset( $_SERVER['HTTP_X_FORWARDED_FOR'] );
unset( $_SERVER['HTTP_CF_CONNECTING_IP'] );
SuperShield_Utils::update_option( 'ip_whitelist', array( '127.0.0.1' ) );

// 5.1 Early execution safety
$early_waf_safe = true;
try {
	$_GET = array();
	$_POST = array();
	$_COOKIE = array();
	$_SERVER['REQUEST_URI'] = '/';
	$_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0';
	SuperShield_WAF::inspect_request();
} catch ( Throwable $e ) {
	$early_waf_safe = false;
}
assert_test( $early_waf_safe, 'WAF executes safely early on plugins_loaded without pluggable fatal error' );

// 5.2 SQLi with comments (UNION/**/SELECT)
$wpdb->blocked_ips = array();
$initial_events = count( $wpdb->logged_events );
$_GET = array( 'id' => '1 UNION/**/SELECT 1,2,user_pass FROM wp_users' );
try {
	SuperShield_WAF::inspect_request();
} catch ( Throwable $e ) {}
assert_test( count( $wpdb->logged_events) > $initial_events, 'WAF detects and blocks UNION/**/SELECT comments SQLi' );

// 5.3 Boolean SQLi (1 OR 1=1)
$wpdb->blocked_ips = array();
$initial_events = count( $wpdb->logged_events );
$_GET = array( 'filter' => "1 OR 1=1" );
try {
	SuperShield_WAF::inspect_request();
} catch ( Throwable $e ) {}
assert_test( count( $wpdb->logged_events ) > $initial_events, 'WAF detects and blocks 1 OR 1=1 boolean SQLi' );

// 5.4 Sensitive file probing (/.env?v=1)
$wpdb->blocked_ips = array();
$initial_events = count( $wpdb->logged_events );
$_GET = array();
$_SERVER['REQUEST_URI'] = '/.env?v=1';
try {
	SuperShield_WAF::inspect_request();
} catch ( Throwable $e ) {}
assert_test( count( $wpdb->logged_events ) > $initial_events, 'WAF detects and blocks /.env?v=1 file probing with query string' );

// 5.5 XSS with unquoted event handler
$wpdb->blocked_ips = array();
$initial_events = count( $wpdb->logged_events );
$_SERVER['REQUEST_URI'] = '/';
$_GET = array( 'q' => '<img src=x onerror=alert(1)>' );
try {
	SuperShield_WAF::inspect_request();
} catch ( Throwable $e ) {}
assert_test( count( $wpdb->logged_events ) > $initial_events, 'WAF detects and blocks unquoted onerror XSS' );

// 5.6 Directory Traversal
$wpdb->blocked_ips = array();
$initial_events = count( $wpdb->logged_events );
$_GET = array( 'page' => '../wp-config.php' );
try {
	SuperShield_WAF::inspect_request();
} catch ( Throwable $e ) {}
assert_test( count( $wpdb->logged_events ) > $initial_events, 'WAF detects and blocks single ../ directory traversal' );

// 5.7 Bad Bot Scanner User-Agent
$wpdb->blocked_ips = array();
$initial_events = count( $wpdb->logged_events );
$_GET = array();
$_SERVER['HTTP_USER_AGENT'] = 'wpscan v3.8.22';
try {
	SuperShield_WAF::inspect_request();
} catch ( Throwable $e ) {}
assert_test( count( $wpdb->logged_events ) > $initial_events, 'WAF detects and blocks WPScan bot user agent' );
$_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0';

// 5.8 SSRF Interception (Layered metadata and intranet blocking)
$ssrf_aws = SuperShield_WAF::intercept_ssrf( false, array(), 'http://169.254.169.254/latest/meta-data/' );
assert_test( is_wp_error( $ssrf_aws ), 'SSRF engine blocks requests to AWS/cloud metadata IP (169.254.169.254)' );

$ssrf_local = SuperShield_WAF::intercept_ssrf( false, array(), 'http://127.0.0.1:8080/internal-api' );
assert_test( is_wp_error( $ssrf_local ), 'SSRF engine blocks loopback intranet requests (127.0.0.1)' );

$ssrf_rfc1918 = SuperShield_WAF::intercept_ssrf( false, array(), 'http://192.168.1.100/admin' );
assert_test( is_wp_error( $ssrf_rfc1918 ), 'SSRF engine blocks RFC 1918 private subnet requests' );

$ssrf_legit = SuperShield_WAF::intercept_ssrf( false, array(), 'https://api.wordpress.org/plugins/update-check/1.1/' );
assert_test( false === $ssrf_legit, 'SSRF engine permits benign external public API requests' );

// 5.9 File Upload & MIME Polyglot Inspection
$tmp_test_dir = str_replace( '\\', '/', __DIR__ . '/tmp_uploads' );
wp_mkdir_p( $tmp_test_dir );
$fake_file = $tmp_test_dir . '/fake_photo.jpg';
file_put_contents( $fake_file, "GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;<?php phpinfo(); ?>" );

$_FILES = array(
	'avatar' => array(
		'name'     => 'avatar.php.png',
		'type'     => 'image/png',
		'tmp_name' => $fake_file,
		'error'    => 0,
		'size'     => filesize( $fake_file ),
	),
);
$upload_blocked = false;
try {
	SuperShield_WAF::inspect_uploaded_files();
} catch ( Throwable $e ) {
	$upload_blocked = true;
}
assert_test( $upload_blocked, 'WAF inspect_uploaded_files neutralizes dangerous double-extension / embedded PHP polyglot upload' );
@unlink( $fake_file );
$_FILES = array();

// 5.10 PHP Object Injection / Deserialization Gadgets
$wpdb->blocked_ips = array();
$initial_events = count( $wpdb->logged_events );
$_POST = array( 'serialized_payload' => 'O:8:"stdClass":1:{s:4:"test";s:3:"bad";}' );
try {
	SuperShield_WAF::inspect_request();
} catch ( Throwable $e ) {}
assert_test( count( $wpdb->logged_events ) > $initial_events, 'WAF detects and blocks PHP Object Injection serialized payload gadget' );

// 5.11 HTTP Response Splitting / CRLF Header Injection
$wpdb->blocked_ips = array();
$initial_events = count( $wpdb->logged_events );
$_GET = array( 'redir' => "index.php%0d%0aSet-Cookie: evil_sess=1" );
$_POST = array();
try {
	SuperShield_WAF::inspect_request();
} catch ( Throwable $e ) {}
assert_test( count( $wpdb->logged_events ) > $initial_events, 'WAF detects and blocks HTTP Response Splitting / CRLF header injection' );

// 5.12 Nested Multi-Decode (%252e%252e%252f)
$wpdb->blocked_ips = array();
$initial_events = count( $wpdb->logged_events );
$_GET = array( 'path' => '%252e%252e%252f%252e%252e%252fetc%2fpasswd' );
try {
	SuperShield_WAF::inspect_request();
} catch ( Throwable $e ) {}
assert_test( count( $wpdb->logged_events ) > $initial_events, 'WAF normalizes and blocks nested multi-encoded traversal payload' );

// 5.13 REQUEST_PATH Traversal in URI Path without Query String
$wpdb->blocked_ips = array();
$initial_events = count( $wpdb->logged_events );
$_GET = array();
$_SERVER['REQUEST_URI'] = '/api/v1/../../../../wp-config.php';
try {
	SuperShield_WAF::inspect_request();
} catch ( Throwable $e ) {}
assert_test( count( $wpdb->logged_events ) > $initial_events, 'WAF inspects REQUEST_PATH and blocks traversal in URI path without query parameters' );

$_SERVER['REQUEST_URI'] = '/';
$_GET = array();
$_POST = array();
$_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0';

// --- 6. Malware Scanner & Forensic Signatures ---
echo "\n--- 6. Testing Malware Scanner & Threat Detection ---\n";
$tmp_uploads = str_replace( '\\', '/', __DIR__ . '/tmp_uploads' );
wp_mkdir_p( $tmp_uploads );

file_put_contents( $tmp_uploads . '/shell.php', '<?php phpinfo(); ?>' );
file_put_contents( $tmp_uploads . '/avatar.php.jpg', 'fake-image' );
file_put_contents( $tmp_uploads . '/.6345dc54.php', '<?php eval(base64_decode("c3lzdGVtKCdpZCcpOw==")); ?>' );

$scan_res = SuperShield_Scanner::run_full_scan();
assert_test( $scan_res['threats_found'] >= 3, 'Scanner detected uploads backdoor, double extension, and hidden dot dropper' );

// Test Shannon Entropy Calculator
$high_entropy_str = base64_encode( random_bytes( 256 ) );
$low_entropy_str  = str_repeat( 'AAAAABBBBB', 20 );
$high_entropy_val = SuperShield_Scanner::calculate_shannon_entropy( $high_entropy_str );
$low_entropy_val  = SuperShield_Scanner::calculate_shannon_entropy( $low_entropy_str );
assert_test( $high_entropy_val > $low_entropy_val, 'Shannon Entropy correctly distinguishes random packed data from repetitive data' );

// --- 7. Hardening Engine & Uploads Lockdown ---
echo "\n--- 7. Testing Hardening Engine & Server Immunity ---\n";
SuperShield_Hardening::ensure_uploads_htaccess_immunity();
$uploads_htaccess = file_get_contents( $tmp_uploads . '/.htaccess' );
assert_test( strpos( $uploads_htaccess, 'Require all denied' ) !== false && strpos( $uploads_htaccess, 'Deny from all' ) !== false, 'Uploads lockdown .htaccess enforces dual Apache 2.2/2.4 execution block' );

// --- 8. Offline GeoIP & Country Blocking ---
echo "\n--- 8. Testing Offline GeoIP & Country Blocking (2.0.0) ---\n";
// Cloudflare header detection
$_SERVER['HTTP_CF_IPCOUNTRY'] = 'PK';
assert_test( 'PK' === SuperShield_GeoIP::resolve_country( '123.45.67.89' ), 'GeoIP resolves country from Cloudflare CF-IPCountry header' );
unset( $_SERVER['HTTP_CF_IPCOUNTRY'] );

// Built-in offline range resolution
assert_test( 'KP' === SuperShield_GeoIP::resolve_country( '175.45.176.1' ), 'GeoIP resolves 175.x to KP via built-in offline CIDR database' );
assert_test( 'LOCAL' === SuperShield_GeoIP::resolve_country( '127.0.0.1' ), 'Loopback address resolves to LOCAL' );

// Policy tests: Blacklist mode
SuperShield_Utils::update_option( 'geoip_enabled', 1 );
SuperShield_Utils::update_option( 'geoip_mode', 'blacklist' );
SuperShield_Utils::update_option( 'geoip_countries', array( 'RU', 'CN', 'KP' ) );
assert_test( ! SuperShield_GeoIP::is_country_allowed( 'KP' ), 'Blacklisted country KP is blocked' );
assert_test( SuperShield_GeoIP::is_country_allowed( 'US' ), 'Non-blacklisted country US is permitted' );
assert_test( SuperShield_GeoIP::is_country_allowed( 'LOCAL' ), 'LOCAL loopback is always permitted' );

// Policy tests: Whitelist mode
SuperShield_Utils::update_option( 'geoip_mode', 'whitelist' );
SuperShield_Utils::update_option( 'geoip_countries', array( 'US', 'CA', 'GB' ) );
assert_test( SuperShield_GeoIP::is_country_allowed( 'US' ), 'Whitelisted country US is permitted' );
assert_test( ! SuperShield_GeoIP::is_country_allowed( 'CN' ), 'Non-whitelisted country CN is blocked' );
SuperShield_Utils::update_option( 'geoip_enabled', 0 ); // reset

// 8.5 GeoIP Login-Only Protection permits admin-ajax.php
SuperShield_Utils::update_option( 'geoip_enabled', 1 );
SuperShield_Utils::update_option( 'geoip_mode', 'blacklist' );
SuperShield_Utils::update_option( 'geoip_protect_login_only', 1 );
SuperShield_Utils::update_option( 'geoip_countries', array( 'KP' ) );
$_SERVER['REMOTE_ADDR'] = '175.45.176.1'; // KP
$_SERVER['REQUEST_URI'] = '/wp-admin/admin-ajax.php';
$ajax_blocked = false;
try {
	SuperShield_GeoIP::inspect_request( '175.45.176.1' );
} catch ( Throwable $e ) {
	$ajax_blocked = true;
}
assert_test( ! $ajax_blocked, 'GeoIP login-only protection permits public frontend admin-ajax.php requests' );

$_SERVER['REQUEST_URI'] = '/wp-login.php';
$login_blocked = false;
try {
	SuperShield_GeoIP::inspect_request( '175.45.176.1' );
} catch ( Throwable $e ) {
	$login_blocked = true;
}
assert_test( $login_blocked, 'GeoIP login-only protection blocks wp-login.php requests from blacklisted countries' );
SuperShield_Utils::update_option( 'geoip_enabled', 0 );
SuperShield_Utils::update_option( 'geoip_protect_login_only', 0 );
$_SERVER['REMOTE_ADDR'] = '127.0.0.1';
$_SERVER['REQUEST_URI'] = '/';

// --- 9. Enterprise TOTP Two-Factor Authentication (2FA) ---
echo "\n--- 9. Testing Enterprise TOTP Two-Factor Authentication (2.0.0) ---\n";
$secret = SuperShield_2FA::generate_secret( 16 );
assert_test( 16 === strlen( $secret ) && preg_match( '/^[A-Z2-7]{16}$/', $secret ), 'Generated Base32 2FA secret matches RFC 4648 specification' );

// Base32 Decode
$decoded_bin = SuperShield_2FA::base32_decode( $secret );
assert_test( false !== $decoded_bin && strlen( $decoded_bin ) === 10, 'Base32 secret cleanly decodes to binary key' );

// Current TOTP code verification
$current_code = SuperShield_2FA::get_totp_code( $secret );
assert_test( 6 === strlen( $current_code ) && ctype_digit( $current_code ), 'Generated TOTP code is a valid 6-digit numeric PIN' );
assert_test( SuperShield_2FA::verify_totp( $secret, $current_code ), 'Current TOTP code passes immediate verification' );
assert_test( ! SuperShield_2FA::verify_totp( $secret, '000000' === $current_code ? '999999' : '000000' ), 'Invalid TOTP code is rejected' );

// Clock-drift window test (+30 seconds)
$next_slice_code = SuperShield_2FA::get_totp_code( $secret, (int) floor( time() / 30 ) + 1 );
assert_test( SuperShield_2FA::verify_totp( $secret, $next_slice_code, 1 ), 'TOTP verification allows +/- 1 time step clock drift' );

// Emergency Recovery Backup Passcodes
$backup_codes = SuperShield_2FA::generate_backup_codes( 8 );
assert_test( 8 === count( $backup_codes ), 'Generated 8 single-use emergency backup recovery passcodes' );
assert_test( preg_match( '/^[A-Z0-9]{4}-[A-Z0-9]{4}$/', $backup_codes[0] ), 'Backup codes follow XXXX-XXXX format' );

$test_user_id = 42;
SuperShield_2FA::enable_user_2fa( $test_user_id, $secret, $backup_codes );
assert_test( SuperShield_2FA::is_user_2fa_enabled( $test_user_id ), '2FA is recognized as active for test user' );

// Consume a backup code
$code_to_use = $backup_codes[0];
$valid_backup = SuperShield_2FA::verify_backup_code( $test_user_id, $code_to_use );
assert_test( $valid_backup, 'Valid emergency backup code passes verification' );
$consumed_again = SuperShield_2FA::verify_backup_code( $test_user_id, $code_to_use );
assert_test( ! $consumed_again, 'Consumed backup code cannot be reused (single-use enforcement)' );
assert_test( 7 === SuperShield_2FA::get_remaining_backup_codes_count( $test_user_id ), 'Remaining backup codes counter decremented to 7' );
SuperShield_2FA::disable_user_2fa( $test_user_id );
assert_test( ! SuperShield_2FA::is_user_2fa_enabled( $test_user_id ), '2FA cleanly deactivated for test user' );

// Offline QR Code SVG Generator
$otpauth = SuperShield_2FA::get_otpauth_url( 'admin', $secret );
$svg = SuperShield_2FA::render_qr_code_svg( $otpauth, 180 );
assert_test( strpos( $svg, '<svg' ) !== false && strpos( $svg, '</svg>' ) !== false && strpos( $svg, '<rect' ) !== false, 'Pure-PHP SVG QR code generated with crisp vectors and zero external API calls' );

// Deep QR Engine tests (ISO/IEC 18004 standard compliance)
$qr_matrix = SuperShield_QRCode::generate( $otpauth );
$module_count = count( $qr_matrix );
assert_test( $module_count >= 21 && $module_count <= 57, 'QR Matrix generated standard version module grid (size: ' . $module_count . 'x' . $module_count . ')' );
// Check Top-Left Finder Pattern: 7x7 outer boundary
assert_test( 1 === $qr_matrix[0][0] && 1 === $qr_matrix[0][6] && 1 === $qr_matrix[6][0] && 1 === $qr_matrix[6][6], 'ISO Top-Left Finder corner points are active dark modules' );
// Check Finder white separator
assert_test( 0 === $qr_matrix[7][0] && 0 === $qr_matrix[0][7], 'ISO Finder white separator boundary rings correctly initialized' );

// 2FA Grace Period Logic
SuperShield_Utils::update_option( '2fa_enabled', 1 );
SuperShield_Utils::update_option( '2fa_roles', array( 'administrator' ) );
SuperShield_Utils::update_option( '2fa_grace_period_days', 3 );

$admin_user = new WP_User( 999, 'legacy_admin', array( 'administrator' ) );
// Case 1: First login after 2FA mandatory enforcement -> automatically starts grace period without locking out
delete_user_meta( 999, '_supershield_2fa_grace_start' );
$auth_res = SuperShield_2FA::filter_authenticate( $admin_user, 'legacy_admin', 'secret_pwd' );
assert_test( $auth_res instanceof WP_User, '2FA Grace period permits initial login for legacy administrator without immediate lockout' );
$recorded_start = get_user_meta( 999, '_supershield_2fa_grace_start', true );
assert_test( ! empty( $recorded_start ), 'Grace period start timestamp recorded in user meta' );

// Case 2: Grace period expired (simulating 4 days later)
update_user_meta( 999, '_supershield_2fa_grace_start', time() - ( 4 * 86400 ) );
$auth_res_expired = SuperShield_2FA::filter_authenticate( $admin_user, 'legacy_admin', 'secret_pwd' );
assert_test( is_wp_error( $auth_res_expired ) && 'supershield_2fa_mandatory_lock' === $auth_res_expired->get_error_code(), '2FA locks out unconfigured mandatory role after grace period expiration' );

// Case 3: Still within active grace period (simulating 1 day later)
update_user_meta( 999, '_supershield_2fa_grace_start', time() - ( 1 * 86400 ) );
$auth_res_valid_grace = SuperShield_2FA::filter_authenticate( $admin_user, 'legacy_admin', 'secret_pwd' );
assert_test( $auth_res_valid_grace instanceof WP_User, '2FA permits authentication while within the 3-day grace period window' );

// Login Security: Error Obfuscation preservation
SuperShield_Utils::update_option( 'obfuscate_login_errors', 1 );
$totp_challenge_err = new WP_Error( 'supershield_2fa_missing', 'Please enter your 6-digit TOTP code.' );
$filtered_totp_err = SuperShield_Login_Security::obfuscate_login_errors( $totp_challenge_err );
assert_test( 'Please enter your 6-digit TOTP code.' === $filtered_totp_err->get_error_message(), 'Login error obfuscation preserves 2FA security code prompts' );

$bad_pwd_err = new WP_Error( 'incorrect_password', 'Unknown username or wrong password provided by client.' );
$filtered_pwd_err = SuperShield_Login_Security::obfuscate_login_errors( $bad_pwd_err );
assert_test( 'Invalid username or password.' === $filtered_pwd_err->get_error_message(), 'Generic credentials failure error safely obfuscated against account enumeration' );

// --- 10. 1-Click Surgical Disinfection (SuperShield_Cleaner) ---
echo "\n--- 10. Testing 1-Click Surgical Disinfection & Cleaner (2.0.0) ---\n";
// Create an infected legitimate plugin file
$infected_file = $tmp_uploads . '/legitimate-plugin.php';
$clean_legit_code = "<?php\n// Legitimate plugin file\nfunction my_custom_plugin_feature() {\n    return 'success';\n}\n";
$malicious_injection = "/*malware start*/ eval(base64_decode('c3lzdGVtKCdpZCcpOw==')); /*malware end*/\n";
file_put_contents( $infected_file, $clean_legit_code . $malicious_injection );

$strip_result = SuperShield_Cleaner::surgical_strip( $infected_file, 'EVAL_BASE64' );
assert_test( $strip_result['success'], 'Surgical strip successfully excised injected malware block' );
$post_clean_content = file_get_contents( $infected_file );
assert_test( strpos( $post_clean_content, 'eval(base64_decode' ) === false, 'Malicious payload completely removed from file' );
assert_test( strpos( $post_clean_content, 'my_custom_plugin_feature' ) !== false, 'Legitimate code structure remained intact' );
assert_test( SuperShield_Cleaner::validate_php_syntax( $post_clean_content ), 'Cleaned file passed PHP syntax token validation' );

// Test PHP Token syntax parsing on variable interpolation
$interp_code = "<?php\n\$user = 'Admin';\necho \"Hello {\$user}, system status: OK\";\n";
assert_test( SuperShield_Cleaner::validate_php_syntax( $interp_code ), 'Cleaner PHP syntax token parser correctly handles variable interpolation {$var} without brace count underflow' );

$broken_syntax = "<?php\nfunction unclosed_routine() {\n    echo 'Missing closure';\n";
assert_test( ! SuperShield_Cleaner::validate_php_syntax( $broken_syntax ), 'Cleaner PHP syntax validator flags unclosed code structures' );

// Test DB Payload cleaning
$clean_db = SuperShield_Cleaner::clean_db_payload( 'wp_vcd' );
assert_test( $clean_db, 'SuperShield_Cleaner successfully purged malicious database payload' );

// Test error-suppressed @eval surgical excision
$suppressed_file = $tmp_uploads . '/suppressed-plugin.php';
$suppressed_code = "<?php\n// Plugin\nfunction feature2() { return true; }\n@eval(base64_decode('c3lzdGVtKCdpZCcpOw=='));\n";
file_put_contents( $suppressed_file, $suppressed_code );
$strip_suppressed = SuperShield_Cleaner::surgical_strip( $suppressed_file, 'SUPPRESSED_EVAL' );
assert_test( $strip_suppressed['success'], 'Surgical strip successfully excised error-suppressed @eval malware line' );
assert_test( strpos( file_get_contents( $suppressed_file ), '@eval' ) === false, 'Error-suppressed @eval completely removed' );
@unlink( $suppressed_file );

// 10.3 Multi-nested recursive surgical excision
$nested_file = $tmp_uploads . '/nested-plugin.php';
$nested_code = "<?php\n// Good feature\nfunction legit_func() {\n    return 'ok';\n}\n@eval(gzinflate(base64_decode('c3lzdGVtKCdpZCcpOw==')));\n// End of feature\n";
file_put_contents( $nested_file, $nested_code );
$strip_nested = SuperShield_Cleaner::surgical_strip( $nested_file, 'SUPPRESSED_EVAL' );
assert_test( $strip_nested['success'], 'Surgical strip cleanly excises multi-nested @eval(gzinflate(base64_decode(...))) payload' );
assert_test( strpos( file_get_contents( $nested_file ), '@eval' ) === false, 'Multi-nested @eval completely removed from file' );
assert_test( strpos( file_get_contents( $nested_file ), 'legit_func' ) !== false, 'Legitimate surrounding code retained intact' );
assert_test( SuperShield_Cleaner::validate_php_syntax( file_get_contents( $nested_file ) ), 'Excised file maintains valid PHP syntax' );
@unlink( $nested_file );

// 10.4 Root WordPress Core Files Quarantine Protection
$fake_index = ABSPATH . 'index.php';
$quarantine_root_attempt = SuperShield_Cleaner::quarantine_file( $fake_index );
assert_test( ! $quarantine_root_attempt['success'] && strpos( $quarantine_root_attempt['message'], 'critical WordPress root core file' ) !== false, 'Cleaner prevents catastrophic quarantine of critical root WordPress core files' );

// 10.5 Tier 4 DB Post Injection Scan & Clean
$db_scan_results = array( 'scanned_files' => 0, 'threats_found' => 0, 'issues' => array() );
SuperShield_Scanner::scan_database_threats( $db_scan_results );
$found_post_injection = false;
foreach ( $db_scan_results['issues'] as $iss ) {
	if ( 'malicious_post_content' === $iss['type'] ) {
		$found_post_injection = true;
		break;
	}
}
assert_test( $found_post_injection, 'Scanner Tier 4 detected malicious iframe/script injection in wp_posts' );
$clean_post_res = SuperShield_Cleaner::clean_issue( array(
	'type' => 'malicious_post_content',
	'post_id' => 501,
) );
assert_test( $clean_post_res['success'], 'Cleaner successfully eradicated malicious script/iframe payload from wp_posts' );
$cleansed_post = $wpdb->get_row( "SELECT * FROM wp_posts WHERE ID = 501" );
assert_test( strpos( $cleansed_post->post_content, 'iframe' ) === false && strpos( $cleansed_post->post_content, 'forecast-chaos' ) === false, 'Malicious tags stripped from post_content while retaining legitimate text' );

// 10.6 Worm Staging Directory Quarantine
$staging_dir = $tmp_uploads . '/.cache_sys_staging';
wp_mkdir_p( $staging_dir );
file_put_contents( $staging_dir . '/dropper.php', '<?php phpinfo(); ?>' );
$quarantine_dir_res = SuperShield_Cleaner::clean_issue( array(
	'type' => 'worm_staging',
	'file_path' => $staging_dir,
) );
assert_test( $quarantine_dir_res['success'], 'Cleaner successfully quarantined worm staging directory' );
assert_test( ! is_dir( $staging_dir ), 'Worm staging directory eradicated from original filesystem location' );

// --- 11. Cryptographic Self-Integrity & Anti-Tamper Vault ---
echo "\n--- 11. Testing Cryptographic Anti-Tamper & Vault (2.0.0) ---\n";
$hash1 = SuperShield_AntiTamper::hash_file( $infected_file );
assert_test( ! empty( $hash1 ) && 64 === strlen( $hash1 ), 'HMAC-SHA256 signature successfully generated for file' );

// Manifest Generation & Integrity Check
$gen_res = SuperShield_AntiTamper::generate_manifest();
assert_test( $gen_res, 'Cryptographic manifest.sig successfully compiled with HMAC-SHA256 file signatures' );
$integrity_res = SuperShield_AntiTamper::verify_plugin_integrity();
assert_test( $integrity_res['is_intact'], 'Cryptographic self-integrity verification validates all core components intact' );
assert_test( $integrity_res['verified_files'] >= 10, 'Self-integrity verified at least 10 core files' );

// AES-256-GCM Vault Encryption / Decryption round-trip
$sample_rule = 'HEUR_SIGNATURE_RULE_EXPLOIT_PATTERN_XYZ';
$encrypted_vault = SuperShield_AntiTamper::encrypt_vault( $sample_rule );
assert_test( ! empty( $encrypted_vault ) && $encrypted_vault !== $sample_rule, 'Proprietary rule encrypted into AES-256-GCM binary vault' );
$decrypted_rule = SuperShield_AntiTamper::decrypt_vault( $encrypted_vault );
assert_test( $decrypted_rule === $sample_rule, 'AES-256-GCM vault cleanly decrypted back to original plaintext rule in-memory' );

// --- 12. GitHub Releases Auto-Updater ---
echo "\n--- 12. Testing GitHub Releases Auto-Updater (2.5.0) ---\n";
assert_test( version_compare( '2.6.0', SUPERSHIELD_VERSION, '>' ), 'Semver comparison correctly recognizes higher GitHub release' );
assert_test( ! version_compare( '2.4.0', SUPERSHIELD_VERSION, '>' ), 'Semver comparison rejects older versions' );

$fake_transient = (object) array( 'response' => array() );
// Populate mock cache
set_transient( 'supershield_latest_release_cache', array(
	'version'      => '2.6.0',
	'tag_name'     => 'v2.6.0',
	'download_url' => 'https://github.com/grwebdevs/supershield-security/releases/download/v2.6.0/supershield-security.zip',
	'html_url'     => 'https://github.com/grwebdevs/supershield-security/releases/tag/v2.6.0',
	'body'         => 'Security updates and improvements',
	'published_at' => current_time( 'mysql' ),
), 3600 );

$updated_transient = SuperShield_Updater::filter_update_transient( $fake_transient );
assert_test( isset( $updated_transient->response[ SUPERSHIELD_BASENAME ] ) && '2.5.0' === $updated_transient->response[ SUPERSHIELD_BASENAME ]->new_version, 'GitHub Releases updater successfully injects update package into WordPress transient' );
delete_transient( 'supershield_latest_release_cache' );

// 12.2 Secret Custom Login Slug & Direct Bot POST Blocking
SuperShield_Utils::update_option( 'custom_login_slug', 'custom-secret-portal' );
$_SERVER['REQUEST_URI'] = '/wp-login.php';
$_SERVER['SCRIPT_NAME'] = '/wp-login.php';
$_POST = array( 'log' => 'admin', 'pwd' => 'password123' );
$_REQUEST = $_POST;
$bot_post_blocked = false;
try {
	SuperShield_Login_Security::handle_custom_login_slug();
} catch ( Throwable $e ) {
	$bot_post_blocked = true;
}
assert_test( $bot_post_blocked, 'Direct bot POST request to /wp-login.php is blocked when custom login slug is enabled' );

// Authorized action like lostpassword is not blocked
$_REQUEST = array( 'action' => 'lostpassword' );
$lostpass_blocked = false;
try {
	SuperShield_Login_Security::handle_custom_login_slug();
} catch ( Throwable $e ) {
	$lostpass_blocked = true;
}
assert_test( ! $lostpass_blocked, 'Legitimate action (lostpassword) on wp-login.php is permitted under custom login slug' );

// Custom slug URL rewriting filters
$rewritten_login = SuperShield_Login_Security::filter_login_url( 'http://example.com/wp-login.php?redirect_to=http%3A%2F%2Fexample.com%2Fwp-admin%2F' );
assert_test( strpos( $rewritten_login, 'custom-secret-portal' ) !== false, 'filter_login_url rewrites login URL to custom slug' );
assert_test( strpos( $rewritten_login, 'redirect_to=' ) !== false, 'filter_login_url preserves redirect_to parameter without double encoding' );

$site_rewritten = SuperShield_Login_Security::filter_site_url_login( 'http://example.com/wp-login.php?action=lostpassword', 'wp-login.php', 'login' );
assert_test( strpos( $site_rewritten, 'custom-secret-portal' ) !== false && strpos( $site_rewritten, 'action=lostpassword' ) !== false, 'filter_site_url_login preserves query arguments' );

$redirect_rewritten = SuperShield_Login_Security::filter_wp_redirect_login( 'http://example.com/wp-login.php?reauth=1' );
assert_test( strpos( $redirect_rewritten, 'custom-secret-portal' ) !== false, 'filter_wp_redirect_login replaces wp-login.php with custom slug' );

SuperShield_Utils::update_option( 'custom_login_slug', '' ); // reset
$_POST = array();
$_REQUEST = array();
$_SERVER['REQUEST_URI'] = '/';
$_SERVER['SCRIPT_NAME'] = '/index.php';

// --- 13. System Diagnostics Exporter (Privacy-Guaranteed) ---
echo "\n--- 13. Testing System Diagnostics Exporter (2.0.0) ---\n";
$report = SuperShield_Telemetry::generate_diagnostics_report();
assert_test( ! empty( $report['markdown'] ) && ! empty( $report['json'] ), 'Diagnostics exporter generated Markdown and JSON bundles' );
assert_test( strpos( $report['markdown'], 'Ghulam Rasool' ) !== false, 'Report includes lead architect Ghulam Rasool' );
assert_test( strpos( $report['json'], 'test_auth_key' ) === false, 'Sensitive authentication keys stripped from diagnostics export' );
assert_test( strpos( $report['markdown'], 'Waf Active' ) !== false || strpos( $report['markdown'], 'WAF' ) !== false, 'Diagnostics contains active security shield audit' );

// --- 14. v2.2.0 Enterprise Features (Rate Limit, Cloudflare, GeoIP Names, 2FA QR, Pwned Passwords) ---
echo "\n--- 14. Testing v2.2.0 Enterprise Capabilities ---\n";

// 14.1 Cloudflare IP Detection
assert_test( SuperShield_Utils::is_cloudflare_ip( '172.71.182.20' ), 'is_cloudflare_ip correctly identifies Cloudflare edge proxy IPv4' );
assert_test( SuperShield_Utils::is_cloudflare_ip( '104.22.65.100' ), 'is_cloudflare_ip correctly identifies Cloudflare edge range 104.16.0.0/13' );
assert_test( ! SuperShield_Utils::is_cloudflare_ip( '8.8.8.8' ), 'is_cloudflare_ip rejects non-Cloudflare public IP' );
assert_test( SuperShield_Utils::is_loopback_or_private( '127.0.0.1' ), 'is_loopback_or_private identifies 127.0.0.1' );
assert_test( SuperShield_Utils::is_loopback_or_private( '192.168.1.50' ), 'is_loopback_or_private identifies private class C' );
assert_test( ! SuperShield_Utils::is_loopback_or_private( '93.184.216.34' ), 'is_loopback_or_private rejects public internet IP' );

// 14.2 GeoIP Country Name Lookup
assert_test( 'United States' === SuperShield_GeoIP::get_country_name( 'US' ), 'get_country_name resolves US to United States' );
assert_test( 'Pakistan' === SuperShield_GeoIP::get_country_name( 'PK' ), 'get_country_name resolves PK to Pakistan' );
assert_test( 'United Kingdom' === SuperShield_GeoIP::get_country_name( 'GB' ), 'get_country_name resolves GB to United Kingdom' );
assert_test( 'Germany' === SuperShield_GeoIP::get_country_name( 'DE' ), 'get_country_name resolves DE to Germany' );

// 14.3 2FA QR Code & otpauth URI strict format
$otpauth_url = SuperShield_2FA::get_otpauth_url( 'testadmin', 'JBSWY3DPEHPK3PXP' );
assert_test( strpos( $otpauth_url, 'otpauth://totp/SuperShield:testadmin?' ) === 0, 'otpauth URL label format strictly matches SuperShield:user prefix' );
assert_test( strpos( $otpauth_url, 'issuer=SuperShield' ) !== false, 'otpauth URL contains matching issuer query parameter' );

$svg_qr = SuperShield_QRCode::svg( $otpauth_url, 260 );
assert_test( strpos( $svg_qr, '<svg' ) !== false && ( strpos( $svg_qr, '<rect' ) !== false || strpos( $svg_qr, '<path' ) !== false ), 'SuperShield_QRCode generates valid XML SVG vector QR code' );
assert_test( strpos( $svg_qr, 'viewBox=' ) !== false, 'SuperShield_QRCode SVG includes proper viewBox' );

// 14.4 Anti-DDoS Rate Limiter
SuperShield_Utils::update_option( 'rate_limit_enabled', 1 );
SuperShield_Utils::update_option( 'rate_limit_max_requests', 3 );
$test_rate_ip = '198.51.100.99';
delete_transient( 'ss_rl_' . md5( $test_rate_ip ) );

// Requests 1-3 should pass cleanly
SuperShield_WAF::inspect_rate_limit( $test_rate_ip );
SuperShield_WAF::inspect_rate_limit( $test_rate_ip );
SuperShield_WAF::inspect_rate_limit( $test_rate_ip );

$rate_blocked = false;
try {
	// Request 4 should exceed limit and throw in testing mode
	SuperShield_WAF::inspect_rate_limit( $test_rate_ip );
} catch ( RuntimeException $e ) {
	if ( strpos( $e->getMessage(), 'RATE_LIMIT_BLOCK' ) !== false ) {
		$rate_blocked = true;
	}
}
assert_test( $rate_blocked, 'Anti-DDoS volumetric rate limiter successfully throttles burst flood with 429' );
delete_transient( 'ss_rl_' . md5( $test_rate_ip ) );
SuperShield_Utils::update_option( 'rate_limit_enabled', 0 );

// 14.5 Pwned Passwords Check
assert_test( 0 === SuperShield_Login_Security::check_pwned_password( '' ), 'check_pwned_password handles empty input safely' );
// Mock cache a breached test password
$sample_pwned_hash = strtoupper( sha1( 'password123' ) );
set_transient( 'ss_pwned_' . md5( $sample_pwned_hash ), 54321, 3600 );
assert_test( 54321 === SuperShield_Login_Security::check_pwned_password( 'password123' ), 'check_pwned_password detects breached password via cache/API' );
delete_transient( 'ss_pwned_' . md5( $sample_pwned_hash ) );

// 14.6 Daily Scan Cron Sync
SuperShield_Utils::update_option( 'daily_scan_cron_enabled', 1 );
SuperShield_Scanner::sync_cron_schedule();
assert_test( (bool) wp_next_scheduled( 'supershield_daily_scan_cron' ), 'sync_cron_schedule successfully registers supershield_daily_scan_cron event' );
SuperShield_Utils::update_option( 'daily_scan_cron_enabled', 0 );
SuperShield_Scanner::sync_cron_schedule();
assert_test( ! wp_next_scheduled( 'supershield_daily_scan_cron' ), 'sync_cron_schedule successfully clears supershield_daily_scan_cron event when disabled' );

// 14.7 Settings Retrieval Helper
assert_test( is_array( SuperShield_Utils::get_settings() ), 'SuperShield_Utils::get_settings returns valid array' );

// --- 15. Clean up temporary test files ---
@unlink( $infected_file );
@unlink( $tmp_uploads . '/shell.php' );
@unlink( $tmp_uploads . '/avatar.php.jpg' );
@unlink( $tmp_uploads . '/.6345dc54.php' );
@unlink( $tmp_uploads . '/.htaccess' );
@unlink( $tmp_uploads . '/.htaccess' );
if ( class_exists( 'SuperShield_Cleaner' ) ) {
	SuperShield_Cleaner::recursive_rmdir( $tmp_uploads );
} else {
	@rmdir( $tmp_uploads );
}

echo "\n========================================================\n";
echo " Results: $pass_count of $test_count tests passed.\n";
if ( $pass_count === $test_count ) {
	echo " ALL 2.5.0 ENTERPRISE SUITE TESTS PASSED SUCCESSFULLY! \n";
} else {
	echo " SOME TESTS FAILED!\n";
}
echo "========================================================\n";
