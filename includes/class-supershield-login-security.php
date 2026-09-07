<?php
/**
 * Login Security & Brute-Force Shield for SuperShield Security.
 *
 * @package    SuperShield_Security
 * @subpackage SuperShield_Security/includes
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SuperShield_Login_Security {

	/**
	 * Initialize login protection hooks.
	 */
	public static function init() {
		// Custom secret login URL slug handling
		$custom_slug = trim( (string) SuperShield_Utils::get_option( 'custom_login_slug', '' ) );
		if ( ! empty( $custom_slug ) ) {
			add_action( 'init', array( __CLASS__, 'handle_custom_login_slug' ), 1 );
			add_filter( 'site_url', array( __CLASS__, 'filter_site_url_login' ), 10, 3 );
			add_filter( 'login_url', array( __CLASS__, 'filter_login_url' ), 10, 2 );
		}

		// Enterprise Two-Factor Authentication (2FA) Hook (independent of bruteforce toggle)
		if ( class_exists( 'SuperShield_2FA' ) ) {
			SuperShield_2FA::init();
		}

		if ( ! SuperShield_Utils::get_option( 'bruteforce_protection', 1 ) ) {
			return;
		}

		// Check lockout before authentication
		add_filter( 'authenticate', array( __CLASS__, 'check_pre_authentication' ), 5, 3 );

		// Hook login failures
		add_action( 'wp_login_failed', array( __CLASS__, 'handle_failed_login' ), 10, 1 );

		// Hook successful logins
		add_action( 'wp_login', array( __CLASS__, 'handle_successful_login' ), 10, 2 );

		// Generic login error messages
		add_filter( 'login_errors', array( __CLASS__, 'obfuscate_login_errors' ) );

		// Honeypot trap on login form
		if ( SuperShield_Utils::get_option( 'enable_login_honeypot', 1 ) ) {
			add_action( 'login_form', array( __CLASS__, 'render_honeypot_field' ) );
			add_filter( 'authenticate', array( __CLASS__, 'verify_honeypot' ), 10, 3 );
		}
	}

	/**
	 * Block login attempt if IP is currently locked out.
	 *
	 * @param WP_User|WP_Error|null $user
	 * @param string                $username
	 * @param string                $password
	 * @return WP_User|WP_Error|null
	 */
	public static function check_pre_authentication( $user, $username, $password ) {
		$client_ip = SuperShield_Utils::get_client_ip();

		if ( SuperShield_IP_Manager::is_whitelisted( $client_ip ) ) {
			return $user;
		}

		$block = SuperShield_DB::get_active_ip_block( $client_ip );
		if ( $block ) {
			return new WP_Error(
				'supershield_ip_locked',
				'<strong>ACCESS TEMPORARILY LOCKED:</strong> Your IP (' . esc_html( $client_ip ) . ') is temporarily locked out due to multiple failed login attempts. Please try again later.'
			);
		}

		return $user;
	}

	/**
	 * Handle failed login attempt.
	 *
	 * @param string $username
	 */
	public static function handle_failed_login( $username ) {
		$client_ip = SuperShield_Utils::get_client_ip();

		if ( SuperShield_IP_Manager::is_whitelisted( $client_ip ) ) {
			return;
		}

		$max_attempts = (int) SuperShield_Utils::get_option( 'max_login_retries', 5 );
		$lockout_duration = (int) SuperShield_Utils::get_option( 'login_lockout_duration', 3600 ); // 1 hour default

		$transient_key = 'supershield_attempts_' . md5( $client_ip );
		$attempts = (int) get_transient( $transient_key );
		$attempts++;

		SuperShield_DB::log_event(
			'login_fail',
			'Failed login attempt for username: ' . sanitize_user( $username ),
			"Attempt #$attempts of $max_attempts",
			$client_ip
		);

		if ( $attempts >= $max_attempts ) {
			delete_transient( $transient_key );
			SuperShield_DB::block_ip(
				$client_ip,
				"Excessive failed login attempts ($attempts failures)",
				'bruteforce',
				$lockout_duration
			);
			SuperShield_DB::log_event(
				'login_lockout',
				"IP temporarily locked out for $lockout_duration seconds after $attempts failed attempts.",
				"User: $username",
				$client_ip
			);
		} else {
			set_transient( $transient_key, $attempts, $lockout_duration );
		}
	}

	/**
	 * Handle successful login: reset counter and log audit entry.
	 *
	 * @param string  $user_login
	 * @param WP_User $user
	 */
	public static function handle_successful_login( $user_login, $user ) {
		$client_ip = SuperShield_Utils::get_client_ip();
		$transient_key = 'supershield_attempts_' . md5( $client_ip );
		delete_transient( $transient_key );

		SuperShield_DB::log_event(
			'login_success',
			'Successful login by user: ' . $user_login . ' (ID #' . $user->ID . ')',
			'Role: ' . implode( ', ', (array) $user->roles ),
			$client_ip
		);
	}

	/**
	 * Replace verbose login errors with a safe generic notice.
	 *
	 * @param string $error
	 * @return string
	 */
	public static function obfuscate_login_errors( $error ) {
		if ( empty( $error ) ) {
			return $error;
		}

		// Preserve SuperShield security notices (2FA prompts, lockouts, honeypots)
		$preserved_keywords = array(
			'supershield_ip_locked',
			'supershield_2fa',
			'supershield_bot_detected',
			'SECURITY CODE',
			'TWO-FACTOR',
			'AUTHENTICATION REQUIRED',
			'TEMPORARILY LOCKED',
			'INVALID SECURITY CODE',
		);

		foreach ( $preserved_keywords as $keyword ) {
			if ( strpos( $error, $keyword ) !== false ) {
				return $error;
			}
		}

		return '<strong>ERROR:</strong> Invalid username or incorrect password.';
	}

	/**
	 * Render invisible honeypot field.
	 */
	public static function render_honeypot_field() {
		echo '<div style="display:none !important; visibility:hidden !important; opacity:0 !important; position:absolute !important; left:-9999px !important;">' .
			 '<label for="supershield_hp_code">Do not fill this</label>' .
			 '<input type="text" name="supershield_hp_code" id="supershield_hp_code" value="" autocomplete="off" tabindex="-1" />' .
			 '</div>';
	}

	/**
	 * Check honeypot submission.
	 *
	 * @param WP_User|WP_Error|null $user
	 * @param string                $username
	 * @param string                $password
	 * @return WP_User|WP_Error|null
	 */
	public static function verify_honeypot( $user, $username, $password ) {
		if ( isset( $_POST['supershield_hp_code'] ) && ! empty( $_POST['supershield_hp_code'] ) ) {
			$client_ip = SuperShield_Utils::get_client_ip();
			SuperShield_DB::log_event( 'waf_block', 'Automated Bot Detected via Honeypot trap', 'Payload: ' . sanitize_text_field( wp_unslash( $_POST['supershield_hp_code'] ) ), $client_ip );
			SuperShield_DB::block_ip( $client_ip, 'Bot Honeypot Trap Triggered', 'waf', 86400 );

			return new WP_Error( 'supershield_bot_detected', 'Automated bot activity detected.' );
		}
		return $user;
	}

	/**
	 * Intercept custom login slug requests and protect wp-login.php direct access.
	 */
	public static function handle_custom_login_slug() {
		$custom_slug = trim( (string) SuperShield_Utils::get_option( 'custom_login_slug', '' ) );
		if ( empty( $custom_slug ) ) {
			return;
		}

		$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '';
		$parsed_path = trim( (string) parse_url( $request_uri, PHP_URL_PATH ), '/' );

		// Accessing custom slug -> internally load login page
		if ( $parsed_path === $custom_slug ) {
			if ( ! function_exists( 'is_user_logged_in' ) || ! is_user_logged_in() ) {
				if ( function_exists( 'status_header' ) ) {
					status_header( 200 );
				}
				if ( defined( 'ABSPATH' ) && file_exists( ABSPATH . 'wp-login.php' ) ) {
					require_once ABSPATH . 'wp-login.php';
					if ( ! defined( 'SUPERSHIELD_TESTING' ) ) {
						exit;
					}
				}
			} else {
				if ( function_exists( 'admin_url' ) && function_exists( 'wp_safe_redirect' ) ) {
					wp_safe_redirect( admin_url() );
					if ( ! defined( 'SUPERSHIELD_TESTING' ) ) {
						exit;
					}
				}
			}
		}

		// Direct access to wp-login.php without custom slug -> block / 404
		if ( strpos( $request_uri, 'wp-login.php' ) !== false && ( ! function_exists( 'is_user_logged_in' ) || ! is_user_logged_in() ) ) {
			$action = isset( $_REQUEST['action'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['action'] ) ) : '';
			$allowed_actions = array( 'logout', 'postpass', 'lostpassword', 'retrievepassword', 'resetpass', 'rp' );
			if ( ! in_array( $action, $allowed_actions, true ) ) {
				if ( function_exists( 'status_header' ) ) {
					status_header( 404 );
				}
				if ( function_exists( 'nocache_headers' ) ) {
					nocache_headers();
				}
				if ( function_exists( 'wp_die' ) ) {
					wp_die( 'The requested login page does not exist.', '404 Not Found', array( 'response' => 404 ) );
				}
			}
		}
	}

	/**
	 * Rewrite login URL to custom slug.
	 *
	 * @param string $login_url
	 * @param string $redirect
	 * @return string
	 */
	public static function filter_login_url( $login_url, $redirect = '' ) {
		$custom_slug = trim( (string) SuperShield_Utils::get_option( 'custom_login_slug', '' ) );
		if ( empty( $custom_slug ) || ! function_exists( 'home_url' ) ) {
			return $login_url;
		}
		$new_url = home_url( '/' . $custom_slug );
		if ( ! empty( $redirect ) && function_exists( 'add_query_arg' ) ) {
			$new_url = add_query_arg( 'redirect_to', urlencode( $redirect ), $new_url );
		}
		return $new_url;
	}

	/**
	 * Filter site_url for login endpoints.
	 *
	 * @param string $url
	 * @param string $path
	 * @param string $scheme
	 * @return string
	 */
	public static function filter_site_url_login( $url, $path, $scheme ) {
		if ( 'login' === $scheme || 'login_post' === $scheme || strpos( $path, 'wp-login.php' ) !== false ) {
			$custom_slug = trim( (string) SuperShield_Utils::get_option( 'custom_login_slug', '' ) );
			if ( ! empty( $custom_slug ) && function_exists( 'home_url' ) ) {
				return home_url( '/' . $custom_slug );
			}
		}
		return $url;
	}
}
