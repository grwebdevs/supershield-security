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
			add_filter( 'network_site_url', array( __CLASS__, 'filter_site_url_login' ), 10, 3 );
			add_filter( 'login_url', array( __CLASS__, 'filter_login_url' ), 10, 3 );
			add_filter( 'wp_redirect', array( __CLASS__, 'filter_wp_redirect_login' ), 10, 2 );
		}

		// Enterprise Two-Factor Authentication (2FA) Hook (independent of bruteforce toggle)
		if ( class_exists( 'SuperShield_2FA' ) ) {
			SuperShield_2FA::init();
		}

		// Pwned Passwords Breached Database check (HaveIBeenPwned k-Anonymity)
		if ( SuperShield_Utils::get_option( 'pwned_passwords_check', 0 ) ) {
			add_filter( 'authenticate', array( __CLASS__, 'check_pwned_password_on_login' ), 25, 3 );
			add_action( 'check_passwords', array( __CLASS__, 'check_pwned_password_on_reset' ), 10, 3 );
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

			// Dispatch Wordfence-style Lockout Email Alert
			if ( class_exists( 'SuperShield_Notifier' ) ) {
				SuperShield_Notifier::notify_brute_lockout( $client_ip, $username );
			}
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
	 * @param string|WP_Error $error
	 * @return string|WP_Error
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
			'Please enter your 6-digit TOTP code',
		);

		if ( is_wp_error( $error ) ) {
			$err_code = (string) $error->get_error_code();
			$err_msg  = (string) $error->get_error_message();

			foreach ( $preserved_keywords as $keyword ) {
				if ( false !== stripos( $err_code, $keyword ) || false !== stripos( $err_msg, $keyword ) ) {
					return $error;
				}
			}

			return new WP_Error( 'invalid_credentials', 'Invalid username or password.' );
		}

		$error_str = (string) $error;
		foreach ( $preserved_keywords as $keyword ) {
			if ( false !== stripos( $error_str, $keyword ) ) {
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

		// Adjust for subdirectory WordPress installations
		if ( function_exists( 'home_url' ) ) {
			$home_path = trim( (string) parse_url( home_url(), PHP_URL_PATH ), '/' );
			if ( ! empty( $home_path ) && 0 === strpos( $parsed_path, $home_path ) ) {
				$parsed_path = trim( substr( $parsed_path, strlen( $home_path ) ), '/' );
			}
		}

		// Accessing custom slug -> internally load login page
		if ( $parsed_path === $custom_slug ) {
			global $pagenow, $error, $interim_login, $action, $user_login;
			$pagenow = 'wp-login.php';

			$action = isset( $_REQUEST['action'] ) ? sanitize_key( $_REQUEST['action'] ) : 'login';

			if ( function_exists( 'is_user_logged_in' ) && is_user_logged_in() && ! in_array( $action, array( 'logout', 'postpass' ), true ) ) {
				if ( function_exists( 'admin_url' ) && function_exists( 'wp_safe_redirect' ) ) {
					wp_safe_redirect( admin_url() );
					if ( ! defined( 'SUPERSHIELD_TESTING' ) ) {
						exit;
					}
					return;
				}
			}

			if ( function_exists( 'status_header' ) ) {
				status_header( 200 );
			}
			if ( function_exists( 'nocache_headers' ) ) {
				nocache_headers();
			}

			if ( defined( 'ABSPATH' ) && file_exists( ABSPATH . 'wp-login.php' ) ) {
				require_once ABSPATH . 'wp-login.php';
				if ( ! defined( 'SUPERSHIELD_TESTING' ) ) {
					exit;
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
	 * @param bool   $force_reauth
	 * @return string
	 */
	public static function filter_login_url( $login_url, $redirect = '', $force_reauth = false ) {
		$custom_slug = trim( (string) SuperShield_Utils::get_option( 'custom_login_slug', '' ) );
		if ( empty( $custom_slug ) || ! function_exists( 'home_url' ) ) {
			return $login_url;
		}

		$parsed = parse_url( $login_url );
		$new_url = trailingslashit( home_url( '/' . $custom_slug ) );

		$query_args = array();
		if ( ! empty( $parsed['query'] ) ) {
			if ( function_exists( 'wp_parse_str' ) ) {
				wp_parse_str( $parsed['query'], $query_args );
			} else {
				parse_str( $parsed['query'], $query_args );
			}
			if ( ! empty( $redirect ) ) {
				$query_args['redirect_to'] = $redirect;
			}
			if ( $force_reauth ) {
				$query_args['reauth'] = '1';
			}
			$new_url = add_query_arg( $query_args, $new_url );
		} elseif ( ! empty( $redirect ) ) {
			$new_url = add_query_arg( 'redirect_to', $redirect, $new_url );
			if ( $force_reauth ) {
				$new_url = add_query_arg( 'reauth', '1', $new_url );
			}
		}

		return $new_url;
	}

	/**
	 * Filter site_url and network_site_url for login endpoints.
	 *
	 * @param string      $url
	 * @param string      $path
	 * @param string|null $scheme
	 * @return string
	 */
	public static function filter_site_url_login( $url, $path, $scheme = null ) {
		if ( 'login' === $scheme || 'login_post' === $scheme || ( is_string( $path ) && strpos( $path, 'wp-login.php' ) !== false ) ) {
			$custom_slug = trim( (string) SuperShield_Utils::get_option( 'custom_login_slug', '' ) );
			if ( ! empty( $custom_slug ) && function_exists( 'home_url' ) ) {
				$parsed = parse_url( $url );
				$new_url = trailingslashit( home_url( '/' . $custom_slug ) );
				if ( ! empty( $parsed['query'] ) ) {
					$new_url .= '?' . $parsed['query'];
				}
				return $new_url;
			}
		}
		return $url;
	}

	/**
	 * Filter wp_redirect to replace wp-login.php with custom login slug.
	 *
	 * @param string $location
	 * @param int    $status
	 * @return string
	 */
	public static function filter_wp_redirect_login( $location, $status = 302 ) {
		$custom_slug = trim( (string) SuperShield_Utils::get_option( 'custom_login_slug', '' ) );
		if ( empty( $custom_slug ) ) {
			return $location;
		}

		if ( false !== strpos( $location, 'wp-login.php' ) ) {
			$location = str_replace( 'wp-login.php', trailingslashit( $custom_slug ), $location );
		}

		return $location;
	}

	/**
	 * Verify password against HaveIBeenPwned k-Anonymity database on login.
	 *
	 * Only evaluates when credentials match a valid WP_User to prevent timing attacks.
	 *
	 * @param WP_User|WP_Error|null $user Authenticated user or error.
	 * @param string                $username Username or email.
	 * @param string                $password Plaintext password attempted.
	 * @return WP_User|WP_Error
	 */
	public static function check_pwned_password_on_login( $user, $username, $password ) {
		if ( ( $user instanceof WP_User ) && ! empty( $password ) ) {
			$pwned_count = self::check_pwned_password( $password );
			if ( $pwned_count > 0 ) {
				$client_ip = SuperShield_Utils::get_client_ip();
				if ( class_exists( 'SuperShield_DB' ) ) {
					SuperShield_DB::log_event(
						'AUTH_BREACHED_PASSWORD',
						"Compromised password detected for user '{$username}'. Appears in " . number_format_i18n( $pwned_count ) . " public breaches.",
						'',
						$client_ip
					);
				}

				return new WP_Error(
					'supershield_pwned_password',
					sprintf(
						'<strong>SECURITY BREACH DETECTED:</strong> This password was discovered in %s known public data breaches (via HaveIBeenPwned). For your account safety, this password has been rejected. Please reset your password.',
						number_format_i18n( $pwned_count )
					)
				);
			}
		}

		return $user;
	}

	/**
	 * Verify password against HaveIBeenPwned when a user changes/resets password.
	 *
	 * @param stdClass $user User object.
	 * @param string   $pass1 Plaintext password 1.
	 * @param string   $pass2 Plaintext password 2.
	 */
	public static function check_pwned_password_on_reset( $user, &$pass1, &$pass2 ) {
		if ( ! empty( $pass1 ) ) {
			$pwned_count = self::check_pwned_password( $pass1 );
			if ( $pwned_count > 0 && isset( $user->errors ) && is_object( $user->errors ) ) {
				$user->errors->add(
					'supershield_pwned_password',
					sprintf(
						'<strong>INSECURE PASSWORD:</strong> This password has appeared in %s public data leaks. Choose a different, unique password.',
						number_format_i18n( $pwned_count )
					)
				);
			}
		}
	}

	/**
	 * Check if password is compromised using HaveIBeenPwned k-Anonymity API.
	 *
	 * Uses SHA-1 prefix (first 5 characters) so the password hash never leaves the server.
	 *
	 * @param string $password
	 * @return int Number of times seen in data breaches (0 if safe or service down).
	 */
	public static function check_pwned_password( $password ) {
		if ( empty( $password ) || ! is_string( $password ) ) {
			return 0;
		}

		$hash = strtoupper( sha1( $password ) );
		$prefix = substr( $hash, 0, 5 );
		$suffix = substr( $hash, 5 );

		$cache_key = 'ss_pwned_' . md5( $hash );
		$cached = function_exists( 'get_transient' ) ? get_transient( $cache_key ) : false;
		if ( false !== $cached ) {
			return (int) $cached;
		}

		$url = 'https://api.pwnedpasswords.com/range/' . $prefix;
		$response = function_exists( 'wp_remote_get' ) ? wp_remote_get( $url, array(
			'timeout'    => 3,
			'user-agent' => 'SuperShield-Security-v2.2.1',
		) ) : null;

		if ( is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			return 0; // Fail-open on network issues
		}

		$body = wp_remote_retrieve_body( $response );
		if ( empty( $body ) ) {
			return 0;
		}

		$lines = explode( "\n", $body );
		$count = 0;
		foreach ( $lines as $line ) {
			$line = trim( $line );
			if ( empty( $line ) ) {
				continue;
			}
			$parts = explode( ':', $line );
			if ( count( $parts ) >= 2 && strtoupper( trim( $parts[0] ) ) === $suffix ) {
				$count = (int) trim( $parts[1] );
				break;
			}
		}

		if ( function_exists( 'set_transient' ) ) {
			set_transient( $cache_key, $count, 3600 );
		}

		return $count;
	}
}
