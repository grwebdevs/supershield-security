<?php
/**
 * Hardening and System Immunity Engine for SuperShield Security.
 *
 * @package    SuperShield_Security
 * @subpackage SuperShield_Security/includes
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SuperShield_Hardening {

	/**
	 * Initialize all active hardening hooks.
	 */
	public static function init() {
		// 1. Disable XML-RPC if enabled (Layer 2)
		if ( SuperShield_Utils::get_option( 'disable_xmlrpc', 1 ) ) {
			add_filter( 'xmlrpc_enabled', '__return_false' );
			add_filter( 'xmlrpc_methods', '__return_empty_array' );
			remove_action( 'wp_head', 'rsd_link' );
			remove_action( 'wp_head', 'wlwmanifest_link' );

			// Early blocking of xmlrpc.php requests
			if ( isset( $_SERVER['REQUEST_URI'] ) && strpos( strtolower( $_SERVER['REQUEST_URI'] ), 'xmlrpc.php' ) !== false ) {
				if ( function_exists( 'status_header' ) ) {
					status_header( 403 );
				}
				wp_die( 'XML-RPC is disabled by SuperShield Security for system hardening.', 'XML-RPC Blocked', array( 'response' => 403 ) );
			}
		}

		// 2. Hide WordPress Version Meta & Query Strings (Layer 6)
		if ( SuperShield_Utils::get_option( 'hide_wp_version', 1 ) ) {
			remove_action( 'wp_head', 'wp_generator' );
			add_filter( 'the_generator', '__return_empty_string' );
			add_filter( 'style_loader_src', array( __CLASS__, 'remove_version_strings' ), 9999 );
			add_filter( 'script_loader_src', array( __CLASS__, 'remove_version_strings' ), 9999 );
		}

		// 3. Block User Enumeration (author queries & REST API) (Layer 3)
		if ( SuperShield_Utils::get_option( 'block_user_enumeration', 1 ) ) {
			self::block_author_scan();
			add_action( 'template_redirect', array( __CLASS__, 'block_author_scan' ) );
			add_filter( 'rest_endpoints', array( __CLASS__, 'restrict_rest_users_endpoint' ) );
		}

		// 4. Inject HTTP Security Headers (Layer 5)
		if ( SuperShield_Utils::get_option( 'security_headers', 1 ) ) {
			add_action( 'send_headers', array( __CLASS__, 'send_security_headers' ) );
		}

		// 5. Enforce DISALLOW_FILE_EDIT constant if enabled (Layer 4)
		if ( SuperShield_Utils::get_option( 'disallow_file_edit', 1 ) ) {
			if ( ! defined( 'DISALLOW_FILE_EDIT' ) ) {
				define( 'DISALLOW_FILE_EDIT', true );
			}
		}

		// 6. Ensure Uploads .htaccess immunity is written (Layer 1)
		if ( SuperShield_Utils::get_option( 'block_uploads_php', 1 ) ) {
			self::ensure_uploads_htaccess_immunity();
		}

		// 7. Protect wp-config.php and Sensitive System Files (Layer 7)
		if ( SuperShield_Utils::get_option( 'protect_config_files', 1 ) ) {
			$raw_uri = isset( $_SERVER['REQUEST_URI'] ) ? rawurldecode( $_SERVER['REQUEST_URI'] ) : '';
			if ( ! empty( $raw_uri ) && preg_match( '/(^|\/)(wp-config\.php|\.htaccess|php\.ini|\.user\.ini)/i', $raw_uri ) ) {
				if ( function_exists( 'status_header' ) ) {
					status_header( 403 );
				}
				wp_die( 'Direct access to core configuration files is blocked by SuperShield Security.', 'Access Denied', array( 'response' => 403 ) );
			}
		}

		// 8. Block Stealth Dropper & Hidden Files (Layer 8)
		if ( SuperShield_Utils::get_option( 'block_hidden_files', 1 ) ) {
			$raw_uri = isset( $_SERVER['REQUEST_URI'] ) ? rawurldecode( $_SERVER['REQUEST_URI'] ) : '';
			if ( ! empty( $raw_uri ) && preg_match( '/\/\..*\.php/i', $raw_uri ) ) {
				if ( function_exists( 'status_header' ) ) {
					status_header( 403 );
				}
				wp_die( 'Hidden dot-dropper file access blocked by SuperShield Security.', 'Dropper Blocked', array( 'response' => 403 ) );
			}
		}
	}

	/**
	 * Strip ?ver= query strings from scripts & stylesheets.
	 *
	 * @param string $src
	 * @return string
	 */
	public static function remove_version_strings( $src ) {
		if ( strpos( $src, 'ver=' ) ) {
			$src = remove_query_arg( 'ver', $src );
		}
		return $src;
	}

	/**
	 * Block author scan enumeration (?author=1).
	 */
	public static function block_author_scan() {
		if ( function_exists( 'is_admin' ) && is_admin() ) {
			return;
		}

		if ( isset( $_REQUEST['author'] ) ) {
			if ( ! empty( $_REQUEST['author'] ) || '0' === $_REQUEST['author'] ) {
				if ( function_exists( 'status_header' ) ) {
					status_header( 403 );
				}
				wp_die( 'User enumeration queries are blocked by SuperShield Security.', 'Author Scan Blocked', array( 'response' => 403 ) );
			}
		}
	}

	/**
	 * Restrict access to /wp-json/wp/v2/users endpoint to authenticated users only.
	 *
	 * @param array $endpoints
	 * @return array
	 */
	public static function restrict_rest_users_endpoint( $endpoints ) {
		if ( function_exists( 'is_user_logged_in' ) && ! is_user_logged_in() ) {
			if ( isset( $endpoints['/wp/v2/users'] ) ) {
				unset( $endpoints['/wp/v2/users'] );
			}
			if ( isset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] ) ) {
				unset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] );
			}
		}
		return $endpoints;
	}

	/**
	 * Transmit modern HTTP security headers.
	 */
	public static function send_security_headers() {
		if ( headers_sent() ) {
			return;
		}

		header( 'X-Frame-Options: SAMEORIGIN' );
		header( 'X-Content-Type-Options: nosniff' );
		header( 'X-XSS-Protection: 1; mode=block' );
		header( 'Referrer-Policy: strict-origin-when-cross-origin' );
		header( 'Permissions-Policy: camera=(), microphone=(), geolocation=()' );
	}

	/**
	 * Guarantee that wp-content/uploads/ has a locked .htaccess blocking PHP execution.
	 */
	public static function ensure_uploads_htaccess_immunity() {
		$upload_dir = wp_upload_dir();
		$htaccess_file = trailingslashit( $upload_dir['basedir'] ) . '.htaccess';

		$rules = "# BEGIN SuperShield Security — Uploads PHP Lockdown\n" .
				 "<IfModule !mod_authz_core.c>\n" .
				 "    <FilesMatch \"(?i)\\.(php|phtml|php3|php4|php5|php7|phps|phar)$\">\n" .
				 "        Order Deny,Allow\n" .
				 "        Deny from all\n" .
				 "    </FilesMatch>\n" .
				 "</IfModule>\n" .
				 "<IfModule mod_authz_core.c>\n" .
				 "    <FilesMatch \"(?i)\\.(php|phtml|php3|php4|php5|php7|phps|phar)$\">\n" .
				 "        Require all denied\n" .
				 "    </FilesMatch>\n" .
				 "</IfModule>\n" .
				 "# END SuperShield Security\n";

		if ( ! file_exists( $htaccess_file ) ) {
			@file_put_contents( $htaccess_file, $rules );
			@chmod( $htaccess_file, 0444 );
		} else {
			$current = @file_get_contents( $htaccess_file );
			if ( false !== $current && strpos( $current, 'SuperShield Security' ) === false ) {
				@chmod( $htaccess_file, 0644 );
				@file_put_contents( $htaccess_file, $rules . "\n" . $current );
				@chmod( $htaccess_file, 0444 );
			}
		}
	}
}
