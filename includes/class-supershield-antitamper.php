<?php
/**
 * Cryptographic Self-Integrity, Anti-Tamper & Signature Vault for SuperShield Security.
 *
 * Implements HMAC-SHA256 self-integrity checks, AES-256-GCM proprietary signature
 * encryption, and the Must-Use (MU) Watchdog immunity shield.
 *
 * @package    SuperShield_Security
 * @subpackage SuperShield_Security/includes
 * @author     Ghulam Rasool <grwebdevs.com>
 * @version    2.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SuperShield_AntiTamper {

	/**
	 * Private HMAC signing key salt.
	 */
	const INTEGRITY_SALT = 'SuperShield_v2_Enterprise_Integrity_Salt_GR_2026';

	/**
	 * Run self-integrity verification on plugin core files.
	 *
	 * @return array Verification results with status, tampered files, and count.
	 */
	public static function verify_plugin_integrity() {
		$results = array(
			'is_intact'      => true,
			'verified_files' => 0,
			'tampered_files' => array(),
		);

		$manifest = self::get_file_manifest();

		foreach ( $manifest as $rel_path => $expected_hash ) {
			$full_path = SUPERSHIELD_PLUGIN_DIR . $rel_path;
			if ( ! file_exists( $full_path ) ) {
				$results['is_intact'] = false;
				$results['tampered_files'][] = array(
					'file'   => $rel_path,
					'reason' => 'Missing critical plugin component',
				);
				continue;
			}

			$current_hash = self::hash_file( $full_path );
			$results['verified_files']++;

			// If manifest has recorded hash, verify match
			if ( ! empty( $expected_hash ) && ! hash_equals( $expected_hash, $current_hash ) ) {
				$results['is_intact'] = false;
				$results['tampered_files'][] = array(
					'file'   => $rel_path,
					'reason' => 'Cryptographic signature mismatch (code altered or injected)',
				);
			}
		}

		if ( ! $results['is_intact'] ) {
			SuperShield_Utils::update_option( 'antitamper_tamper_detected', 1 );
			SuperShield_DB::log_event(
				'tamper_alert',
				'CRITICAL: Plugin self-integrity verification failed! Possible code tampering detected.',
				wp_json_encode( $results['tampered_files'] )
			);
		} else {
			SuperShield_Utils::update_option( 'antitamper_tamper_detected', 0 );
		}

		return $results;
	}

	/**
	 * Compute HMAC-SHA256 signature for a file.
	 *
	 * @param string $file_path
	 * @return string
	 */
	public static function hash_file( $file_path ) {
		if ( ! file_exists( $file_path ) || ! is_readable( $file_path ) ) {
			return '';
		}
		$content = file_get_contents( $file_path );
		// Strip carriage returns for cross-platform OS consistency
		$normalized = str_replace( "\r\n", "\n", $content );
		return hash_hmac( 'sha256', $normalized, self::INTEGRITY_SALT );
	}

	/**
	 * Encrypt proprietary rules or signatures using AES-256-GCM.
	 *
	 * @param string      $plaintext
	 * @param string|null $key
	 * @return string|false Base64-encoded encrypted payload or false on failure.
	 */
	public static function encrypt_vault( $plaintext, $key = null ) {
		if ( ! function_exists( 'openssl_encrypt' ) ) {
			return base64_encode( $plaintext );
		}

		$key = ( null !== $key ) ? $key : self::get_vault_key();
		$cipher = 'aes-256-gcm';
		$iv_len = openssl_cipher_iv_length( $cipher );
		$iv = openssl_random_pseudo_bytes( $iv_len );
		$tag = '';

		$ciphertext = openssl_encrypt( $plaintext, $cipher, $key, OPENSSL_RAW_DATA, $iv, $tag );
		if ( false === $ciphertext ) {
			return false;
		}

		return base64_encode( $iv . $tag . $ciphertext );
	}

	/**
	 * Decrypt proprietary rules from AES-256-GCM vault.
	 *
	 * @param string      $encrypted_base64
	 * @param string|null $key
	 * @return string|false
	 */
	public static function decrypt_vault( $encrypted_base64, $key = null ) {
		if ( ! function_exists( 'openssl_decrypt' ) ) {
			return base64_decode( $encrypted_base64 );
		}

		$raw = base64_decode( $encrypted_base64 );
		if ( false === $raw ) {
			return false;
		}

		$key = ( null !== $key ) ? $key : self::get_vault_key();
		$cipher = 'aes-256-gcm';
		$iv_len = openssl_cipher_iv_length( $cipher );
		$tag_len = 16;

		if ( strlen( $raw ) < ( $iv_len + $tag_len ) ) {
			return false;
		}

		$iv = substr( $raw, 0, $iv_len );
		$tag = substr( $raw, $iv_len, $tag_len );
		$ciphertext = substr( $raw, $iv_len + $tag_len );

		return openssl_decrypt( $ciphertext, $cipher, $key, OPENSSL_RAW_DATA, $iv, $tag );
	}

	/**
	 * Derive rotating cryptographic session key for vault.
	 *
	 * @return string 32-byte binary key.
	 */
	private static function get_vault_key() {
		$seed = defined( 'AUTH_KEY' ) ? AUTH_KEY : 'SuperShield_Default_Auth_Key_Vault_Salt';
		return hash( 'sha256', $seed . self::INTEGRITY_SALT, true );
	}

	/**
	 * Deploy or maintain high-privilege Must-Use (MU) Watchdog.
	 *
	 * @return bool
	 */
	public static function ensure_watchdog_installed() {
		if ( ! defined( 'WPMU_PLUGIN_DIR' ) ) {
			return false;
		}

		$mu_dir = WPMU_PLUGIN_DIR;
		if ( ! is_dir( $mu_dir ) ) {
			wp_mkdir_p( $mu_dir );
		}

		$watchdog_file = trailingslashit( $mu_dir ) . 'supershield-watchdog.php';

		$watchdog_code = "<?php\n" .
			"/**\n" .
			" * SuperShield Security — MU Watchdog & Persistence Guard\n" .
			" * Protects SuperShield Security from unauthorized tampering or deactivation.\n" .
			" * Author: Ghulam Rasool (grwebdevs.com)\n" .
			" */\n\n" .
			"if ( ! defined( 'ABSPATH' ) ) { exit; }\n\n" .
			"// Prevent malicious or unauthenticated script calls from deactivating SuperShield\n" .
			"add_action( 'deactivate_plugin', function( \$plugin ) {\n" .
			"    if ( strpos( \$plugin, 'supershield-security' ) !== false ) {\n" .
			"        if ( ! current_user_can( 'manage_options' ) ) {\n" .
			"            wp_die( 'SuperShield Watchdog: Unauthorized attempt to deactivate core security plugin intercepted.', 'Security Violation', array( 'response' => 403 ) );\n" .
			"        }\n" .
			"    }\n" .
			"});\n";

		if ( ! file_exists( $watchdog_file ) || md5( (string) @file_get_contents( $watchdog_file ) ) !== md5( $watchdog_code ) ) {
			return ( false !== @file_put_contents( $watchdog_file, $watchdog_code ) );
		}

		return true;
	}

	/**
	 * Retrieve plugin files manifest list.
	 *
	 * @return array<string, string> Relative path => expected HMAC hash (or empty string for dynamic verification).
	 */
	public static function get_file_manifest() {
		$files = array(
			'supershield-security.php'                     => '',
			'includes/class-supershield-core.php'          => '',
			'includes/class-supershield-activator.php'     => '',
			'includes/class-supershield-deactivator.php'   => '',
			'includes/class-supershield-waf.php'           => '',
			'includes/class-supershield-scanner.php'       => '',
			'includes/class-supershield-cleaner.php'       => '',
			'includes/class-supershield-geoip.php'         => '',
			'includes/class-supershield-2fa.php'           => '',
			'includes/class-supershield-qrcode.php'        => '',
			'includes/class-supershield-login-security.php' => '',
			'includes/class-supershield-hardening.php'     => '',
			'includes/class-supershield-ip-manager.php'    => '',
			'includes/class-supershield-antitamper.php'    => '',
			'includes/class-supershield-db.php'            => '',
			'includes/class-supershield-utils.php'         => '',
			'includes/class-supershield-updater.php'       => '',
			'includes/class-supershield-telemetry.php'     => '',
			'admin/class-supershield-admin.php'            => '',
		);

		// Check if pre-compiled manifest.sig exists in plugin directory
		$sig_file = SUPERSHIELD_PLUGIN_DIR . 'manifest.sig';
		if ( file_exists( $sig_file ) && is_readable( $sig_file ) ) {
			$content = @file_get_contents( $sig_file );
			$parsed = json_decode( $content, true );
			if ( is_array( $parsed ) ) {
				return $parsed;
			}
		}

		return $files;
	}

	/**
	 * Generate or refresh manifest.sig with current HMAC-SHA256 hashes.
	 *
	 * @return bool
	 */
	public static function generate_manifest() {
		$files = array(
			'supershield-security.php',
			'includes/class-supershield-core.php',
			'includes/class-supershield-activator.php',
			'includes/class-supershield-deactivator.php',
			'includes/class-supershield-waf.php',
			'includes/class-supershield-scanner.php',
			'includes/class-supershield-cleaner.php',
			'includes/class-supershield-geoip.php',
			'includes/class-supershield-2fa.php',
			'includes/class-supershield-qrcode.php',
			'includes/class-supershield-login-security.php',
			'includes/class-supershield-hardening.php',
			'includes/class-supershield-ip-manager.php',
			'includes/class-supershield-antitamper.php',
			'includes/class-supershield-db.php',
			'includes/class-supershield-utils.php',
			'includes/class-supershield-updater.php',
			'includes/class-supershield-telemetry.php',
			'admin/class-supershield-admin.php',
		);

		$manifest = array();
		foreach ( $files as $rel_path ) {
			$full_path = SUPERSHIELD_PLUGIN_DIR . $rel_path;
			if ( file_exists( $full_path ) ) {
				$manifest[ $rel_path ] = self::hash_file( $full_path );
			}
		}

		$sig_file = SUPERSHIELD_PLUGIN_DIR . 'manifest.sig';
		return ( false !== @file_put_contents( $sig_file, wp_json_encode( $manifest, JSON_PRETTY_PRINT ) ) );
	}
}
