<?php
/**
 * Enterprise TOTP Two-Factor Authentication & Zero-Trust Login for SuperShield Security.
 *
 * Fully compliant with RFC 6238 (TOTP) and RFC 4226 (HOTP).
 * Compatible with Google Authenticator, Authy, 1Password, Bitwarden, Microsoft Authenticator.
 *
 * @package    SuperShield_Security
 * @subpackage SuperShield_Security/includes
 * @author     Ghulam Rasool <grwebdevs.com>
 * @version    2.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SuperShield_2FA {

	/**
	 * Base32 character map for RFC 4648.
	 *
	 * @var string
	 */
	private static $b32_alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

	/**
	 * Initialize 2FA hooks into WordPress authentication flow.
	 */
	public static function init() {
		$enabled = SuperShield_Utils::get_option( '2fa_enabled', 0 );
		if ( ! $enabled ) {
			return;
		}

		// Inject 2FA input field into default WordPress login form
		add_action( 'login_form', array( __CLASS__, 'render_login_2fa_field' ) );

		// Authenticate user check (priority 30 runs after standard wp_authenticate_username_password)
		add_filter( 'authenticate', array( __CLASS__, 'filter_authenticate' ), 30, 3 );
	}

	/**
	 * Check if 2FA is active and configured for a given user.
	 *
	 * @param int $user_id
	 * @return bool
	 */
	public static function is_user_2fa_enabled( $user_id ) {
		$enabled = get_user_meta( $user_id, '_supershield_2fa_enabled', true );
		$secret  = get_user_meta( $user_id, '_supershield_2fa_secret', true );
		return ( '1' === (string) $enabled && ! empty( $secret ) );
	}

	/**
	 * Check if a user role is mandated to enforce 2FA.
	 *
	 * @param WP_User $user
	 * @return bool
	 */
	public static function is_role_enforced( $user ) {
		if ( ! $user || ! isset( $user->roles ) || ! is_array( $user->roles ) ) {
			return false;
		}

		$enforced_roles = SuperShield_Utils::get_option( '2fa_roles', array( 'administrator' ) );
		if ( ! is_array( $enforced_roles ) ) {
			$enforced_roles = array( 'administrator' );
		}

		foreach ( $user->roles as $role ) {
			if ( in_array( $role, $enforced_roles, true ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Render TOTP 2FA input field on the login form.
	 */
	public static function render_login_2fa_field() {
		?>
		<p class="supershield-2fa-login-row">
			<label for="supershield_2fa_code"><?php esc_html_e( 'Security Code / 2FA / Backup Code', 'supershield-security' ); ?><br />
			<input type="text" name="supershield_2fa_code" id="supershield_2fa_code" class="input" value="" size="20" autocomplete="one-time-code" placeholder="6-digit code or backup code" style="font-family:monospace; letter-spacing: 2px;" /></label>
		</p>
		<?php
	}

	/**
	 * Intercept authentication to verify 2FA TOTP code or emergency backup code.
	 *
	 * @param WP_User|WP_Error|null $user
	 * @param string                $username
	 * @param string                $password
	 * @return WP_User|WP_Error|null
	 */
	public static function filter_authenticate( $user, $username, $password ) {
		// If already an error or null, pass through
		if ( is_wp_error( $user ) || ! ( $user instanceof WP_User ) ) {
			return $user;
		}

		$user_id = $user->ID;
		$is_2fa_active = self::is_user_2fa_enabled( $user_id );
		$is_role_mandatory = self::is_role_enforced( $user );

		// If user doesn't need 2FA, allow login
		if ( ! $is_2fa_active && ! $is_role_mandatory ) {
			return $user;
		}

		// If role requires 2FA but user hasn't configured it yet:
		if ( ! $is_2fa_active && $is_role_mandatory ) {
			$grace_days = (int) SuperShield_Utils::get_option( '2fa_grace_period_days', 3 );
			$grace_start = get_user_meta( $user_id, '_supershield_2fa_grace_start', true );
			if ( empty( $grace_start ) ) {
				$grace_start = time();
				update_user_meta( $user_id, '_supershield_2fa_grace_start', $grace_start );
			}

			$grace_expiry = (int) $grace_start + ( $grace_days * 86400 );

			if ( time() > $grace_expiry ) {
				return new WP_Error(
					'supershield_2fa_mandatory_lock',
					'<strong>TWO-FACTOR AUTHENTICATION REQUIRED:</strong> Your user role requires mandatory 2FA. The grace period has expired. Please contact the site administrator to reset your account.'
				);
			}
			// Still within grace period
			return $user;
		}

		// Check submitted code
		$submitted_code = isset( $_POST['supershield_2fa_code'] ) ? sanitize_text_field( wp_unslash( $_POST['supershield_2fa_code'] ) ) : '';
		$submitted_code = str_replace( array( ' ', '-' ), '', trim( $submitted_code ) );

		if ( empty( $submitted_code ) ) {
			return new WP_Error(
				'supershield_2fa_missing',
				'<strong>SECURITY CODE REQUIRED:</strong> Please enter the 6-digit TOTP code from your authenticator app (or an 8-character backup recovery code).'
			);
		}

		$secret = get_user_meta( $user_id, '_supershield_2fa_secret', true );

		// 1. Try TOTP code verification (6 digits)
		if ( preg_match( '/^\d{6}$/', $submitted_code ) ) {
			if ( self::verify_totp( $secret, $submitted_code ) ) {
				SuperShield_DB::log_event(
					'login_success',
					'2FA TOTP authentication verified for user: ' . $user->user_login,
					'Method: TOTP Authenticator App'
				);
				return $user;
			}
		}

		// 2. Try Emergency Recovery Backup Code verification (8 characters alphanumeric)
		if ( self::verify_backup_code( $user_id, $submitted_code ) ) {
			SuperShield_DB::log_event(
				'login_success',
				'Emergency One-Time Backup Code consumed for user: ' . $user->user_login,
				'Method: Backup Recovery Code'
			);
			return $user;
		}

		// If neither matched:
		$client_ip = SuperShield_Utils::get_client_ip();
		SuperShield_DB::log_event(
			'login_fail',
			'Invalid 2FA code provided for user: ' . $user->user_login,
			'Submitted code failed verification',
			$client_ip
		);

		return new WP_Error(
			'supershield_2fa_invalid',
			'<strong>INVALID SECURITY CODE:</strong> The 2FA security code or backup code you entered is invalid or has expired.'
		);
	}

	/**
	 * Generate a random 16-character Base32 secret key.
	 *
	 * @param int $length
	 * @return string
	 */
	public static function generate_secret( $length = 16 ) {
		$secret = '';
		$alphabet_length = strlen( self::$b32_alphabet );

		for ( $i = 0; $i < $length; $i++ ) {
			$random_index = function_exists( 'random_int' ) ? random_int( 0, $alphabet_length - 1 ) : mt_rand( 0, $alphabet_length - 1 );
			$secret .= self::$b32_alphabet[ $random_index ];
		}

		return $secret;
	}

	/**
	 * Decode Base32 string into binary.
	 *
	 * @param string $b32
	 * @return string|false
	 */
	public static function base32_decode( $b32 ) {
		$b32 = strtoupper( trim( $b32 ) );
		$b32 = preg_replace( '/[^A-Z2-7]/', '', $b32 );

		if ( empty( $b32 ) ) {
			return false;
		}

		$binary_string = '';
		$buffer = 0;
		$bits_left = 0;

		for ( $i = 0, $len = strlen( $b32 ); $i < $len; $i++ ) {
			$val = strpos( self::$b32_alphabet, $b32[ $i ] );
			if ( false === $val ) {
				continue;
			}

			$buffer = ( $buffer << 5 ) | $val;
			$bits_left += 5;

			if ( $bits_left >= 8 ) {
				$bits_left -= 8;
				$binary_string .= chr( ( $buffer >> $bits_left ) & 0xFF );
			}
		}

		return $binary_string;
	}

	/**
	 * Calculate 6-digit TOTP code for a secret and time slice.
	 *
	 * @param string   $secret Base32 secret.
	 * @param int|null $time_slice 30-second interval (defaults to current time).
	 * @return string|false
	 */
	public static function get_totp_code( $secret, $time_slice = null ) {
		if ( null === $time_slice ) {
			$time_slice = (int) floor( time() / 30 );
		}

		$key = self::base32_decode( $secret );
		if ( false === $key ) {
			return false;
		}

		// Pack counter as 64-bit big-endian integer
		$packed_time = pack( 'N*', 0 ) . pack( 'N*', $time_slice );

		// HMAC-SHA1
		$hash = hash_hmac( 'sha1', $packed_time, $key, true );

		// Dynamic truncation
		$offset = ord( substr( $hash, -1 ) ) & 0x0F;
		$truncated_hash = substr( $hash, $offset, 4 );

		$value = unpack( 'N', $truncated_hash );
		$value = $value[1] & 0x7FFFFFFF;

		$modulo = 1000000;
		$pin = str_pad( (string) ( $value % $modulo ), 6, '0', STR_PAD_LEFT );

		return $pin;
	}

	/**
	 * Verify TOTP code with standard clock-drift allowance (+/- 1 time step = 30s).
	 *
	 * @param string $secret
	 * @param string $code
	 * @param int    $discrepancy Windows to check before and after.
	 * @return bool
	 */
	public static function verify_totp( $secret, $code, $discrepancy = 1 ) {
		$code = trim( (string) $code );
		if ( strlen( $code ) !== 6 || ! ctype_digit( $code ) ) {
			return false;
		}

		$current_slice = (int) floor( time() / 30 );

		for ( $i = -$discrepancy; $i <= $discrepancy; $i++ ) {
			$calculated = self::get_totp_code( $secret, $current_slice + $i );
			if ( hash_equals( (string) $calculated, $code ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Generate 8 single-use emergency backup recovery codes.
	 *
	 * @param int $count
	 * @return array<string> Formatted codes (e.g. ['A4X9-K2P8', ...])
	 */
	public static function generate_backup_codes( $count = 8 ) {
		$codes = array();
		$chars = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
		$chars_len = strlen( $chars );

		for ( $i = 0; $i < $count; $i++ ) {
			$part1 = '';
			$part2 = '';
			for ( $j = 0; $j < 4; $j++ ) {
				$part1 .= $chars[ random_int( 0, $chars_len - 1 ) ];
				$part2 .= $chars[ random_int( 0, $chars_len - 1 ) ];
			}
			$codes[] = $part1 . '-' . $part2;
		}

		return $codes;
	}

	/**
	 * Save hashed backup codes for user.
	 *
	 * @param int   $user_id
	 * @param array $codes Array of raw backup codes.
	 */
	public static function save_user_backup_codes( $user_id, $codes ) {
		$hashed = array();
		foreach ( $codes as $code ) {
			$clean = strtoupper( str_replace( array( '-', ' ' ), '', trim( $code ) ) );
			$hashed[] = hash( 'sha256', $clean );
		}
		update_user_meta( $user_id, '_supershield_2fa_backup_codes', $hashed );
	}

	/**
	 * Verify and consume a single-use backup recovery code.
	 *
	 * @param int    $user_id
	 * @param string $code Raw backup code.
	 * @return bool
	 */
	public static function verify_backup_code( $user_id, $code ) {
		$clean = strtoupper( str_replace( array( '-', ' ' ), '', trim( $code ) ) );
		if ( strlen( $clean ) !== 8 ) {
			return false;
		}

		$input_hash = hash( 'sha256', $clean );
		$stored_hashes = get_user_meta( $user_id, '_supershield_2fa_backup_codes', true );

		if ( ! is_array( $stored_hashes ) || empty( $stored_hashes ) ) {
			return false;
		}

		foreach ( $stored_hashes as $index => $stored_hash ) {
			if ( hash_equals( $stored_hash, $input_hash ) ) {
				// Match! Consume code immediately
				unset( $stored_hashes[ $index ] );
				update_user_meta( $user_id, '_supershield_2fa_backup_codes', array_values( $stored_hashes ) );
				return true;
			}
		}

		return false;
	}

	/**
	 * Get count of remaining emergency recovery backup codes.
	 *
	 * @param int $user_id
	 * @return int
	 */
	public static function get_remaining_backup_codes_count( $user_id ) {
		$stored = get_user_meta( $user_id, '_supershield_2fa_backup_codes', true );
		return is_array( $stored ) ? count( $stored ) : 0;
	}

	/**
	 * Enable 2FA for user.
	 *
	 * @param int    $user_id
	 * @param string $secret
	 * @param array  $backup_codes
	 */
	public static function enable_user_2fa( $user_id, $secret, $backup_codes = array() ) {
		update_user_meta( $user_id, '_supershield_2fa_secret', sanitize_text_field( $secret ) );
		update_user_meta( $user_id, '_supershield_2fa_enabled', '1' );

		if ( ! empty( $backup_codes ) ) {
			self::save_user_backup_codes( $user_id, $backup_codes );
		}
	}

	/**
	 * Disable 2FA for user.
	 *
	 * @param int $user_id
	 */
	public static function disable_user_2fa( $user_id ) {
		delete_user_meta( $user_id, '_supershield_2fa_secret' );
		delete_user_meta( $user_id, '_supershield_2fa_enabled' );
		delete_user_meta( $user_id, '_supershield_2fa_backup_codes' );
	}

	/**
	 * Generate otpauth:// URI string for mobile authenticators.
	 *
	 * @param string $username
	 * @param string $secret
	 * @param string $issuer
	 * @return string
	 */
	public static function get_otpauth_url( $username, $secret, $issuer = 'SuperShield Security' ) {
		$site_name = function_exists( 'get_bloginfo' ) ? get_bloginfo( 'name' ) : 'WordPress';
		$label = rawurlencode( $issuer . ':' . $username );
		$issuer_encoded = rawurlencode( $issuer . ' (' . $site_name . ')' );
		return "otpauth://totp/{$label}?secret={$secret}&issuer={$issuer_encoded}&algorithm=SHA1&digits=6&period=30";
	}

	/**
	 * Dependency-free, pure-PHP SVG QR-Code matrix renderer for TOTP setup.
	 * Generates an ultra-crisp, offline SVG without external API calls or tracking.
	 *
	 * @param string $data Text/URL to encode.
	 * @param int    $pixel_size Size in px.
	 * @return string SVG markup.
	 */
	public static function render_qr_code_svg( $data, $pixel_size = 200 ) {
		if ( class_exists( 'SuperShield_QRCode' ) ) {
			return SuperShield_QRCode::get_svg( $data, $pixel_size );
		}
		return "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 {$pixel_size} {$pixel_size}' width='{$pixel_size}' height='{$pixel_size}'><rect width='100%' height='100%' fill='#ffffff'/></svg>";
	}
}
