<?php
/**
 * Offline GeoIP & Country Blocking Engine for SuperShield Security.
 *
 * @package    SuperShield_Security
 * @subpackage SuperShield_Security/includes
 * @author     Ghulam Rasool <grwebdevs.com>
 * @version    2.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SuperShield_GeoIP {

	/**
	 * Common country codes and names mapping.
	 *
	 * @var array<string, string>
	 */
	private static $countries = array(
		'AF' => 'Afghanistan', 'AL' => 'Albania', 'DZ' => 'Algeria', 'AS' => 'American Samoa',
		'AD' => 'Andorra', 'AO' => 'Angola', 'AI' => 'Anguilla', 'AQ' => 'Antarctica',
		'AG' => 'Antigua and Barbuda', 'AR' => 'Argentina', 'AM' => 'Armenia', 'AW' => 'Aruba',
		'AU' => 'Australia', 'AT' => 'Austria', 'AZ' => 'Azerbaijan', 'BS' => 'Bahamas',
		'BH' => 'Bahrain', 'BD' => 'Bangladesh', 'BB' => 'Barbados', 'BY' => 'Belarus',
		'BE' => 'Belgium', 'BZ' => 'Belize', 'BJ' => 'Benin', 'BM' => 'Bermuda',
		'BT' => 'Bhutan', 'BO' => 'Bolivia', 'BA' => 'Bosnia and Herzegovina', 'BW' => 'Botswana',
		'BR' => 'Brazil', 'IO' => 'British Indian Ocean Territory', 'BN' => 'Brunei', 'BG' => 'Bulgaria',
		'BF' => 'Burkina Faso', 'BI' => 'Burundi', 'KH' => 'Cambodia', 'CM' => 'Cameroon',
		'CA' => 'Canada', 'CV' => 'Cape Verde', 'KY' => 'Cayman Islands', 'CF' => 'Central African Republic',
		'TD' => 'Chad', 'CL' => 'Chile', 'CN' => 'China', 'CX' => 'Christmas Island',
		'CC' => 'Cocos (Keeling) Islands', 'CO' => 'Colombia', 'KM' => 'Comoros', 'CG' => 'Congo',
		'CD' => 'Congo, Democratic Republic', 'CK' => 'Cook Islands', 'CR' => 'Costa Rica', 'CI' => 'Cote d\'Ivoire',
		'HR' => 'Croatia', 'CU' => 'Cuba', 'CY' => 'Cyprus', 'CZ' => 'Czech Republic',
		'DK' => 'Denmark', 'DJ' => 'Djibouti', 'DM' => 'Dominica', 'DO' => 'Dominican Republic',
		'EC' => 'Ecuador', 'EG' => 'Egypt', 'SV' => 'El Salvador', 'GQ' => 'Equatorial Guinea',
		'ER' => 'Eritrea', 'EE' => 'Estonia', 'ET' => 'Ethiopia', 'FK' => 'Falkland Islands',
		'FO' => 'Faroe Islands', 'FJ' => 'Fiji', 'FI' => 'Finland', 'FR' => 'France',
		'GF' => 'French Guiana', 'PF' => 'French Polynesia', 'GA' => 'Gabon', 'GM' => 'Gambia',
		'GE' => 'Georgia', 'DE' => 'Germany', 'GH' => 'Ghana', 'GI' => 'Gibraltar',
		'GR' => 'Greece', 'GL' => 'Greenland', 'GD' => 'Grenada', 'GP' => 'Guadeloupe',
		'GU' => 'Guam', 'GT' => 'Guatemala', 'GN' => 'Guinea', 'GW' => 'Guinea-Bissau',
		'GY' => 'Guyana', 'HT' => 'Haiti', 'HN' => 'Honduras', 'HK' => 'Hong Kong',
		'HU' => 'Hungary', 'IS' => 'Iceland', 'IN' => 'India', 'ID' => 'Indonesia',
		'IR' => 'Iran', 'IQ' => 'Iraq', 'IE' => 'Ireland', 'IL' => 'Israel',
		'IT' => 'Italy', 'JM' => 'Jamaica', 'JP' => 'Japan', 'JO' => 'Jordan',
		'KZ' => 'Kazakhstan', 'KE' => 'Kenya', 'KI' => 'Kiribati', 'KP' => 'North Korea',
		'KR' => 'South Korea', 'KW' => 'Kuwait', 'KG' => 'Kyrgyzstan', 'LA' => 'Laos',
		'LV' => 'Latvia', 'LB' => 'Lebanon', 'LS' => 'Lesotho', 'LR' => 'Liberia',
		'LY' => 'Libya', 'LI' => 'Liechtenstein', 'LT' => 'Lithuania', 'LU' => 'Luxembourg',
		'MO' => 'Macao', 'MK' => 'North Macedonia', 'MG' => 'Madagascar', 'MW' => 'Malawi',
		'MY' => 'Malaysia', 'MV' => 'Maldives', 'ML' => 'Mali', 'MT' => 'Malta',
		'MH' => 'Marshall Islands', 'MQ' => 'Martinique', 'MR' => 'Mauritania', 'MU' => 'Mauritius',
		'YT' => 'Mayotte', 'MX' => 'Mexico', 'FM' => 'Micronesia', 'MD' => 'Moldova',
		'MC' => 'Monaco', 'MN' => 'Mongolia', 'ME' => 'Montenegro', 'MS' => 'Montserrat',
		'MA' => 'Morocco', 'MZ' => 'Mozambique', 'MM' => 'Myanmar', 'NA' => 'Namibia',
		'NR' => 'Nauru', 'NP' => 'Nepal', 'NL' => 'Netherlands', 'NC' => 'New Caledonia',
		'NZ' => 'New Zealand', 'NI' => 'Nicaragua', 'NE' => 'Niger', 'NG' => 'Nigeria',
		'NO' => 'Norway', 'OM' => 'Oman', 'PK' => 'Pakistan', 'PW' => 'Palau',
		'PS' => 'Palestine', 'PA' => 'Panama', 'PG' => 'Papua New Guinea', 'PY' => 'Paraguay',
		'PE' => 'Peru', 'PH' => 'Philippines', 'PL' => 'Poland', 'PT' => 'Portugal',
		'PR' => 'Puerto Rico', 'QA' => 'Qatar', 'RO' => 'Romania', 'RU' => 'Russian Federation',
		'RW' => 'Rwanda', 'SA' => 'Saudi Arabia', 'SN' => 'Senegal', 'RS' => 'Serbia',
		'SG' => 'Singapore', 'SK' => 'Slovakia', 'SI' => 'Slovenia', 'SO' => 'Somalia',
		'ZA' => 'South Africa', 'ES' => 'Spain', 'LK' => 'Sri Lanka', 'SD' => 'Sudan',
		'SE' => 'Sweden', 'CH' => 'Switzerland', 'SY' => 'Syria', 'TW' => 'Taiwan',
		'TJ' => 'Tajikistan', 'TZ' => 'Tanzania', 'TH' => 'Thailand', 'TR' => 'Turkey',
		'UA' => 'Ukraine', 'AE' => 'United Arab Emirates', 'GB' => 'United Kingdom', 'US' => 'United States',
		'UY' => 'Uruguay', 'UZ' => 'Uzbekistan', 'VE' => 'Venezuela', 'VN' => 'Vietnam',
		'YE' => 'Yemen', 'ZM' => 'Zambia', 'ZW' => 'Zimbabwe',
	);

	/**
	 * Offline sample IP range prefixes for instant offline resolution without external API calls.
	 *
	 * @var array<string, string>
	 */
	private static $offline_ranges = array(
		'1.0.0.0/8'       => 'AU',
		'3.0.0.0/8'       => 'US',
		'4.0.0.0/8'       => 'US',
		'8.0.0.0/8'       => 'US',
		'12.0.0.0/8'      => 'US',
		'13.0.0.0/8'      => 'US',
		'14.0.0.0/8'      => 'JP',
		'15.0.0.0/8'      => 'US',
		'16.0.0.0/8'      => 'US',
		'17.0.0.0/8'      => 'US',
		'18.0.0.0/8'      => 'US',
		'20.0.0.0/8'      => 'US',
		'23.0.0.0/8'      => 'US',
		'24.0.0.0/8'      => 'US',
		'27.0.0.0/8'      => 'CN',
		'32.0.0.0/8'      => 'US',
		'34.0.0.0/8'      => 'US',
		'35.0.0.0/8'      => 'US',
		'36.0.0.0/8'      => 'CN',
		'39.0.0.0/8'      => 'PK',
		'42.0.0.0/8'      => 'CN',
		'49.0.0.0/8'      => 'IN',
		'52.0.0.0/8'      => 'US',
		'54.0.0.0/8'      => 'US',
		'58.0.0.0/8'      => 'CN',
		'77.0.0.0/8'      => 'RU',
		'80.0.0.0/8'      => 'DE',
		'81.0.0.0/8'      => 'GB',
		'82.0.0.0/8'      => 'FR',
		'85.0.0.0/8'      => 'NL',
		'91.0.0.0/8'      => 'RU',
		'95.0.0.0/8'      => 'RU',
		'103.0.0.0/8'     => 'SG',
		'110.0.0.0/8'     => 'CN',
		'111.0.0.0/8'     => 'CN',
		'112.0.0.0/8'     => 'CN',
		'115.0.0.0/8'     => 'CN',
		'116.0.0.0/8'     => 'PK',
		'117.0.0.0/8'     => 'IN',
		'118.0.0.0/8'     => 'ID',
		'121.0.0.0/8'     => 'CN',
		'122.0.0.0/8'     => 'JP',
		'123.0.0.0/8'     => 'CN',
		'124.0.0.0/8'     => 'JP',
		'125.0.0.0/8'     => 'CN',
		'175.0.0.0/8'     => 'KP',
		'178.0.0.0/8'     => 'RU',
		'185.0.0.0/8'     => 'DE',
		'192.0.2.0/24'    => 'US',
		'198.51.100.0/24' => 'US',
		'203.0.113.0/24'  => 'US',
	);

	/**
	 * Retrieve all supported country codes and names.
	 *
	 * @return array<string, string>
	 */
	public static function get_countries() {
		return self::$countries;
	}

	/**
	 * Resolve client IP to 2-letter ISO Country Code.
	 * Prioritizes Cloudflare headers, then checks local offline lookup and GeoLite2 file if present.
	 *
	 * @param string $ip Client IP.
	 * @return string 2-letter ISO Country Code (e.g. 'US', 'PK', 'CN') or 'XX' if unknown.
	 */
	public static function resolve_country( $ip = null ) {
		$ip = ( null !== $ip ) ? trim( (string) $ip ) : SuperShield_Utils::get_client_ip();

		// 1. Check Cloudflare & Edge Headers
		$header_keys = array(
			'HTTP_CF_IPCOUNTRY',
			'CF-IPCountry',
			'HTTP_X_COUNTRY_CODE',
			'HTTP_GEOIP_COUNTRY_CODE',
		);

		foreach ( $header_keys as $key ) {
			if ( ! empty( $_SERVER[ $key ] ) ) {
				$code = strtoupper( trim( sanitize_text_field( wp_unslash( $_SERVER[ $key ] ) ) ) );
				if ( 2 === strlen( $code ) && preg_match( '/^[A-Z]{2}$/', $code ) && 'XX' !== $code && 'T1' !== $code ) {
					return $code;
				}
			}
		}

		// Private or loopback IPs
		if ( '127.0.0.1' === $ip || '::1' === $ip || ! filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
			return 'LOCAL';
		}

		// 2. Check local MaxMind GeoLite2 binary database if uploaded
		$custom_mmdb = self::get_database_path();
		if ( file_exists( $custom_mmdb ) && is_readable( $custom_mmdb ) ) {
			$mmdb_country = self::lookup_mmdb( $ip, $custom_mmdb );
			if ( ! empty( $mmdb_country ) ) {
				return $mmdb_country;
			}
		}

		// 3. High-Speed Built-in Offline CIDR matching
		foreach ( self::$offline_ranges as $range => $country ) {
			if ( SuperShield_Utils::ip_in_range( $ip, $range ) ) {
				return $country;
			}
		}

		// Fallback for unidentified public IP
		return 'XX';
	}

	/**
	 * Get the storage path for optional GeoLite2 database.
	 *
	 * @return string
	 */
	public static function get_database_path() {
		$upload_dir = wp_upload_dir();
		return trailingslashit( $upload_dir['basedir'] ) . 'supershield-data/GeoLite2-Country.mmdb';
	}

	/**
	 * Simple MaxMind DB parser fallback.
	 *
	 * @param string $ip
	 * @param string $db_file
	 * @return string|null
	 */
	private static function lookup_mmdb( $ip, $db_file ) {
		// If custom MaxMind DB reader library is present, invoke it
		if ( class_exists( 'GeoIp2\Database\Reader' ) ) {
			try {
				$reader = new \GeoIp2\Database\Reader( $db_file );
				$record = $reader->country( $ip );
				return $record->country->isoCode;
			} catch ( Throwable $e ) {
				return null;
			}
		}
		return null;
	}

	/**
	 * Check if a country is allowed under current GeoIP policies.
	 *
	 * @param string $country_code 2-letter ISO code.
	 * @return bool True if allowed, false if blocked.
	 */
	public static function is_country_allowed( $country_code ) {
		if ( 'LOCAL' === $country_code ) {
			return true;
		}

		$enabled = SuperShield_Utils::get_option( 'geoip_enabled', 0 );
		if ( ! $enabled ) {
			return true;
		}

		$mode = SuperShield_Utils::get_option( 'geoip_mode', 'blacklist' );
		$country_list = SuperShield_Utils::get_option( 'geoip_countries', array() );

		if ( ! is_array( $country_list ) ) {
			$country_list = array();
		}

		$country_list = array_map( 'strtoupper', array_map( 'trim', $country_list ) );
		$country_code = strtoupper( trim( $country_code ) );

		if ( 'blacklist' === $mode ) {
			// If in blacklist, block it
			return ! in_array( $country_code, $country_list, true );
		} elseif ( 'whitelist' === $mode ) {
			// If whitelist is empty, do not lock out the entire site
			if ( empty( $country_list ) ) {
				return true;
			}
			// If whitelist, ONLY allow if in list
			return in_array( $country_code, $country_list, true );
		}

		return true;
	}

	/**
	 * Inspect current request against GeoIP blocking rules.
	 *
	 * @param string $ip Client IP address.
	 */
	public static function inspect_request( $ip = null ) {
		$enabled = SuperShield_Utils::get_option( 'geoip_enabled', 0 );
		if ( ! $enabled ) {
			return;
		}

		$ip = ( null !== $ip ) ? $ip : SuperShield_Utils::get_client_ip();

		// Whitelist bypass
		if ( SuperShield_IP_Manager::is_whitelisted( $ip ) ) {
			return;
		}

		$protect_login_only = SuperShield_Utils::get_option( 'geoip_protect_login_only', 0 );
		if ( $protect_login_only ) {
			$raw_uri = isset( $_SERVER['REQUEST_URI'] ) ? strtolower( $_SERVER['REQUEST_URI'] ) : '';
			// Do not block public frontend admin-ajax.php calls
			if ( strpos( $raw_uri, 'admin-ajax.php' ) !== false ) {
				return;
			}
			$custom_slug = strtolower( trim( (string) SuperShield_Utils::get_option( 'custom_login_slug', '' ) ) );
			$is_custom = ( ! empty( $custom_slug ) && strpos( $raw_uri, '/' . $custom_slug ) !== false );
			$is_login = ( strpos( $raw_uri, 'wp-login.php' ) !== false || strpos( $raw_uri, 'wp-admin' ) !== false || $is_custom );
			if ( ! $is_login ) {
				return;
			}
		}

		$country = self::resolve_country( $ip );

		if ( ! self::is_country_allowed( $country ) ) {
			$country_name = isset( self::$countries[ $country ] ) ? self::$countries[ $country ] : $country;
			$reason = sprintf( 'Access restricted for geographic territory (%s - %s) by SuperShield GeoIP Policy', $country, $country_name );

			SuperShield_DB::log_event(
				'geoip_block',
				$reason,
				'Country Code: ' . $country,
				$ip
			);

			SuperShield_WAF::block_request( $reason, 'geoip_block', $ip );
		}
	}
}
