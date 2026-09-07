<?php
/**
 * IP Whitelist & Blacklist Manager for SuperShield Security.
 *
 * @package    SuperShield_Security
 * @subpackage SuperShield_Security/includes
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SuperShield_IP_Manager {

	/**
	 * Check if an IP is whitelisted.
	 *
	 * @param string $ip IP address to check.
	 * @return bool
	 */
	public static function is_whitelisted( $ip ) {
		// Always whitelist loopback and local in non-strict modes if configured
		if ( '127.0.0.1' === $ip || '::1' === $ip ) {
			// Check setting
			$allow_loopback = SuperShield_Utils::get_option( 'whitelist_loopback', 1 );
			if ( $allow_loopback ) {
				return true;
			}
		}

		$whitelist = SuperShield_Utils::get_option( 'ip_whitelist', array() );
		if ( ! is_array( $whitelist ) ) {
			$whitelist = array_filter( array_map( 'trim', explode( "\n", $whitelist ) ) );
		}

		foreach ( $whitelist as $entry ) {
			if ( empty( $entry ) ) {
				continue;
			}
			if ( SuperShield_Utils::ip_in_range( $ip, $entry ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Check if an IP is manually blacklisted or temporarily blocked.
	 *
	 * @param string $ip IP address to check.
	 * @return array|false Returns block details array if blocked, false otherwise.
	 */
	public static function is_blocked( $ip ) {
		// Whitelisted IPs are never blocked
		if ( self::is_whitelisted( $ip ) ) {
			return false;
		}

		// 1. Check manual blacklist in settings
		$blacklist = SuperShield_Utils::get_option( 'ip_blacklist', array() );
		if ( ! is_array( $blacklist ) ) {
			$blacklist = array_filter( array_map( 'trim', explode( "\n", $blacklist ) ) );
		}

		foreach ( $blacklist as $entry ) {
			if ( empty( $entry ) ) {
				continue;
			}
			if ( SuperShield_Utils::ip_in_range( $ip, $entry ) ) {
				return array(
					'reason'     => 'Manual Blacklist Match: ' . $entry,
					'block_type' => 'manual',
					'expires_at' => null,
				);
			}
		}

		// 2. Check active dynamic blocks in DB
		$db_block = SuperShield_DB::get_active_ip_block( $ip );
		if ( $db_block ) {
			return array(
				'reason'     => $db_block->reason,
				'block_type' => $db_block->block_type,
				'expires_at' => $db_block->expires_at,
			);
		}

		return false;
	}

	/**
	 * Add an IP to the persistent whitelist.
	 *
	 * @param string $ip
	 * @return bool
	 */
	public static function add_to_whitelist( $ip ) {
		$whitelist = SuperShield_Utils::get_option( 'ip_whitelist', array() );
		if ( ! is_array( $whitelist ) ) {
			$whitelist = array_filter( array_map( 'trim', explode( "\n", $whitelist ) ) );
		}

		if ( ! in_array( $ip, $whitelist, true ) ) {
			$whitelist[] = $ip;
			return SuperShield_Utils::update_option( 'ip_whitelist', $whitelist );
		}

		return true;
	}

	/**
	 * Remove an IP from whitelist.
	 *
	 * @param string $ip
	 * @return bool
	 */
	public static function remove_from_whitelist( $ip ) {
		$whitelist = SuperShield_Utils::get_option( 'ip_whitelist', array() );
		if ( ! is_array( $whitelist ) ) {
			$whitelist = array_filter( array_map( 'trim', explode( "\n", $whitelist ) ) );
		}

		$whitelist = array_diff( $whitelist, array( $ip ) );
		return SuperShield_Utils::update_option( 'ip_whitelist', array_values( $whitelist ) );
	}
}
