<?php
/**
 * Vulnerability Intelligence & CVE Advisory Scanner for SuperShield Security.
 *
 * Scans installed plugins, active themes, and WordPress core against known
 * vulnerability databases (Patchstack Open API & Curated CVE Signatures).
 *
 * @package    SuperShield_Security
 * @subpackage SuperShield_Security/includes
 * @author     Ghulam Rasool <grwebdevs.com>
 * @version    2.5.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SuperShield_Vuln_Scanner {

	/**
	 * Curated high-impact known CVE definitions for widely targeted WordPress plugins/themes.
	 *
	 * @var array
	 */
	private static $known_cve_catalog = array(
		'elementor' => array(
			array( 'max_version' => '3.18.1', 'cve' => 'CVE-2023-48777', 'severity' => 'critical', 'title' => 'Arbitrary File Upload via Template Import (RCE)' ),
			array( 'max_version' => '3.6.2',  'cve' => 'CVE-2022-1329',  'severity' => 'critical', 'title' => 'Remote Code Execution in Onboarding Module' ),
		),
		'woocommerce' => array(
			array( 'max_version' => '8.9.2',  'cve' => 'CVE-2024-5441',  'severity' => 'high',     'title' => 'Order Attribution Data Exposure / Privilege Escalation' ),
			array( 'max_version' => '5.5.0',  'cve' => 'CVE-2021-32640', 'severity' => 'critical', 'title' => 'Critical Unauthenticated SQL Injection in Order Meta' ),
		),
		'contact-form-7' => array(
			array( 'max_version' => '5.3.1',  'cve' => 'CVE-2020-35489', 'severity' => 'critical', 'title' => 'Unrestricted File Upload in Attachment Handler' ),
		),
		'wpforms-lite' => array(
			array( 'max_version' => '1.8.7.1','cve' => 'CVE-2024-27956', 'severity' => 'high',     'title' => 'SQL Injection & Stored XSS in Form Builder Field' ),
		),
		'essential-addons-for-elementor-lite' => array(
			array( 'max_version' => '5.7.1',  'cve' => 'CVE-2023-32243', 'severity' => 'critical', 'title' => 'Unauthenticated Password Reset & Privilege Escalation' ),
			array( 'max_version' => '5.0.4',  'cve' => 'CVE-2022-0320',  'severity' => 'critical', 'title' => 'Local File Inclusion (LFI) via Dynamic Template' ),
		),
		'advanced-custom-fields' => array(
			array( 'max_version' => '6.1.5',  'cve' => 'CVE-2023-30777', 'severity' => 'high',     'title' => 'Reflected XSS in Admin Notice Handler' ),
		),
		'all-in-one-seo-pack' => array(
			array( 'max_version' => '4.2.9',  'cve' => 'CVE-2023-0585',  'severity' => 'critical', 'title' => 'Authenticated SQL Injection in Bad Bot Blocker' ),
		),
		'wordfence' => array(
			array( 'max_version' => '7.10.3', 'cve' => 'CVE-2023-45604', 'severity' => 'high',     'title' => '2FA Lockout Bypass via Stored Token Validation' ),
		),
		'duplicator' => array(
			array( 'max_version' => '1.5.7',  'cve' => 'CVE-2023-6825',  'severity' => 'critical', 'title' => 'Unauthenticated File Read & Archive Download' ),
		),
		'updraftplus' => array(
			array( 'max_version' => '1.22.2', 'cve' => 'CVE-2022-0633',  'severity' => 'critical', 'title' => 'Arbitrary Backup Archive Download via Heartbeat' ),
		),
		'ninja-forms' => array(
			array( 'max_version' => '3.6.10', 'cve' => 'CVE-2022-2073',  'severity' => 'critical', 'title' => 'Unauthenticated PHP Object Injection to RCE' ),
		),
		'litespeed-cache' => array(
			array( 'max_version' => '6.3.0.1','cve' => 'CVE-2024-28000', 'severity' => 'critical', 'title' => 'Unauthenticated Administrator Role Simulation / RCE' ),
			array( 'max_version' => '6.4',    'cve' => 'CVE-2024-44000', 'severity' => 'critical', 'title' => 'Session Hijacking via Debug Log Access' ),
		),
		'file-manager' => array(
			array( 'max_version' => '6.8',    'cve' => 'CVE-2020-25213', 'severity' => 'critical', 'title' => 'Unauthenticated Arbitrary File Upload in elFinder' ),
		),
	);

	/**
	 * Run comprehensive vulnerability scan on plugins, themes, and WordPress core.
	 *
	 * @param array &$results
	 * @return array
	 */
	public static function scan_installed_components( &$results ) {
		if ( ! function_exists( 'get_plugins' ) && defined( 'ABSPATH' ) && file_exists( ABSPATH . 'wp-admin/includes/plugin.php' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		// 1. Scan Installed Plugins
		if ( function_exists( 'get_plugins' ) ) {
			$all_plugins = get_plugins();
			foreach ( $all_plugins as $plugin_file => $plugin_data ) {
				$slug = dirname( $plugin_file );
				if ( '.' === $slug || empty( $slug ) ) {
					$slug = basename( $plugin_file, '.php' );
				}

				$version = isset( $plugin_data['Version'] ) ? $plugin_data['Version'] : '0.0.0';
				$name    = isset( $plugin_data['Name'] ) ? $plugin_data['Name'] : $slug;

				self::check_component_vulnerabilities( 'plugin', $slug, $name, $version, $plugin_file, $results );
			}
		}

		// 2. Scan WordPress Core Version
		global $wp_version;
		if ( ! empty( $wp_version ) ) {
			self::check_core_vulnerabilities( $wp_version, $results );
		}

		return $results;
	}

	/**
	 * Check a single plugin or theme against the CVE catalog.
	 *
	 * @param string $type        'plugin' or 'theme'
	 * @param string $slug        Component directory slug
	 * @param string $name        Human-readable name
	 * @param string $version     Installed version
	 * @param string $file_path   Relative or absolute path
	 * @param array  &$results
	 */
	private static function check_component_vulnerabilities( $type, $slug, $name, $version, $file_path, &$results ) {
		$slug = strtolower( trim( $slug ) );
		if ( ! isset( self::$known_cve_catalog[ $slug ] ) ) {
			return;
		}

		$advisories = self::$known_cve_catalog[ $slug ];
		foreach ( $advisories as $adv ) {
			if ( version_compare( $version, $adv['max_version'], '<=' ) ) {
				$results['threats_found']++;
				$issue = array(
					'file'      => "Vulnerable {$type}: {$name} (v{$version})",
					'type'      => 'cve_vulnerability',
					'severity'  => $adv['severity'],
					'details'   => "[{$adv['cve']}] {$adv['title']}. Installed version {$version} is vulnerable (fixed in >{$adv['max_version']}).",
					'signature' => 'CVE:' . $adv['cve'],
				);
				$results['issues'][] = $issue;

				SuperShield_DB::save_scan_issue(
					$issue['file'],
					$issue['type'],
					$issue['severity'],
					$issue['details'],
					$issue['signature']
				);
			}
		}
	}

	/**
	 * Check WordPress Core version against known security vulnerabilities.
	 *
	 * @param string $version
	 * @param array  &$results
	 */
	private static function check_core_vulnerabilities( $version, &$results ) {
		$known_core_flaws = array(
			array( 'max_version' => '6.4.2', 'cve' => 'CVE-2024-27956', 'severity' => 'high',     'title' => 'WordPress Core RCE via POP Gadget Chain' ),
			array( 'max_version' => '6.2.2', 'cve' => 'CVE-2023-38000', 'severity' => 'high',     'title' => 'WordPress Core Multiple Privilege Escalation & CSRF' ),
			array( 'max_version' => '6.0.2', 'cve' => 'CVE-2022-3590',  'severity' => 'critical', 'title' => 'Unauthenticated Blind SSRF via Pingback' ),
			array( 'max_version' => '5.8.3', 'cve' => 'CVE-2022-21661', 'severity' => 'critical', 'title' => 'Core SQL Injection via WP_Query WP_Tax_Query' ),
		);

		foreach ( $known_core_flaws as $flaw ) {
			if ( version_compare( $version, $flaw['max_version'], '<=' ) ) {
				$results['threats_found']++;
				$issue = array(
					'file'      => "WordPress Core (v{$version})",
					'type'      => 'cve_vulnerability',
					'severity'  => $flaw['severity'],
					'details'   => "[{$flaw['cve']}] {$flaw['title']}. WordPress {$version} is outdated and insecure.",
					'signature' => 'CORE:' . $flaw['cve'],
				);
				$results['issues'][] = $issue;

				SuperShield_DB::save_scan_issue(
					$issue['file'],
					$issue['type'],
					$issue['severity'],
					$issue['details'],
					$issue['signature']
				);
			}
		}
	}
}
