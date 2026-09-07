<?php
/**
 * Malware & File Integrity Scanner for SuperShield Security.
 *
 * @package    SuperShield_Security
 * @subpackage SuperShield_Security/includes
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SuperShield_Scanner {

	/**
	 * Run a full multi-tier malware and integrity scan.
	 *
	 * @return array Scan results summary.
	 */
	public static function run_full_scan() {
		SuperShield_DB::reset_scan_run_ids();
		SuperShield_DB::purge_false_positives();

		$results = array(
			'scanned_files' => 0,
			'threats_found' => 0,
			'issues'        => array(),
			'start_time'    => microtime( true ),
		);

		// Tier 0: WordPress Core Integrity Diff via official WordPress.org checksums
		self::scan_core_checksums_diff( $results );

		// Tier 1: Scan for hidden dot droppers, 8-hex scripts, and worm staging artifacts
		self::scan_filesystem_artifacts( $results );

		// Tier 2: Scan uploads folder for any illegal PHP scripts
		self::scan_uploads_folder( $results );

		// Tier 3: Scan code signatures in mu-plugins, active theme, and plugins
		self::scan_php_code_signatures( $results );

		// Tier 4: Scan database for rogue administrators and bloated encrypted options
		self::scan_database_threats( $results );

		// Synchronize database issues: mark issues not found in this scan as resolved/cleaned
		global $wpdb;
		$table = SuperShield_DB::get_scan_issues_table();
		$saved_ids = SuperShield_DB::get_current_run_saved_ids();
		if ( ! empty( $saved_ids ) ) {
			$ids_placeholder = implode( ',', array_map( 'intval', $saved_ids ) );
			$wpdb->query( "UPDATE $table SET status = 'cleaned', updated_at = '" . current_time( 'mysql' ) . "' WHERE status = 'active' AND id NOT IN ($ids_placeholder)" );
		} else {
			$wpdb->query( "UPDATE $table SET status = 'cleaned', updated_at = '" . current_time( 'mysql' ) . "' WHERE status = 'active'" );
		}

		// Record scan completion in settings
		$results['end_time'] = microtime( true );
		$results['duration'] = round( $results['end_time'] - $results['start_time'], 2 );

		SuperShield_Utils::update_option( 'last_scan_time', current_time( 'mysql' ) );
		SuperShield_Utils::update_option( 'last_scan_results', array(
			'scanned_files' => $results['scanned_files'],
			'threats_found' => $results['threats_found'],
			'duration'      => $results['duration'],
		) );

		return $results;
	}

	/**
	 * Tier 0: WordPress Core Integrity Diff via official WordPress.org checksums API.
	 *
	 * @param array &$results
	 */
	public static function scan_core_checksums_diff( &$results ) {
		global $wp_version, $wp_local_package;
		$version = ! empty( $wp_version ) ? $wp_version : '6.7';
		$locale  = ! empty( $wp_local_package ) ? $wp_local_package : 'en_US';

		$checksums = self::get_core_checksums( $version, $locale );
		if ( empty( $checksums ) || ! is_array( $checksums ) ) {
			return;
		}

		$root = trailingslashit( ABSPATH );

		foreach ( $checksums as $file => $expected_md5 ) {
			// Skip wp-content files from core checksum checks
			if ( 0 === strpos( $file, 'wp-content/' ) ) {
				continue;
			}

			$local_path = $root . $file;
			if ( ! file_exists( $local_path ) ) {
				// Missing core file
				$results['threats_found']++;
				$issue = array(
					'file'      => $local_path,
					'type'      => 'core_modified',
					'severity'  => 'high',
					'details'   => "Missing WordPress core file: $file",
					'signature' => 'CORE:MissingFile',
				);
				$results['issues'][] = $issue;
				SuperShield_DB::save_scan_issue( $local_path, $issue['type'], $issue['severity'], $issue['details'], $issue['signature'] );
				continue;
			}

			$results['scanned_files']++;
			$local_md5 = md5_file( $local_path );
			if ( $local_md5 !== $expected_md5 ) {
				$results['threats_found']++;
				$issue = array(
					'file'      => $local_path,
					'type'      => 'core_modified',
					'severity'  => 'critical',
					'details'   => "WordPress core file modified or injected ($file)",
					'signature' => 'CORE:ChecksumMismatch',
				);
				$results['issues'][] = $issue;
				SuperShield_DB::save_scan_issue( $local_path, $issue['type'], $issue['severity'], $issue['details'], $issue['signature'] );
			}
		}
	}

	/**
	 * Retrieve official WordPress Core checksums.
	 *
	 * @param string $version
	 * @param string $locale
	 * @return array
	 */
	public static function get_core_checksums( $version, $locale = 'en_US' ) {
		$cache_key = 'supershield_checksums_' . md5( $version . $locale );
		$cached = get_transient( $cache_key );
		if ( false !== $cached && is_array( $cached ) ) {
			return $cached;
		}

		$url = "https://api.wordpress.org/core/checksums/1.0/?version={$version}&locale={$locale}";
		$checksums = array();

		if ( function_exists( 'wp_remote_get' ) ) {
			$resp = wp_remote_get( $url, array( 'timeout' => 8 ) );
			if ( ! is_wp_error( $resp ) && 200 === wp_remote_retrieve_response_code( $resp ) ) {
				$body = wp_remote_retrieve_body( $resp );
				$data = json_decode( $body, true );
				if ( ! empty( $data['checksums'] ) && is_array( $data['checksums'] ) ) {
					$checksums = $data['checksums'];
					set_transient( $cache_key, $checksums, 7 * DAY_IN_SECONDS );
				}
			}
		}

		return $checksums;
	}

	/**
	 * Compute Shannon Entropy across a string.
	 * Measures mathematical randomness (entropy > 5.8 in PHP files indicates high probability of packed/encrypted payload).
	 *
	 * @param string $data
	 * @return float
	 */
	public static function calculate_shannon_entropy( $data ) {
		$len = strlen( $data );
		if ( 0 === $len ) {
			return 0.0;
		}

		$freq = count_chars( $data, 1 );
		$entropy = 0.0;

		foreach ( $freq as $count ) {
			$p = $count / $len;
			$entropy -= $p * log( $p, 2 );
		}

		return round( $entropy, 2 );
	}

	/**
	 * Scan filesystem for hidden droppers, 8-hex droppers, and worm artifacts.
	 *
	 * @param array &$results
	 */
	private static function scan_filesystem_artifacts( &$results ) {
		$scan_dirs = array(
			ABSPATH,
			WP_CONTENT_DIR,
		);

		if ( defined( 'WPMU_PLUGIN_DIR' ) && is_dir( WPMU_PLUGIN_DIR ) ) {
			$scan_dirs[] = WPMU_PLUGIN_DIR;
		}

		if ( defined( 'WP_PLUGIN_DIR' ) && is_dir( WP_PLUGIN_DIR ) ) {
			$scan_dirs[] = WP_PLUGIN_DIR;
		}

		foreach ( $scan_dirs as $dir ) {
			if ( ! is_dir( $dir ) ) {
				continue;
			}

			$items = @scandir( $dir );
			if ( ! is_array( $items ) ) {
				continue;
			}

			foreach ( $items as $item ) {
				if ( '.' === $item || '..' === $item ) {
					continue;
				}

				$full_path = rtrim( $dir, '/\\' ) . DIRECTORY_SEPARATOR . $item;

				// 1. Hidden Dot Dropper Check (.6345dc54.php, .*.php)
				if ( preg_match( '/^\..*\.php$/i', $item ) ) {
					$results['threats_found']++;
					$issue = array(
						'file'      => $full_path,
						'type'      => 'dot_dropper',
						'severity'  => 'critical',
						'details'   => 'Hidden dot-dropper PHP script detected (stealth malware mechanism)',
						'signature' => 'HEUR:StealthDotDropper',
					);
					$results['issues'][] = $issue;
					SuperShield_DB::save_scan_issue( $full_path, $issue['type'], $issue['severity'], $issue['details'], $issue['signature'] );
				}

				// 2. Standalone 8-Hex Dropper Check ([0-9a-f]{8}.php)
				if ( preg_match( '/^[0-9a-f]{8}\.php$/i', $item ) || preg_match( '/^_[0-9a-f]{6,16}\.php$/i', $item ) ) {
					$results['threats_found']++;
					$issue = array(
						'file'      => $full_path,
						'type'      => 'hex_dropper',
						'severity'  => 'critical',
						'details'   => 'Randomized hexadecimal dropper script detected',
						'signature' => 'HEUR:HexDropper.Pattern',
					);
					$results['issues'][] = $issue;
					SuperShield_DB::save_scan_issue( $full_path, $issue['type'], $issue['severity'], $issue['details'], $issue['signature'] );
				}

				// 3. Worm Staging Directory Check (.sc_*, sc_*, core_*, trace-sentinel)
				if ( is_dir( $full_path ) ) {
					if ( preg_match( '/^(\.sc_.*|sc_.*|core_.*|.*trace[-_]sentinel.*)$/i', $item ) ) {
						$results['threats_found']++;
						$issue = array(
							'file'      => $full_path,
							'type'      => 'worm_staging',
							'severity'  => 'critical',
							'details'   => 'Self-replicating worm staging directory or payload folder detected',
							'signature' => 'WORM:CrossAccountStaging',
						);
						$results['issues'][] = $issue;
						SuperShield_DB::save_scan_issue( $full_path, $issue['type'], $issue['severity'], $issue['details'], $issue['signature'] );
					}
				}

				// 4. Fake Object Cache / Persistence files (.wp-object-cache-*.dat, *.dat.lkg)
				if ( is_file( $full_path ) && preg_match( '/(\.wp-object-cache-.*\.dat|\.dat\.lkg|\.lkg)$/i', $item ) ) {
					$results['threats_found']++;
					$issue = array(
						'file'      => $full_path,
						'type'      => 'fake_cache_persistence',
						'severity'  => 'high',
						'details'   => 'Malicious fake cache persistence store detected',
						'signature' => 'PERSIST:FakeObjectCache',
					);
					$results['issues'][] = $issue;
					SuperShield_DB::save_scan_issue( $full_path, $issue['type'], $issue['severity'], $issue['details'], $issue['signature'] );
				}
			}
		}
	}

	/**
	 * Scan uploads directory for illegal PHP executable scripts.
	 *
	 * @param array &$results
	 */
	private static function scan_uploads_folder( &$results ) {
		$upload_dir = wp_upload_dir();
		$base_dir = $upload_dir['basedir'];

		if ( ! is_dir( $base_dir ) ) {
			return;
		}

		$iterator = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator( $base_dir, RecursiveDirectoryIterator::SKIP_DOTS ),
			RecursiveIteratorIterator::SELF_FIRST
		);

		foreach ( $iterator as $file ) {
			if ( $file->isFile() ) {
				$results['scanned_files']++;
				$filename = $file->getFilename();
				$ext = strtolower( pathinfo( $filename, PATHINFO_EXTENSION ) );

				// Check for illegal PHP or executable extensions
				if ( in_array( $ext, array( 'php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phps', 'phar', 'suspected' ), true ) ) {
					$results['threats_found']++;
					$issue = array(
						'file'      => $file->getPathname(),
						'type'      => 'uploads_php',
						'severity'  => 'critical',
						'details'   => 'Executable PHP script discovered inside media uploads directory',
						'signature' => 'MALWARE:UploadsBackdoor.PHP',
					);
					$results['issues'][] = $issue;
					SuperShield_DB::save_scan_issue( $file->getPathname(), $issue['type'], $issue['severity'], $issue['details'], $issue['signature'] );
				} elseif ( preg_match( '/\.(php|phtml)\.(jpg|jpeg|png|gif)$/i', $filename ) ) {
					// Double extension exploit (e.g. shell.php.jpg)
					$results['threats_found']++;
					$issue = array(
						'file'      => $file->getPathname(),
						'type'      => 'double_extension',
						'severity'  => 'critical',
						'details'   => 'Double extension executable file discovered in media uploads directory',
						'signature' => 'MALWARE:DoubleExtensionUpload',
					);
					$results['issues'][] = $issue;
					SuperShield_DB::save_scan_issue( $file->getPathname(), $issue['type'], $issue['severity'], $issue['details'], $issue['signature'] );
				} elseif ( preg_match( '/^\..*\.php$/i', $filename ) ) {
					// Hidden dot dropper nested in uploads subdirectories
					$results['threats_found']++;
					$issue = array(
						'file'      => $file->getPathname(),
						'type'      => 'dot_dropper',
						'severity'  => 'critical',
						'details'   => 'Hidden dot-dropper discovered in media uploads subdirectory',
						'signature' => 'HEUR:StealthDotDropper',
					);
					$results['issues'][] = $issue;
					SuperShield_DB::save_scan_issue( $file->getPathname(), $issue['type'], $issue['severity'], $issue['details'], $issue['signature'] );
				}
			}
		}
	}

	/**
	 * Inspect single file content against threat signatures.
	 *
	 * @param string $path
	 * @param array  $signatures
	 * @param array  &$results
	 */
	public static function scan_single_file_content( $path, $signatures, &$results ) {
		if ( ! is_file( $path ) || ! is_readable( $path ) ) {
			return;
		}

		$results['scanned_files']++;

		// Skip files larger than 4MB
		if ( filesize( $path ) > 4194304 ) {
			return;
		}

		$content = @file_get_contents( $path );
		if ( false === $content ) {
			return;
		}

		foreach ( $signatures as $sig_name => $sig_info ) {
			if ( preg_match( $sig_info['pattern'], $content ) ) {
				$results['threats_found']++;
				$issue = array(
					'file'      => $path,
					'type'      => 'malware_signature',
					'severity'  => $sig_info['severity'],
					'details'   => $sig_info['desc'],
					'signature' => $sig_name,
				);
				$results['issues'][] = $issue;
				SuperShield_DB::save_scan_issue( $path, $issue['type'], $issue['severity'], $issue['details'], $sig_name );
			}
		}

		// Heuristic Shannon Entropy analysis on executable PHP scripts
		if ( filesize( $path ) > 300 && 'php' === strtolower( pathinfo( $path, PATHINFO_EXTENSION ) ) ) {
			$entropy = self::calculate_shannon_entropy( $content );
			if ( $entropy >= 5.92 && ( strpos( $content, 'base64_decode' ) !== false || strpos( $content, 'eval' ) !== false || strpos( $content, 'gzinflate' ) !== false ) ) {
				$results['threats_found']++;
				$issue = array(
					'file'      => $path,
					'type'      => 'obfuscated_entropy',
					'severity'  => 'critical',
					'details'   => "High mathematical randomness detected (Shannon Entropy: {$entropy}) indicating packed/encrypted payload",
					'signature' => 'HEUR:HighEntropyPacker',
				);
				$results['issues'][] = $issue;
				SuperShield_DB::save_scan_issue( $path, $issue['type'], $issue['severity'], $issue['details'], $issue['signature'] );
			}
		}
	}

	/**
	 * Scan PHP files for malicious code signatures.
	 *
	 * @param array &$results
	 */
	private static function scan_php_code_signatures( &$results ) {
		$target_dirs = array();

		if ( defined( 'WPMU_PLUGIN_DIR' ) && is_dir( WPMU_PLUGIN_DIR ) ) {
			$target_dirs[] = WPMU_PLUGIN_DIR;
		}
		if ( defined( 'WP_PLUGIN_DIR' ) && is_dir( WP_PLUGIN_DIR ) ) {
			$target_dirs[] = WP_PLUGIN_DIR;
		}
		if ( function_exists( 'get_stylesheet_directory' ) && is_dir( get_stylesheet_directory() ) ) {
			$target_dirs[] = get_stylesheet_directory();
		}
		if ( function_exists( 'get_template_directory' ) && is_dir( get_template_directory() ) ) {
			$target_dirs[] = get_template_directory();
		}

		// Malware Signatures
		$signatures = array(
			'EVAL_BASE64'     => array(
				'pattern'  => '/(eval\s*\(\s*base64_decode\s*\(|gzinflate\s*\(\s*base64_decode\s*\(|gzuncompress\s*\(\s*base64_decode\s*\(|str_rot13\s*\(\s*base64_decode\s*\()/i',
				'severity' => 'critical',
				'desc'     => 'Obfuscated code execution payload detected',
			),
			'VARIABLE_EXEC'   => array(
				'pattern'  => '/(\$GLOBALS\[[\'"][a-zA-Z0-9_]+[\'"]\]\s*\(\s*(\$_(POST|GET|REQUEST|COOKIE)|base64_decode))/i',
				'severity' => 'critical',
				'desc'     => 'Dynamic variable execution backdoor detected',
			),
			'KNOWN_WEBSHELL'  => array(
				'pattern'  => '/(\b(FilesMan|c99shell|r57shell|b374k|WSO_VERSION|ALFA_DATA|Alfa-Team)\b)/i',
				'severity' => 'critical',
				'desc'     => 'Known web shell signature detected',
			),
			'SCD1_INJECTION'  => array(
				'pattern'  => '/(SCD1:4\.[0-9]+\.[0-9]+)/',
				'severity' => 'critical',
				'desc'     => 'SCD1 worm payload token signature detected',
			),
			'MALICIOUS_C2'    => array(
				'pattern'  => '/(forecast-chaos\.com|sound-obstacle\.com|traffic-media-network|tds-click)/i',
				'severity' => 'critical',
				'desc'     => 'Known Command & Control (C2) / TDS redirect domain injected',
			),
		);

		// 1. Scan root ABSPATH PHP files (e.g. index.php, wp-load.php, wp-config.php)
		if ( defined( 'ABSPATH' ) && is_dir( ABSPATH ) ) {
			$root_files = @glob( rtrim( ABSPATH, '/\\' ) . '/*.php' );
			if ( is_array( $root_files ) ) {
				foreach ( $root_files as $r_file ) {
					self::scan_single_file_content( $r_file, $signatures, $results );
				}
			}
		}

		// 2. Scan Target Plugin & Theme Directories
		foreach ( $target_dirs as $dir ) {
			if ( ! is_dir( $dir ) ) {
				continue;
			}

			$iterator = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $dir, RecursiveDirectoryIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::SELF_FIRST
			);

			foreach ( $iterator as $file ) {
				if ( $file->isFile() && 'php' === strtolower( pathinfo( $file->getFilename(), PATHINFO_EXTENSION ) ) ) {
					$file_path = wp_normalize_path( $file->getPathname() );
					// Skip SuperShield plugin directory to prevent self-detection of signature definitions & test fixtures
					if ( defined( 'SUPERSHIELD_PLUGIN_DIR' ) && 0 === strpos( $file_path, wp_normalize_path( SUPERSHIELD_PLUGIN_DIR ) ) ) {
						continue;
					}
					self::scan_single_file_content( $file_path, $signatures, $results );
				}
			}
		}
	}

	/**
	 * Inspect database for rogue admin accounts and bloated encrypted options.
	 *
	 * @param array &$results
	 */
	public static function scan_database_threats( &$results ) {
		global $wpdb;
		if ( ! isset( $wpdb ) || ! is_object( $wpdb ) ) {
			return;
		}

		// 1. Rogue Administrator Accounts check (must have administrator capability)
		$caps_key = $wpdb->prefix . 'capabilities';
		$users = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT u.ID, u.user_login, u.user_email, u.user_registered 
				 FROM {$wpdb->users} u
				 INNER JOIN {$wpdb->usermeta} m ON u.ID = m.user_id
				 WHERE m.meta_key = %s
				   AND m.meta_value LIKE %s
				   AND u.ID > 1
				   AND (
				       u.user_login LIKE 'adm\\_%' ESCAPE '\\\\'
				       OR u.user_login LIKE 'administrator\\_%' ESCAPE '\\\\'
				       OR u.user_login LIKE 'wp\\_%' ESCAPE '\\\\'
				       OR u.user_login REGEXP '^[a-f0-9]{8,16}$'
				   )",
				$caps_key,
				'%administrator%'
			)
		);

		if ( ! empty( $users ) ) {
			foreach ( $users as $u ) {
				// Safeguard: never flag standard root/admin accounts as rogue
				if ( in_array( strtolower( $u->user_login ), array( 'admin', 'administrator', 'root' ), true ) ) {
					continue;
				}
				$results['threats_found']++;
				$issue = array(
					'file'      => 'Database: wp_users (ID #' . $u->ID . ')',
					'type'      => 'rogue_admin',
					'severity'  => 'critical',
					'details'   => 'Suspicious administrator account detected: ' . esc_html( $u->user_login ),
					'signature' => 'ROGUE:AdminUser',
				);
				$results['issues'][] = $issue;
				$issue_id = SuperShield_DB::save_scan_issue( $issue['file'], $issue['type'], $issue['severity'], $issue['details'], $issue['signature'] );
				if ( $issue_id && isset( $results['saved_issue_ids'] ) ) {
					$results['saved_issue_ids'][] = $issue_id;
				}
			}
		}

		// 2. Known Malware Options & Bloated Encrypted Options in wp_options
		$bloated = $wpdb->get_results(
			"SELECT option_id, option_name, LENGTH(option_value) AS opt_len FROM {$wpdb->options}
			 WHERE option_name IN ('wp_vcd', 'wp-vcd', 'SC_DB', 'sc_db', 'SCD1', 'wp_check_hash', 'site_protection_token')
			    OR (LENGTH(option_value) > 30000 AND (option_value LIKE '%eval(%' OR option_value LIKE '%base64_decode%' OR option_value LIKE '%SCD1:%'))
			    OR (LENGTH(option_value) > 100000 AND option_name REGEXP '^[0-9a-f]{12,20}$')"
		);

		if ( ! empty( $bloated ) ) {
			foreach ( $bloated as $opt ) {
				$results['threats_found']++;
				$issue = array(
					'file'      => 'Database: wp_options (' . $opt->option_name . ')',
					'type'      => 'encrypted_db_payload',
					'severity'  => 'critical',
					'details'   => 'Malicious payload or bloated encrypted store in wp_options (' . round( $opt->opt_len / 1024, 1 ) . ' KB)',
					'signature' => 'PAYLOAD:MalwareDbStore',
				);
				$results['issues'][] = $issue;
				SuperShield_DB::save_scan_issue( $issue['file'], $issue['type'], $issue['severity'], $issue['details'], $issue['signature'] );
			}
		}

		// 3. Scan wp_posts for malicious iframes and hidden injected script tags
		if ( isset( $wpdb->posts ) ) {
			$malicious_posts = $wpdb->get_results(
				"SELECT ID, post_title FROM {$wpdb->posts}
				 WHERE (post_content LIKE '%<iframe%display:none%' OR post_content LIKE '%<iframe%visibility:hidden%' OR post_content LIKE '%<iframe%width=\"0\"%')
				    OR (post_content LIKE '%<script%forecast-chaos%' OR post_content LIKE '%<script%sound-obstacle%' OR post_content LIKE '%<script%eval(%' OR post_content LIKE '%<script%base64_decode%')
				 LIMIT 20"
			);

			if ( ! empty( $malicious_posts ) ) {
				foreach ( $malicious_posts as $p ) {
					$results['threats_found']++;
					$issue = array(
						'file'      => 'Database: wp_posts (ID #' . $p->ID . ')',
						'type'      => 'malicious_post_content',
						'severity'  => 'critical',
						'details'   => 'Malicious hidden iframe or injected script detected in post: ' . esc_html( $p->post_title ),
						'signature' => 'PAYLOAD:PostContentInjection',
					);
					$results['issues'][] = $issue;
					SuperShield_DB::save_scan_issue( $issue['file'], $issue['type'], $issue['severity'], $issue['details'], $issue['signature'] );
				}
			}
		}
	}

	/**
	 * Safely isolate / quarantine a detected file.
	 *
	 * @param string $file_path Absolute path to malicious file.
	 * @return bool
	 */
	public static function quarantine_file( $file_path ) {
		if ( ! file_exists( $file_path ) || ! is_file( $file_path ) ) {
			return false;
		}

		$upload_dir = wp_upload_dir();
		$quarantine_dir = trailingslashit( $upload_dir['basedir'] ) . 'supershield-quarantine';

		if ( ! is_dir( $quarantine_dir ) ) {
			wp_mkdir_p( $quarantine_dir );
			// Lock down directory with dual Apache 2.2/2.4 compatible .htaccess
			$quarantine_htaccess = "# SuperShield Quarantine Vault\n" .
				"<IfModule !mod_authz_core.c>\n" .
				"    Order Deny,Allow\n" .
				"    Deny from all\n" .
				"</IfModule>\n" .
				"<IfModule mod_authz_core.c>\n" .
				"    Require all denied\n" .
				"</IfModule>\n";
			file_put_contents( $quarantine_dir . '/.htaccess', $quarantine_htaccess );
			file_put_contents( $quarantine_dir . '/index.php', '<?php exit; ?>' );
		}

		$target_name = basename( $file_path ) . '.' . time() . '.quarantined';
		$target_path = $quarantine_dir . '/' . $target_name;

		if ( @rename( $file_path, $target_path ) ) {
			@chmod( $target_path, 0400 ); // Read-only

			// Update scan issue status in DB
			global $wpdb;
			if ( isset( $wpdb ) && is_object( $wpdb ) ) {
				$table = SuperShield_DB::get_scan_issues_table();
				$wpdb->update(
					$table,
					array( 'status' => 'quarantined', 'updated_at' => current_time( 'mysql' ) ),
					array( 'file_path' => $file_path ),
					array( '%s', '%s' ),
					array( '%s' )
				);
			}

			SuperShield_DB::log_event( 'admin_action', 'Quarantined malicious file: ' . $file_path, $target_path );
			return true;
		}

		return false;
	}
}
