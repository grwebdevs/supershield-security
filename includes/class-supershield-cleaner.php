<?php
/**
 * 1-Click Surgical Disinfection & Core Restoration Engine for SuperShield Security.
 *
 * @package    SuperShield_Security
 * @subpackage SuperShield_Security/includes
 * @author     Ghulam Rasool <grwebdevs.com>
 * @version    2.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SuperShield_Cleaner {

	/**
	 * Quarantine and backup directory path.
	 *
	 * @return string
	 */
	public static function get_quarantine_dir() {
		$upload_dir = wp_upload_dir();
		$dir = trailingslashit( $upload_dir['basedir'] ) . 'supershield-quarantine';
		if ( ! is_dir( $dir ) ) {
			wp_mkdir_p( $dir );
			self::secure_quarantine_dir( $dir );
		}
		return $dir;
	}

	/**
	 * Backup vault directory for pre-cleaning snapshots.
	 *
	 * @return string
	 */
	public static function get_backup_dir() {
		$quarantine = self::get_quarantine_dir();
		$backup_dir = trailingslashit( $quarantine ) . 'backups';
		if ( ! is_dir( $backup_dir ) ) {
			wp_mkdir_p( $backup_dir );
		}
		return $backup_dir;
	}

	/**
	 * Deploy dual Apache 2.2 / 2.4 immunity lockdown in quarantine directory.
	 *
	 * @param string $dir
	 */
	private static function secure_quarantine_dir( $dir ) {
		$htaccess_content = "# SuperShield Quarantine Vault Immunity\n" .
			"<IfModule !mod_authz_core.c>\n" .
			"    Order Deny,Allow\n" .
			"    Deny from all\n" .
			"</IfModule>\n" .
			"<IfModule mod_authz_core.c>\n" .
			"    Require all denied\n" .
			"</IfModule>\n";
		@file_put_contents( $dir . '/.htaccess', $htaccess_content );
		@file_put_contents( $dir . '/index.php', '<?php exit; ?>' );
	}

	/**
	 * Create a safe pre-cleaning backup of a file.
	 *
	 * @param string $file_path
	 * @return string|false Backup file path or false on failure.
	 */
	public static function backup_file( $file_path ) {
		if ( ! file_exists( $file_path ) || ! is_readable( $file_path ) ) {
			return false;
		}

		$backup_dir = self::get_backup_dir();
		$filename = basename( $file_path ) . '.' . time() . '.bak';
		$backup_path = trailingslashit( $backup_dir ) . $filename;

		if ( @copy( $file_path, $backup_path ) ) {
			@chmod( $backup_path, 0400 );
			return $backup_path;
		}

		return false;
	}

	/**
	 * Master Remediation Dispatcher: Cleans a scan issue by ID or path.
	 *
	 * @param int|string $issue_id Database issue ID or file path.
	 * @return array Result summary with status and message.
	 */
	public static function clean_issue( $issue_id ) {
		global $wpdb;
		$table = SuperShield_DB::get_scan_issues_table();

		if ( is_numeric( $issue_id ) ) {
			$issue = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM $table WHERE id = %d", (int) $issue_id ) );
		} else {
			$issue = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM $table WHERE file_path = %s ORDER BY id DESC LIMIT 1", (string) $issue_id ) );
		}

		if ( ! $issue ) {
			return array( 'success' => false, 'message' => 'Scan finding record not found.' );
		}

		$type = $issue->issue_type;
		$target = $issue->file_path;

		// 1. Rogue Admin Account Removal
		if ( 'rogue_admin' === $type || strpos( $target, 'wp_users' ) !== false ) {
			preg_match( '/ID\s*#?(\d+)/i', $target, $matches );
			$user_id = ! empty( $matches[1] ) ? (int) $matches[1] : 0;
			if ( $user_id > 0 ) {
				$removed = self::remove_rogue_admin( $user_id );
				if ( $removed ) {
					self::mark_issue_resolved( $issue->id, 'cleaned' );
					return array( 'success' => true, 'message' => 'Rogue administrator account deleted.' );
				}
			}
			return array( 'success' => false, 'message' => 'Failed to remove rogue administrator.' );
		}

		// 2. Database Option Payload Cleaning
		if ( 'encrypted_db_payload' === $type || strpos( $target, 'wp_options' ) !== false ) {
			preg_match( '/wp_options\s*\(([^)]+)\)/i', $target, $matches );
			$option_name = ! empty( $matches[1] ) ? trim( $matches[1] ) : '';
			if ( ! empty( $option_name ) ) {
				$cleaned = self::clean_db_payload( $option_name );
				if ( $cleaned ) {
					self::mark_issue_resolved( $issue->id, 'cleaned' );
					return array( 'success' => true, 'message' => "Malicious database payload '$option_name' erased." );
				}
			}
			return array( 'success' => false, 'message' => 'Failed to sanitize database option.' );
		}

		// 2b. Malicious Post Content Cleaning (wp_posts)
		if ( 'malicious_post_content' === $type || strpos( $target, 'wp_posts' ) !== false ) {
			preg_match( '/ID\s*#?(\d+)/i', $target, $matches );
			$post_id = ! empty( $matches[1] ) ? (int) $matches[1] : 0;
			if ( $post_id > 0 ) {
				$cleaned = self::clean_post_content( $post_id );
				if ( $cleaned ) {
					self::mark_issue_resolved( $issue->id, 'cleaned' );
					return array( 'success' => true, 'message' => 'Malicious iframe/script excised from post content.' );
				}
			}
			return array( 'success' => false, 'message' => 'Failed to sanitize post content.' );
		}

		// 3. WordPress Core Modified File Restoration
		if ( 'core_modified' === $type ) {
			$relative = self::get_core_relative_path( $target );
			if ( ! empty( $relative ) ) {
				$restored = self::restore_core_file( $relative );
				if ( $restored['success'] ) {
					self::mark_issue_resolved( $issue->id, 'cleaned' );
					return array( 'success' => true, 'message' => 'Core file restored from official WordPress release.' );
				}
				return $restored;
			}
		}

		// 4. Standalone droppers or uploads backdoors -> Safe Quarantine
		if ( in_array( $type, array( 'dot_dropper', 'hex_dropper', 'uploads_php', 'double_extension', 'fake_cache_persistence' ), true ) ) {
			$quarantined = self::quarantine_file( $target );
			if ( $quarantined ) {
				self::mark_issue_resolved( $issue->id, 'quarantined' );
				return array( 'success' => true, 'message' => 'Malicious file safely isolated in quarantine vault.' );
			}
			return array( 'success' => false, 'message' => 'Unable to quarantine file. Check permissions.' );
		}

		// 4b. Worm Staging Directories -> Safe Quarantine / Removal
		if ( 'worm_staging' === $type || ( is_dir( $target ) && ! is_file( $target ) ) ) {
			$quarantined = self::quarantine_directory( $target );
			if ( $quarantined ) {
				self::mark_issue_resolved( $issue->id, 'quarantined' );
				return array( 'success' => true, 'message' => 'Worm staging directory safely isolated in quarantine vault.' );
			}
			return array( 'success' => false, 'message' => 'Unable to quarantine staging directory. Check permissions.' );
		}

		// 5. Injected Code in Themes or Plugins -> Surgical Disinfection
		if ( file_exists( $target ) && is_file( $target ) ) {
			$stripped = self::surgical_strip( $target, $issue->signature_name );
			if ( $stripped['success'] ) {
				self::mark_issue_resolved( $issue->id, 'cleaned' );
				return array( 'success' => true, 'message' => 'Malicious code surgically excised; legitimate code preserved.' );
			}

			// Fallback to quarantine if surgical strip fails
			$quarantined = self::quarantine_file( $target );
			if ( $quarantined ) {
				self::mark_issue_resolved( $issue->id, 'quarantined' );
				return array( 'success' => true, 'message' => 'File quarantined after surgical strip could not guarantee syntax safety.' );
			}
		}

		return array( 'success' => false, 'message' => 'Could not determine disinfection method for target.' );
	}

	/**
	 * Mark issue as resolved in the database.
	 *
	 * @param int    $issue_id
	 * @param string $status
	 */
	public static function mark_issue_resolved( $issue_id, $status = 'cleaned' ) {
		global $wpdb;
		$table = SuperShield_DB::get_scan_issues_table();
		$wpdb->update(
			$table,
			array(
				'status'     => $status,
				'updated_at' => current_time( 'mysql' ),
			),
			array( 'id' => (int) $issue_id ),
			array( '%s', '%s' ),
			array( '%d' )
		);
	}

	/**
	 * Surgically excise injected malware blocks from a file without breaking legitimate code.
	 *
	 * @param string $file_path Absolute path.
	 * @param string $signature Known signature name.
	 * @return array
	 */
	public static function surgical_strip( $file_path, $signature = '' ) {
		if ( ! file_exists( $file_path ) || ! is_readable( $file_path ) || ! is_writable( $file_path ) ) {
			return array( 'success' => false, 'message' => 'File is not accessible or writable.' );
		}

		$original_code = file_get_contents( $file_path );
		if ( false === $original_code || empty( $original_code ) ) {
			return array( 'success' => false, 'message' => 'Failed to read file content.' );
		}

		// Pre-cleaning backup
		self::backup_file( $file_path );

		$cleaned_code = $original_code;

		// 1. Strip Delimited Exploit Blocks
		$delimited_patterns = array(
			'/\/\*(?:malware|backdoor|inject)[ _]?(?:start|begin)?\*\/[\s\S]*?\/\*(?:malware|backdoor|inject)[ _]?(?:end|finish)?\*\/\s*/i',
			'/\/\*(?:malware|backdoor)[ _]?(?:start|begin)?[\s\S]*?\*\/\s*@?(?:eval|assert)\s*(?P<paren>\((?:[^()]|(?&paren))*\))\s*(?:;|\?>)\s*/i',
			'/\/\*wp_vcd\*\/(?:[\s\S]*?)\/\*wp_vcd_end\*\/\s*/i',
			'/\<\?php\s*\/\*[\s\S]*?\*\/\s*@?(?:eval|assert)\s*(?P<paren>\((?:[^()]|(?&paren))*\))\s*(?:;|\s*)\?\>\s*/i',
			'/\<\?php\s*@?(?:eval|assert)\s*(?P<paren>\((?:[^()]|(?&paren))*\))\s*(?:;|\s*)\?\>\s*/i',
			'/\<\?php\s*if\s*\(\s*isset\s*\(\s*\$_(?:POST|GET|REQUEST|COOKIE)\[[^\]]+\]\s*\)\s*\)\s*\{\s*@?(?:eval|assert|system|passthru|shell_exec)\s*\(.*?\);\s*\}\s*\?>\s*/i',
		);

		foreach ( $delimited_patterns as $pattern ) {
			$cleaned_code = preg_replace( $pattern, '', $cleaned_code );
		}

		// 2. Strip Known Malicious Eval / Base64 lines with arbitrary balanced parenthesis nesting
		$cleaned_code = preg_replace_callback(
			'/^[ \t]*@?(?:eval|assert)\s*(?P<paren>\((?:[^()]|(?&paren))*\))\s*;[ \t]*(?:\r?\n)?/m',
			function( $matches ) {
				$inner = $matches[0];
				if ( preg_match( '/(base64_decode|gzinflate|gzuncompress|str_rot13|\$_(?:POST|GET|REQUEST|COOKIE)|GLOBALS)/i', $inner ) ) {
					return '';
				}
				return $matches[0];
			},
			$cleaned_code
		);

		$line_patterns = array(
			'/^[ \t]*\$GLOBALS\[[\'"][^\'"]+[\'"]\]\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\[.*?\);\s*[ \t]*(?:\r?\n)?/m',
			'/^[ \t]*@?include(?:_once)?\s*[\'"][^\'"]*\.(?:ico|png|jpg|tmp)[\'"]\s*;[ \t]*(?:\r?\n)?/m',
			'/^[ \t]*if\s*\(\s*isset\s*\(\s*\$_(?:POST|GET|REQUEST|COOKIE)\[[^\]]+\]\s*\)\s*\)\s*\{\s*@?(?:eval|assert|system)\s*\(.*?\);\s*\}[ \t]*(?:\r?\n)?/m',
		);

		foreach ( $line_patterns as $l_pat ) {
			$cleaned_code = preg_replace( $l_pat, '', $cleaned_code );
		}

		// Check if anything actually changed
		if ( $cleaned_code === $original_code ) {
			return array( 'success' => false, 'message' => 'No known extractable malware pattern found for automated strip.' );
		}

		// Validate PHP syntax of cleaned code
		if ( ! self::validate_php_syntax( $cleaned_code ) ) {
			return array( 'success' => false, 'message' => 'Syntax validation failed; original file preserved.' );
		}

		// Write modified content back
		$written = @file_put_contents( $file_path, $cleaned_code );
		if ( false === $written ) {
			return array( 'success' => false, 'message' => 'Failed to write cleaned code to disk.' );
		}

		SuperShield_DB::log_event(
			'admin_action',
			'Surgically cleaned infected file: ' . basename( $file_path ),
			'Signature: ' . $signature
		);

		return array( 'success' => true, 'message' => 'File surgically cleaned successfully.' );
	}

	/**
	 * Robust PHP syntax validator using token_get_all and AST error checking.
	 *
	 * @param string $code
	 * @return bool
	 */
	public static function validate_php_syntax( $code ) {
		if ( ! function_exists( 'token_get_all' ) ) {
			return true;
		}

		// PHP 7.0+ AST syntax validation via TOKEN_PARSE
		if ( defined( 'TOKEN_PARSE' ) ) {
			try {
				@token_get_all( $code, TOKEN_PARSE );
			} catch ( ParseError $e ) {
				return false;
			} catch ( Throwable $e ) {
				return false;
			}
		}

		try {
			$tokens = @token_get_all( $code );
			if ( empty( $tokens ) ) {
				return false;
			}

			// Verify balanced braces, parens, and square brackets with string interpolation awareness
			$braces = 0;
			$parens = 0;
			$brackets = 0;

			foreach ( $tokens as $token ) {
				if ( is_array( $token ) ) {
					// Handle string variable interpolation: "Hello {$name}" or "${name}"
					if ( defined( 'T_CURLY_OPEN' ) && T_CURLY_OPEN === $token[0] ) {
						$braces++;
					} elseif ( defined( 'T_DOLLAR_OPEN_CURLY_BRACES' ) && T_DOLLAR_OPEN_CURLY_BRACES === $token[0] ) {
						$braces++;
					}
					continue;
				}

				if ( is_string( $token ) ) {
					if ( '{' === $token ) {
						$braces++;
					} elseif ( '}' === $token ) {
						$braces--;
					} elseif ( '(' === $token ) {
						$parens++;
					} elseif ( ')' === $token ) {
						$parens--;
					} elseif ( '[' === $token ) {
						$brackets++;
					} elseif ( ']' === $token ) {
						$brackets--;
					}

					if ( $braces < 0 || $parens < 0 || $brackets < 0 ) {
						return false;
					}
				}
			}

			return ( 0 === $braces && 0 === $parens && 0 === $brackets );
		} catch ( Throwable $e ) {
			return false;
		}
	}

	/**
	 * Restore a modified WordPress Core file from official WordPress.org releases.
	 *
	 * @param string $relative_path Path relative to ABSPATH (e.g. 'wp-includes/version.php').
	 * @return array
	 */
	public static function restore_core_file( $relative_path ) {
		$relative_path = ltrim( str_replace( '\\', '/', $relative_path ), '/' );

		// Security: Never touch wp-config.php or wp-content files
		if ( 'wp-config.php' === $relative_path || 0 === strpos( $relative_path, 'wp-content/' ) ) {
			return array( 'success' => false, 'message' => 'Core restoration denied for protected or user-content paths.' );
		}

		global $wp_version;
		$version = ! empty( $wp_version ) ? $wp_version : '6.7';

		// Download official pristine file from official raw WordPress GitHub mirror or SVN tags
		$sources = array(
			"https://raw.githubusercontent.com/WordPress/WordPress/{$version}/{$relative_path}",
			"https://core.svn.wordpress.org/tags/{$version}/{$relative_path}",
		);

		$clean_content = false;
		foreach ( $sources as $source_url ) {
			$response = null;
			if ( function_exists( 'wp_remote_get' ) ) {
				$response = wp_remote_get( $source_url, array( 'timeout' => 15, 'sslverify' => true ) );
			}

			if ( is_array( $response ) && ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response ) ) {
				$clean_content = wp_remote_retrieve_body( $response );
			} elseif ( function_exists( 'file_get_contents' ) && ini_get( 'allow_url_fopen' ) ) {
				$clean_content = @file_get_contents( $source_url );
			}

			if ( false !== $clean_content && ! empty( $clean_content ) ) {
				break;
			}
		}

		if ( false === $clean_content || empty( $clean_content ) ) {
			return array( 'success' => false, 'message' => "Could not retrieve pristine core file from official repository ($relative_path)." );
		}

		$target_file = trailingslashit( ABSPATH ) . $relative_path;

		// Create backup of current version
		self::backup_file( $target_file );

		// Ensure parent directory exists
		$parent_dir = dirname( $target_file );
		if ( ! is_dir( $parent_dir ) ) {
			wp_mkdir_p( $parent_dir );
		}

		if ( false === @file_put_contents( $target_file, $clean_content ) ) {
			return array( 'success' => false, 'message' => 'Failed to write restored file. Check filesystem write permissions.' );
		}

		@chmod( $target_file, 0644 );

		SuperShield_DB::log_event(
			'admin_action',
			'WordPress core file restored from pristine upstream: ' . $relative_path,
			'WordPress Version: ' . $version
		);

		// Mark issue resolved in DB if present
		global $wpdb;
		if ( isset( $wpdb ) && is_object( $wpdb ) ) {
			$table = SuperShield_DB::get_scan_issues_table();
			$wpdb->update(
				$table,
				array( 'status' => 'cleaned', 'updated_at' => current_time( 'mysql' ) ),
				array( 'file_path' => $target_file ),
				array( '%s', '%s' ),
				array( '%s' )
			);
			$wpdb->update(
				$table,
				array( 'status' => 'cleaned', 'updated_at' => current_time( 'mysql' ) ),
				array( 'file_path' => $relative_path ),
				array( '%s', '%s' ),
				array( '%s' )
			);
		}

		return array( 'success' => true, 'message' => "Successfully restored $relative_path to official WordPress pristine release." );
	}

	/**
	 * Compute relative path for core file.
	 *
	 * @param string $full_path
	 * @return string|false
	 */
	public static function get_core_relative_path( $full_path ) {
		$norm_target = str_replace( '\\', '/', trim( (string) $full_path ) );
		$norm_root   = str_replace( '\\', '/', trailingslashit( ABSPATH ) );

		if ( 0 === strpos( $norm_target, $norm_root ) ) {
			$rel = substr( $norm_target, strlen( $norm_root ) );
			if ( 0 !== strpos( $rel, 'wp-content/' ) ) {
				return ltrim( $rel, '/' );
			}
			return false;
		}

		// Support if path is already relative (e.g. wp-includes/version.php)
		if ( strpos( $norm_target, '..' ) === false && strpos( $norm_target, ':' ) === false && 0 !== strpos( $norm_target, '/' ) ) {
			if ( 0 !== strpos( $norm_target, 'wp-content/' ) ) {
				return $norm_target;
			}
		}

		return false;
	}

	/**
	 * Safely isolate a malicious file to quarantine.
	 *
	 * @param string $file_path
	 * @return bool
	 */
	public static function quarantine_file( $file_path ) {
		if ( ! file_exists( $file_path ) || ! is_file( $file_path ) ) {
			return false;
		}

		// Critical core files must never be quarantined (prevent fatal site bricking)
		$critical_files = array( 'wp-config.php', 'index.php', 'wp-load.php', 'wp-settings.php', 'wp-blog-header.php', '.htaccess' );
		$basename = strtolower( basename( $file_path ) );
		if ( in_array( $basename, $critical_files, true ) ) {
			$norm_target = str_replace( '\\', '/', trim( (string) $file_path ) );
			$norm_root   = str_replace( '\\', '/', rtrim( ABSPATH, '/\\' ) );
			if ( dirname( $norm_target ) === $norm_root ) {
				return false;
			}
		}

		$quarantine_dir = self::get_quarantine_dir();
		$target_name = basename( $file_path ) . '.' . time() . '.quarantined';
		$target_path = trailingslashit( $quarantine_dir ) . $target_name;

		if ( @rename( $file_path, $target_path ) ) {
			@chmod( $target_path, 0400 );
			SuperShield_DB::log_event( 'admin_action', 'Quarantined file: ' . $file_path, $target_path );

			// Mark issue resolved in DB
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

			return true;
		}

		return false;
	}

	/**
	 * Safely isolate or remove a worm staging directory.
	 *
	 * @param string $dir_path
	 * @return bool
	 */
	public static function quarantine_directory( $dir_path ) {
		if ( ! is_dir( $dir_path ) ) {
			return false;
		}

		$quarantine_dir = self::get_quarantine_dir();
		$target_name = basename( $dir_path ) . '.' . time() . '.quarantined_dir';
		$target_path = trailingslashit( $quarantine_dir ) . $target_name;

		if ( @rename( $dir_path, $target_path ) ) {
			@chmod( $target_path, 0700 );
			SuperShield_DB::log_event( 'admin_action', 'Quarantined worm staging directory: ' . $dir_path, $target_path );
			return true;
		}

		// Fallback: recursively delete contents if rename fails across filesystems
		self::recursive_rmdir( $dir_path );
		return ! is_dir( $dir_path );
	}

	/**
	 * Recursively remove a directory and its contents.
	 *
	 * @param string $dir
	 */
	public static function recursive_rmdir( $dir ) {
		if ( ! is_dir( $dir ) ) {
			return;
		}
		$items = @scandir( $dir );
		if ( is_array( $items ) ) {
			foreach ( $items as $item ) {
				if ( '.' === $item || '..' === $item ) {
					continue;
				}
				$path = $dir . DIRECTORY_SEPARATOR . $item;
				if ( is_dir( $path ) ) {
					self::recursive_rmdir( $path );
				} else {
					@unlink( $path );
				}
			}
		}
		@rmdir( $dir );
	}

	/**
	 * Sanitize malicious script tags or iframes from post content.
	 *
	 * @param int $post_id
	 * @return bool
	 */
	public static function clean_post_content( $post_id ) {
		global $wpdb;
		$post_id = (int) $post_id;
		if ( $post_id <= 0 ) {
			return false;
		}

		$post = $wpdb->get_row( $wpdb->prepare( "SELECT post_content FROM {$wpdb->posts} WHERE ID = %d", $post_id ) );
		if ( ! $post ) {
			return false;
		}

		$content = $post->post_content;
		$cleaned = preg_replace( '/<iframe\b[^>]*(?:display:\s*none|visibility:\s*hidden|width=["\']0["\'])[^>]*>.*?<\/iframe>/is', '', $content );
		$cleaned = preg_replace( '/<script\b[^>]*(?:forecast-chaos|sound-obstacle|eval\(|base64_decode)[^>]*>.*?<\/script>/is', '', $cleaned );

		if ( $cleaned !== $content ) {
			$wpdb->update(
				$wpdb->posts,
				array( 'post_content' => $cleaned ),
				array( 'ID' => $post_id ),
				array( '%s' ),
				array( '%d' )
			);
			SuperShield_DB::log_event( 'admin_action', "Surgically sanitized malicious iframes/scripts from post ID #$post_id" );
			return true;
		}

		return false;
	}

	/**
	 * Eradicate malicious or oversized option payload in wp_options.
	 *
	 * @param string $option_name
	 * @return bool
	 */
	public static function clean_db_payload( $option_name ) {
		global $wpdb;
		if ( empty( $option_name ) ) {
			return false;
		}

		if ( function_exists( 'delete_option' ) ) {
			delete_option( $option_name );
		}

		$result = $wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$wpdb->options} WHERE option_name = %s",
				$option_name
			)
		);

		SuperShield_DB::log_event(
			'admin_action',
			'Deleted malicious database payload option: ' . sanitize_text_field( $option_name )
		);

		return ( false !== $result );
	}

	/**
	 * Eradicate rogue administrator account.
	 *
	 * @param int $user_id
	 * @return bool
	 */
	public static function remove_rogue_admin( $user_id ) {
		global $wpdb;
		$user_id = (int) $user_id;

		if ( $user_id <= 1 ) {
			return false; // Safeguard: Never delete primary site owner (User ID 1)
		}

		// Prevent deleting current user if called in session
		if ( function_exists( 'get_current_user_id' ) && get_current_user_id() === $user_id ) {
			return false;
		}

		if ( ! function_exists( 'wp_delete_user' ) && defined( 'ABSPATH' ) && file_exists( ABSPATH . 'wp-admin/includes/user.php' ) ) {
			require_once ABSPATH . 'wp-admin/includes/user.php';
		}

		if ( function_exists( 'wp_delete_user' ) ) {
			return (bool) wp_delete_user( $user_id );
		}

		$wpdb->delete( $wpdb->users, array( 'ID' => $user_id ), array( '%d' ) );
		$wpdb->delete( $wpdb->usermeta, array( 'user_id' => $user_id ), array( '%d' ) );

		SuperShield_DB::log_event(
			'admin_action',
			'Eradicated rogue administrator user account ID: #' . $user_id
		);

		return true;
	}
}
