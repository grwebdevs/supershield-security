<?php
/**
 * GitHub Releases API Auto-Updater & Distribution Engine for SuperShield Security.
 *
 * @package    SuperShield_Security
 * @subpackage SuperShield_Security/includes
 * @author     Ghulam Rasool <grwebdevs.com>
 * @version    2.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SuperShield_Updater {

	/**
	 * Official GitHub Repository endpoint.
	 */
	const GITHUB_REPO = 'grwebdevs/supershield-security';
	const GITHUB_API_URL = 'https://api.github.com/repos/grwebdevs/supershield-security/releases/latest';
	const CLOUD_PROXY_URL = 'https://SSS.grwebdevs.com/api/v1/updates';

	/**
	 * Initialize updater hooks.
	 */
	public static function init() {
		// Hook WordPress update transient
		add_filter( 'pre_set_site_transient_update_plugins', array( __CLASS__, 'filter_update_transient' ) );

		// Hook WordPress plugin information popup modal
		add_filter( 'plugins_api', array( __CLASS__, 'filter_plugin_information' ), 20, 3 );

		// Pre/post installation hooks for safe backups & rollbacks
		add_filter( 'upgrader_pre_install', array( __CLASS__, 'pre_install_snapshot' ), 10, 2 );
		add_filter( 'upgrader_post_install', array( __CLASS__, 'post_install_verify' ), 10, 3 );
	}

	/**
	 * Fetch latest release metadata from GitHub or cloud proxy with transient caching.
	 *
	 * @param bool $force_check
	 * @return array|false
	 */
	public static function get_latest_release( $force_check = false ) {
		$cache_key = 'supershield_latest_release_cache';

		if ( ! $force_check ) {
			$cached = get_transient( $cache_key );
			if ( false !== $cached && is_array( $cached ) ) {
				return $cached;
			}
		}

		$headers = array(
			'Accept'     => 'application/vnd.github.v3+json',
			'User-Agent' => 'SuperShield-Security-Updater/' . SUPERSHIELD_VERSION . ' (WordPress/' . get_bloginfo( 'version' ) . ')',
		);

		$response = null;
		if ( function_exists( 'wp_remote_get' ) ) {
			$response = wp_remote_get( self::GITHUB_API_URL, array( 'headers' => $headers, 'timeout' => 10 ) );
		}

		$body = null;
		if ( is_array( $response ) && ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response ) ) {
			$body = wp_remote_retrieve_body( $response );
		}

		// Fallback to Cloud Proxy if direct GitHub API is rate-limited
		if ( empty( $body ) ) {
			if ( function_exists( 'wp_remote_get' ) ) {
				$proxy_resp = wp_remote_get( self::CLOUD_PROXY_URL, array( 'headers' => $headers, 'timeout' => 10 ) );
				if ( is_array( $proxy_resp ) && ! is_wp_error( $proxy_resp ) && 200 === wp_remote_retrieve_response_code( $proxy_resp ) ) {
					$body = wp_remote_retrieve_body( $proxy_resp );
				}
			}
		}

		if ( empty( $body ) ) {
			return false;
		}

		$data = json_decode( $body, true );
		if ( ! is_array( $data ) || ! isset( $data['tag_name'] ) ) {
			return false;
		}

		$version = ltrim( $data['tag_name'], 'v' );
		$download_url = isset( $data['zipball_url'] ) ? $data['zipball_url'] : '';

		// Check for release asset zip file first
		if ( ! empty( $data['assets'] ) && is_array( $data['assets'] ) ) {
			foreach ( $data['assets'] as $asset ) {
				if ( isset( $asset['name'] ) && preg_match( '/\.zip$/i', $asset['name'] ) ) {
					$download_url = $asset['browser_download_url'];
					break;
				}
			}
		}

		$release_info = array(
			'version'       => $version,
			'tag_name'      => $data['tag_name'],
			'download_url'  => $download_url,
			'html_url'      => isset( $data['html_url'] ) ? $data['html_url'] : '',
			'body'          => isset( $data['body'] ) ? $data['body'] : '',
			'published_at'  => isset( $data['published_at'] ) ? $data['published_at'] : '',
		);

		// Cache for 6 hours
		set_transient( $cache_key, $release_info, 6 * HOUR_IN_SECONDS );

		return $release_info;
	}

	/**
	 * Inject update payload into WordPress plugin update transient if newer release is available.
	 *
	 * @param object $transient
	 * @return object
	 */
	public static function filter_update_transient( $transient ) {
		if ( ! is_object( $transient ) ) {
			$transient = new stdClass();
		}

		$release = self::get_latest_release();
		if ( ! $release || empty( $release['version'] ) ) {
			return $transient;
		}

		// Semver comparison
		if ( version_compare( $release['version'], SUPERSHIELD_VERSION, '>' ) ) {
			$plugin_file = defined( 'SUPERSHIELD_BASENAME' ) ? SUPERSHIELD_BASENAME : 'supershield-security/supershield-security.php';

			$update_item = (object) array(
				'id'            => 'supershield-security',
				'slug'          => 'supershield-security',
				'plugin'        => $plugin_file,
				'new_version'   => $release['version'],
				'url'           => 'https://SSS.grwebdevs.com',
				'package'       => $release['download_url'],
				'tested'        => '6.7',
				'requires_php'  => '7.4',
				'compatibility' => new stdClass(),
			);

			$transient->response[ $plugin_file ] = $update_item;
		}

		return $transient;
	}

	/**
	 * Render custom plugin details modal for plugins_api query.
	 *
	 * @param false|object|array $result
	 * @param string             $action
	 * @param object             $args
	 * @return object
	 */
	public static function filter_plugin_information( $result, $action, $args ) {
		if ( 'plugin_information' !== $action || ! isset( $args->slug ) || 'supershield-security' !== $args->slug ) {
			return $result;
		}

		$release = self::get_latest_release();
		$version = $release ? $release['version'] : SUPERSHIELD_VERSION;
		$changelog = $release ? esc_html( $release['body'] ) : 'Security enhancements and bug fixes.';

		$info = new stdClass();
		$info->name           = 'SuperShield Security — Enterprise WordPress Defense-in-Depth Suite';
		$info->slug           = 'supershield-security';
		$info->version        = $version;
		$info->author         = '<a href="https://grwebdevs.com" target="_blank">Ghulam Rasool</a> (Founder & Principal Security Engineer)';
		$info->author_profile = 'https://grwebdevs.com';
		$info->homepage       = 'https://SSS.grwebdevs.com';
		$info->requires       = '5.8';
		$info->tested         = '6.7';
		$info->requires_php   = '7.4';
		$info->download_link  = $release ? $release['download_url'] : '';
		$info->last_updated   = $release ? $release['published_at'] : current_time( 'mysql' );

		$info->sections = array(
			'description'  => '<p><strong>SuperShield Security (SSS)</strong> combines the Real-Time WAF of Wordfence, the Deep Heuristic Scanner & 1-Click Disinfection of MalCare, and the 8-Layer Server Hardening of AIOS into a unified, zero-overhead defense suite.</p>',
			'changelog'    => '<pre style="background:#1e293b; color:#e2e8f0; padding:15px; border-radius:6px; font-family:monospace;">' . $changelog . '</pre>',
			'installation' => '<p>Automatic updates powered by Ghulam Rasool and the SuperShield GitHub Distribution Network.</p>',
		);

		$info->banners = array(
			'low'  => 'https://raw.githubusercontent.com/grwebdevs/supershield-security/main/assets/banner-772x250.png',
			'high' => 'https://raw.githubusercontent.com/grwebdevs/supershield-security/main/assets/banner-1544x500.png',
		);

		return $info;
	}

	/**
	 * Pre-installation snapshot before update extraction.
	 *
	 * @param bool  $true
	 * @param array $hook_extra
	 * @return bool
	 */
	public static function pre_install_snapshot( $true, $hook_extra ) {
		$plugin = isset( $hook_extra['plugin'] ) ? $hook_extra['plugin'] : '';
		if ( defined( 'SUPERSHIELD_BASENAME' ) && $plugin === SUPERSHIELD_BASENAME ) {
			$upload_dir = wp_upload_dir();
			$backup_dir = trailingslashit( $upload_dir['basedir'] ) . 'supershield-backups';
			if ( ! is_dir( $backup_dir ) ) {
				wp_mkdir_p( $backup_dir );
			}
			self::secure_backup_dir( $backup_dir );
			// Snapshot current version
			$snapshot_path = trailingslashit( $backup_dir ) . 'supershield-v' . SUPERSHIELD_VERSION . '-' . time() . '.zip';
			if ( class_exists( 'ZipArchive' ) && defined( 'SUPERSHIELD_PLUGIN_DIR' ) ) {
				$zip = new ZipArchive();
				if ( true === $zip->open( $snapshot_path, ZipArchive::CREATE ) ) {
					$source = rtrim( SUPERSHIELD_PLUGIN_DIR, '/\\' );
					$iterator = new RecursiveIteratorIterator(
						new RecursiveDirectoryIterator( $source, RecursiveDirectoryIterator::SKIP_DOTS ),
						RecursiveIteratorIterator::SELF_FIRST
					);
					foreach ( $iterator as $file ) {
						$file_path = $file->getPathname();
						$rel = substr( $file_path, strlen( $source ) + 1 );
						if ( $file->isFile() ) {
							$zip->addFile( $file_path, $rel );
						}
					}
					$zip->close();
				}
			}
			// Log pre-install snapshot
			SuperShield_DB::log_event( 'admin_action', 'Pre-update snapshot created for version: ' . SUPERSHIELD_VERSION, $snapshot_path );
		}
		return $true;
	}

	/**
	 * Post-installation verification and fatal error immunity guard.
	 *
	 * @param bool  $response
	 * @param array $hook_extra
	 * @param array $result
	 * @return bool
	 */
	public static function post_install_verify( $response, $hook_extra, $result ) {
		$plugin = isset( $hook_extra['plugin'] ) ? $hook_extra['plugin'] : '';
		if ( defined( 'SUPERSHIELD_BASENAME' ) && $plugin === SUPERSHIELD_BASENAME ) {
			// Clear update transient cache
			delete_transient( 'supershield_latest_release_cache' );
			delete_site_transient( 'update_plugins' );
			SuperShield_DB::log_event( 'admin_action', 'SuperShield updated successfully via GitHub Release Engine.' );
		}
		return $response;
	}

	/**
	 * Deploy Apache 2.2 / 2.4 immunity lockdown in backup directory.
	 *
	 * @param string $dir
	 */
	private static function secure_backup_dir( $dir ) {
		$htaccess_content = "# SuperShield Updater Backup Immunity\n" .
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
}
