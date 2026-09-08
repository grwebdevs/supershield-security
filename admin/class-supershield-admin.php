<?php
/**
 * Cybersecurity Command Center Controller for SuperShield Security.
 *
 * @package    SuperShield_Security
 * @subpackage SuperShield_Security/admin
 * @author     Ghulam Rasool <grwebdevs.com>
 * @version    2.2.1
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SuperShield_Admin {

	/**
	 * Initialize admin hooks and AJAX endpoints.
	 */
	public function init() {
		add_action( 'admin_menu', array( $this, 'register_admin_menus' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_admin_assets' ) );

		// Core AJAX Endpoints
		add_action( 'wp_ajax_supershield_save_settings', array( $this, 'ajax_save_settings' ) );
		add_action( 'wp_ajax_supershield_start_scan', array( $this, 'ajax_start_scan' ) );
		add_action( 'wp_ajax_supershield_scan_stage', array( $this, 'ajax_scan_stage' ) );
		add_action( 'wp_ajax_supershield_surgical_clean', array( $this, 'ajax_surgical_clean' ) );
		add_action( 'wp_ajax_supershield_restore_core', array( $this, 'ajax_restore_core' ) );
		add_action( 'wp_ajax_supershield_quarantine_file', array( $this, 'ajax_quarantine_file' ) );
		add_action( 'wp_ajax_supershield_unblock_ip', array( $this, 'ajax_unblock_ip' ) );
		add_action( 'wp_ajax_supershield_clear_logs', array( $this, 'ajax_clear_logs' ) );

		add_action( 'admin_notices', array( $this, 'render_admin_security_notices' ) );

		// 2.0.0 Feature Endpoints
		add_action( 'wp_ajax_supershield_export_diagnostics', array( $this, 'ajax_export_diagnostics' ) );
		add_action( 'wp_ajax_supershield_submit_feedback', array( $this, 'ajax_submit_feedback' ) );
		add_action( 'wp_ajax_supershield_check_updates', array( $this, 'ajax_check_updates' ) );
		add_action( 'wp_ajax_supershield_setup_2fa', array( $this, 'ajax_setup_2fa' ) );
		add_action( 'wp_ajax_supershield_verify_2fa', array( $this, 'ajax_verify_2fa' ) );
		add_action( 'wp_ajax_supershield_disable_2fa', array( $this, 'ajax_disable_2fa' ) );
		add_action( 'wp_ajax_supershield_destroy_sessions', array( $this, 'ajax_destroy_sessions' ) );
		add_action( 'wp_ajax_supershield_send_test_email', array( $this, 'ajax_send_test_email' ) );

		// 2.5.0 Feature Endpoints
		add_action( 'wp_ajax_supershield_test_discord', array( $this, 'ajax_test_discord' ) );
		add_action( 'wp_ajax_supershield_bulk_action', array( $this, 'ajax_bulk_action' ) );
		add_action( 'wp_ajax_supershield_fetch_live_traffic', array( $this, 'ajax_fetch_live_traffic' ) );
	}

	/**
	 * Register menus and submenus in WordPress Admin.
	 */
	public function register_admin_menus() {
		// Main Menu
		add_menu_page(
			'SuperShield Security — Command Center',
			'SuperShield',
			'manage_options',
			'supershield-security',
			array( $this, 'render_dashboard_page' ),
			'dashicons-shield',
			2
		);

		// Submenu: Dashboard
		add_submenu_page(
			'supershield-security',
			'SuperShield — Cybersecurity Command Center',
			'Dashboard',
			'manage_options',
			'supershield-security',
			array( $this, 'render_dashboard_page' )
		);

		// Submenu: Firewall (WAF) & GeoIP
		add_submenu_page(
			'supershield-security',
			'SuperShield — Web Application Firewall & GeoIP',
			'Firewall & GeoIP',
			'manage_options',
			'supershield-firewall',
			array( $this, 'render_firewall_page' )
		);

		// Submenu: Malware Scanner & 1-Click Disinfection
		add_submenu_page(
			'supershield-security',
			'SuperShield — Malware Scanner & 1-Click Eradication',
			'Malware Scanner',
			'manage_options',
			'supershield-scanner',
			array( $this, 'render_scanner_page' )
		);

		// Submenu: Hardening (8 Layers)
		add_submenu_page(
			'supershield-security',
			'SuperShield — 8-Layer Server Hardening',
			'Hardening',
			'manage_options',
			'supershield-hardening',
			array( $this, 'render_hardening_page' )
		);

		// Submenu: Login Security & 2FA
		add_submenu_page(
			'supershield-security',
			'SuperShield — Login Security & Enterprise 2FA',
			'Login & 2FA',
			'manage_options',
			'supershield-login',
			array( $this, 'render_login_page' )
		);

		// Submenu: Diagnostics & Updates
		add_submenu_page(
			'supershield-security',
			'SuperShield — Diagnostics & GitHub Auto-Updater',
			'Diagnostics & Updates',
			'manage_options',
			'supershield-diagnostics',
			array( $this, 'render_diagnostics_page' )
		);

		// Submenu: Live Traffic & Logs
		add_submenu_page(
			'supershield-security',
			'SuperShield — Live Traffic & Audit Logs',
			'Live Traffic & Logs',
			'manage_options',
			'supershield-logs',
			array( $this, 'render_logs_page' )
		);
	}

	/**
	 * Enqueue assets only on SuperShield admin screens.
	 *
	 * @param string $hook
	 */
	public function enqueue_admin_assets( $hook ) {
		if ( strpos( $hook, 'supershield' ) === false ) {
			return;
		}

		$css_file = SUPERSHIELD_PLUGIN_DIR . 'admin/css/supershield-admin.css';
		$css_ver  = file_exists( $css_file ) ? (string) filemtime( $css_file ) : SUPERSHIELD_VERSION;

		wp_enqueue_style( 'dashicons' );

		wp_enqueue_script(
			'supershield-admin-js',
			set_url_scheme( SUPERSHIELD_PLUGIN_URL . 'admin/js/supershield-admin.js', 'https' ),
			array( 'jquery' ),
			SUPERSHIELD_VERSION . '.' . time(),
			true
		);

		wp_localize_script(
			'supershield-admin-js',
			'supershield_vars',
			array(
				'ajax_url' => admin_url( 'admin-ajax.php' ),
				'nonce'    => wp_create_nonce( 'supershield_admin_nonce' ),
				'user_id'  => get_current_user_id(),
			)
		);
	}

	/**
	 * View renderers.
	 */
	public function render_dashboard_page() {
		require_once SUPERSHIELD_PLUGIN_DIR . 'admin/views/dashboard.php';
	}

	public function render_firewall_page() {
		require_once SUPERSHIELD_PLUGIN_DIR . 'admin/views/firewall.php';
	}

	public function render_scanner_page() {
		require_once SUPERSHIELD_PLUGIN_DIR . 'admin/views/scanner.php';
	}

	public function render_hardening_page() {
		require_once SUPERSHIELD_PLUGIN_DIR . 'admin/views/hardening.php';
	}

	public function render_login_page() {
		require_once SUPERSHIELD_PLUGIN_DIR . 'admin/views/login-security.php';
	}

	public function render_diagnostics_page() {
		require_once SUPERSHIELD_PLUGIN_DIR . 'admin/views/diagnostics.php';
	}

	public function render_logs_page() {
		require_once SUPERSHIELD_PLUGIN_DIR . 'admin/views/live-traffic.php';
	}

	/**
	 * Render unified Light Theme Header and Sub-Navigation bar across all 7 views.
	 *
	 * @param string $active_tab
	 * @param string $page_title
	 * @param string $page_subtitle
	 * @param string $actions_html
	 */
	public static function render_navigation_header( $active_tab, $page_title, $page_subtitle, $actions_html = '' ) {
		$tabs = array(
			'dashboard'   => array(
				'title' => 'Dashboard',
				'url'   => admin_url( 'admin.php?page=supershield-security' ),
				'icon'  => 'dashicons-dashboard',
			),
			'firewall'    => array(
				'title' => 'Firewall & GeoIP',
				'url'   => admin_url( 'admin.php?page=supershield-firewall' ),
				'icon'  => 'dashicons-shield',
			),
			'scanner'     => array(
				'title' => 'Malware Scanner',
				'url'   => admin_url( 'admin.php?page=supershield-scanner' ),
				'icon'  => 'dashicons-search',
			),
			'hardening'   => array(
				'title' => 'Server Hardening',
				'url'   => admin_url( 'admin.php?page=supershield-hardening' ),
				'icon'  => 'dashicons-admin-network',
			),
			'login'       => array(
				'title' => 'Login Security & 2FA',
				'url'   => admin_url( 'admin.php?page=supershield-login' ),
				'icon'  => 'dashicons-lock',
			),
			'diagnostics' => array(
				'title' => 'Diagnostics & Updates',
				'url'   => admin_url( 'admin.php?page=supershield-diagnostics' ),
				'icon'  => 'dashicons-admin-tools',
			),
			'logs'        => array(
				'title' => 'Live Traffic & Logs',
				'url'   => admin_url( 'admin.php?page=supershield-logs' ),
				'icon'  => 'dashicons-list-view',
			),
		);
		?>
		<!-- Inline Core CSS to guarantee 100% immediate Light Theme rendering with zero cache delay -->
		<style id="supershield-enterprise-light-theme">
			<?php
			$css_file = SUPERSHIELD_PLUGIN_DIR . 'admin/css/supershield-admin.css';
			if ( file_exists( $css_file ) ) {
				echo file_get_contents( $css_file ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			}
			?>
		</style>
		<div class="supershield-header-container">
			<div class="supershield-header">
				<div class="supershield-brand">
					<div class="supershield-logo">
						<svg viewBox="0 0 24 24"><path d="M12 2L4 5v6.09c0 5.05 3.41 9.76 8 10.91 4.59-1.15 8-5.86 8-10.91V5l-8-3z"></path></svg>
					</div>
					<div>
						<div class="brand-title-row">
							<h1><?php echo esc_html( $page_title ); ?></h1>
							<span class="version-badge">v<?php echo esc_html( SUPERSHIELD_VERSION ); ?></span>
							<span class="status-badge"><span class="status-dot"></span> Active Defense</span>
						</div>
						<p class="brand-subtitle"><?php echo esc_html( $page_subtitle ); ?></p>
					</div>
				</div>
				<div class="supershield-header-actions">
					<button type="button" id="btn-open-feedback-modal" class="btn-shield-secondary">
						<span class="dashicons dashicons-testimonial" style="font-size:15px; width:15px; height:15px; margin-top:2px;"></span> Feedback & Support
					</button>
					<?php echo $actions_html; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
				</div>
			</div>

			<nav class="supershield-nav-tabs">
				<?php foreach ( $tabs as $key => $tab ) : ?>
					<a href="<?php echo esc_url( $tab['url'] ); ?>" class="supershield-nav-tab <?php echo ( $active_tab === $key ) ? 'active' : ''; ?>">
						<span class="dashicons <?php echo esc_attr( $tab['icon'] ); ?>"></span>
						<span><?php echo esc_html( $tab['title'] ); ?></span>
					</a>
				<?php endforeach; ?>
			</nav>
		</div>

		<!-- Notification Alert Box -->
		<div id="supershield-alert-box" class="supershield-alert"></div>
		<?php
	}

	/**
	 * Render unified Light Theme Footer and Global Feedback Modal.
	 */
	public static function render_footer() {
		?>
		<!-- Shared Direct Feedback Modal -->
		<div id="supershield-feedback-modal" class="supershield-modal" style="display:none;">
			<div class="supershield-modal-backdrop"></div>
			<div class="supershield-modal-content">
				<div class="supershield-modal-header">
					<h2>Direct Engineering Feedback</h2>
					<button type="button" class="btn-modal-close">&times;</button>
				</div>
				<form id="supershield-feedback-form">
					<div style="margin-bottom:14px;">
						<label style="display:block; font-weight:600; margin-bottom:6px; color:#0f172a;">Category:</label>
						<select name="feedback_category" id="feedback-category" class="regular-text" style="width:100%;">
							<option value="bug_report">Bug Report (with environment diagnostics)</option>
							<option value="feature_request">Feature Request / Proposal</option>
							<option value="praise">General Review & Testimonial</option>
						</select>
					</div>

					<div style="margin-bottom:14px;">
						<label style="display:block; font-weight:600; margin-bottom:6px; color:#0f172a;">Your Message / Report:</label>
						<textarea name="feedback_message" id="feedback-message" rows="5" class="large-text" style="width:100%;" required placeholder="Describe what you observed or suggested improvements..."></textarea>
					</div>

					<div style="margin-bottom:20px;">
						<label style="display:block; font-weight:600; margin-bottom:6px; color:#0f172a;">Contact Email (Optional):</label>
						<input type="email" name="feedback_email" id="feedback-email" class="regular-text" style="width:100%;" placeholder="you@example.com">
						<p style="font-size:11px; color:#64748b; margin:4px 0 0 0;">Feedback transmits securely to Ghulam Rasool at <code>SSS.grwebdevs.com</code>.</p>
					</div>

					<div style="display:flex; justify-content:flex-end; gap:10px;">
						<button type="button" class="btn-shield-secondary btn-modal-close">Cancel</button>
						<button type="submit" class="btn-shield-primary">Submit to Engineering Lead</button>
					</div>
				</form>
			</div>
		</div>

		<!-- Suite Footer -->
		<div class="supershield-footer">
			<div>
				<strong>SuperShield Security Suite</strong> v<?php echo esc_html( SUPERSHIELD_VERSION ); ?> &bull; Engineered with Zero-Trust principles by <a href="https://grwebdevs.com" target="_blank" rel="noopener">Ghulam Rasool</a> (Founder, GR Web Devs)
			</div>
			<div>
				<a href="https://SSS.grwebdevs.com" target="_blank" rel="noopener">Documentation</a> &bull;
				<a href="https://github.com/grwebdevs/supershield-security" target="_blank" rel="noopener">GitHub Project</a>
			</div>
		</div>
		<?php
	}

	/**
	 * AJAX: Save Settings.
	 */
	public function ajax_save_settings() {
		check_ajax_referer( 'supershield_admin_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => 'Unauthorized' ), 403 );
		}

		$current_options = get_option( 'supershield_settings', array() );

		// Process toggle switches
		$toggle_keys = array(
			'waf_enabled',
			'waf_bypass_admin',
			'auto_block_waf_violators',
			'rate_limit_enabled',
			'bruteforce_protection',
			'enable_login_honeypot',
			'pwned_passwords_check',
			'block_uploads_php',
			'disable_xmlrpc',
			'hide_wp_version',
			'block_user_enumeration',
			'security_headers',
			'disallow_file_edit',
			'block_hidden_files',
			'protect_config_files',
			'trust_proxy_headers',
			'whitelist_loopback',
			'geoip_enabled',
			'geoip_protect_login_only',
			'2fa_enabled',
			'daily_scan_cron_enabled',
			'telemetry_enabled',
		);

		$section_map = array(
			'firewall'     => array( 'waf_enabled', 'auto_block_waf_violators', 'rate_limit_enabled', 'waf_bypass_admin', 'trust_proxy_headers', 'geoip_enabled', 'geoip_protect_login_only' ),
			'access_lists' => array(),
			'hardening'    => array( 'block_uploads_php', 'disable_xmlrpc', 'block_user_enumeration', 'disallow_file_edit', 'security_headers', 'hide_wp_version', 'protect_config_files', 'block_hidden_files' ),
			'login'        => array( 'bruteforce_protection', 'enable_login_honeypot', '2fa_enabled', 'pwned_passwords_check' ),
			'scanner'      => array( 'daily_scan_cron_enabled', 'weekly_scan_report_enabled', 'monthly_scan_report_enabled', 'daily_clean_report_enabled' ),
			'diagnostics'  => array( 'telemetry_enabled', 'daily_scan_cron_enabled', 'notify_file_changes', 'notify_brute_lockout', 'notify_malware_found', 'notify_admin_login' ),
		);

		$section = isset( $_POST['supershield_section'] ) ? sanitize_text_field( wp_unslash( $_POST['supershield_section'] ) ) : '';

		if ( isset( $section_map[ $section ] ) ) {
			foreach ( $section_map[ $section ] as $sec_key ) {
				$current_options[ $sec_key ] = ( isset( $_POST[ $sec_key ] ) && 1 === (int) $_POST[ $sec_key ] ) ? 1 : 0;
			}
		} else {
			foreach ( $toggle_keys as $key ) {
				if ( isset( $_POST[ $key ] ) ) {
					$current_options[ $key ] = ( 1 === (int) $_POST[ $key ] ) ? 1 : 0;
				}
			}
		}

		// Numerical and text settings
		if ( isset( $_POST['max_login_retries'] ) ) {
			$current_options['max_login_retries'] = max( 1, (int) $_POST['max_login_retries'] );
		}

		if ( isset( $_POST['login_lockout_duration'] ) ) {
			$current_options['login_lockout_duration'] = max( 60, (int) $_POST['login_lockout_duration'] );
		}

		if ( isset( $_POST['custom_login_slug'] ) ) {
			$raw_slug = strtolower( trim( sanitize_text_field( wp_unslash( $_POST['custom_login_slug'] ) ) ) );
			$slug = preg_replace( '/[^a-z0-9-_]/', '', $raw_slug );
			$forbidden = array( 'wp-admin', 'wp-login', 'wp-content', 'wp-includes', 'admin', 'login', 'feed', 'wp-json' );
			if ( in_array( $slug, $forbidden, true ) ) {
				wp_send_json_error( array( 'message' => "The login slug '$slug' is a reserved WordPress system slug. Please choose a different slug." ) );
			}
			$current_options['custom_login_slug'] = $slug;
		}

		if ( isset( $_POST['geoip_mode'] ) ) {
			$mode = sanitize_text_field( wp_unslash( $_POST['geoip_mode'] ) );
			$current_options['geoip_mode'] = ( 'whitelist' === $mode ) ? 'whitelist' : 'blacklist';
		}

		if ( isset( $_POST['geoip_countries'] ) ) {
			if ( is_array( $_POST['geoip_countries'] ) ) {
				$current_options['geoip_countries'] = array_map( 'sanitize_text_field', wp_unslash( $_POST['geoip_countries'] ) );
			} else {
				$raw = sanitize_textarea_field( wp_unslash( $_POST['geoip_countries'] ) );
				$current_options['geoip_countries'] = array_filter( array_map( 'trim', preg_split( '/[\s,]+/', $raw ) ) );
			}
		}

		if ( isset( $_POST['2fa_roles'] ) && is_array( $_POST['2fa_roles'] ) ) {
			$current_options['2fa_roles'] = array_map( 'sanitize_text_field', wp_unslash( $_POST['2fa_roles'] ) );
		}

		if ( isset( $_POST['2fa_grace_period_days'] ) ) {
			$current_options['2fa_grace_period_days'] = max( 0, (int) $_POST['2fa_grace_period_days'] );
		}

		if ( isset( $_POST['ip_whitelist'] ) ) {
			$whitelist_raw = sanitize_textarea_field( wp_unslash( $_POST['ip_whitelist'] ) );
			$current_options['ip_whitelist'] = array_filter( array_map( 'trim', explode( "\n", $whitelist_raw ) ) );
		}

		if ( isset( $_POST['ip_blacklist'] ) ) {
			$blacklist_raw = sanitize_textarea_field( wp_unslash( $_POST['ip_blacklist'] ) );
			$current_options['ip_blacklist'] = array_filter( array_map( 'trim', explode( "\n", $blacklist_raw ) ) );
		}

		if ( isset( $_POST['alert_emails'] ) ) {
			$current_options['alert_emails'] = sanitize_textarea_field( wp_unslash( $_POST['alert_emails'] ) );
		}

		// Safety check: protect current admin IP in whitelist so they never lock themselves out
		$admin_ip = SuperShield_Utils::get_client_ip();
		if ( ! empty( $admin_ip ) && '127.0.0.1' !== $admin_ip && '::1' !== $admin_ip ) {
			$whitelist = isset( $current_options['ip_whitelist'] ) && is_array( $current_options['ip_whitelist'] ) ? $current_options['ip_whitelist'] : array();
			if ( ! in_array( $admin_ip, $whitelist, true ) ) {
				$whitelist[] = $admin_ip;
				$current_options['ip_whitelist'] = array_values( array_unique( $whitelist ) );
			}
		}

		if ( 'blacklist' === ( isset( $current_options['geoip_mode'] ) ? $current_options['geoip_mode'] : 'blacklist' ) ) {
			$current_admin_country = SuperShield_GeoIP::resolve_country( $admin_ip );
			if ( ! empty( $current_admin_country ) && 'LOCAL' !== $current_admin_country && 'XX' !== $current_admin_country ) {
				if ( isset( $current_options['geoip_countries'] ) && is_array( $current_options['geoip_countries'] ) ) {
					// Remove current admin country from blacklist if accidentally included
					$current_options['geoip_countries'] = array_values( array_filter( $current_options['geoip_countries'], function( $c ) use ( $current_admin_country ) {
						return strtoupper( trim( $c ) ) !== $current_admin_country;
					} ) );
				}
			}
		}

		update_option( 'supershield_settings', $current_options );

		if ( ! empty( $current_options['block_uploads_php'] ) ) {
			SuperShield_Hardening::ensure_uploads_htaccess_immunity();
		}

		if ( class_exists( 'SuperShield_Scanner' ) ) {
			SuperShield_Scanner::sync_cron_schedule();
		}

		SuperShield_DB::log_event( 'admin_action', 'Security settings updated.' );
		wp_send_json_success( array( 'message' => 'Settings saved successfully!' ) );
	}

	/**
	 * AJAX: Trigger Malware Scan.
	 */
	public function ajax_start_scan() {
		check_ajax_referer( 'supershield_admin_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => 'Unauthorized' ), 403 );
		}

		try {
			$results = SuperShield_Scanner::run_full_scan();
			wp_send_json_success( $results );
		} catch ( Throwable $e ) {
			wp_send_json_error( array( 'message' => 'Scanner error: ' . $e->getMessage() ) );
		}
	}

	/**
	 * AJAX: 1-Click Surgical Disinfection.
	 */
	public function ajax_surgical_clean() {
		check_ajax_referer( 'supershield_admin_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => 'Unauthorized' ), 403 );
		}

		$issue_id = isset( $_POST['issue_id'] ) ? sanitize_text_field( wp_unslash( $_POST['issue_id'] ) ) : '';
		if ( empty( $issue_id ) ) {
			wp_send_json_error( array( 'message' => 'Invalid issue identifier' ) );
		}

		$result = SuperShield_Cleaner::clean_issue( $issue_id );
		if ( $result['success'] ) {
			wp_send_json_success( $result );
		} else {
			wp_send_json_error( $result );
		}
	}

	/**
	 * AJAX: 1-Click Core File Restoration.
	 */
	public function ajax_restore_core() {
		check_ajax_referer( 'supershield_admin_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => 'Unauthorized' ), 403 );
		}

		$file_path = isset( $_POST['file_path'] ) ? sanitize_text_field( wp_unslash( $_POST['file_path'] ) ) : '';
		$relative = SuperShield_Cleaner::get_core_relative_path( $file_path );

		if ( ! $relative ) {
			wp_send_json_error( array( 'message' => 'Invalid core file path' ) );
		}

		$result = SuperShield_Cleaner::restore_core_file( $relative );
		if ( $result['success'] ) {
			if ( ! empty( $_POST['issue_id'] ) ) {
				$issue_id = sanitize_text_field( wp_unslash( $_POST['issue_id'] ) );
				global $wpdb;
				if ( isset( $wpdb ) && is_object( $wpdb ) ) {
					$wpdb->update(
						SuperShield_DB::get_scan_issues_table(),
						array( 'status' => 'cleaned', 'updated_at' => current_time( 'mysql' ) ),
						array( 'id' => $issue_id )
					);
				}
			}
			wp_send_json_success( $result );
		} else {
			wp_send_json_error( $result );
		}
	}

	/**
	 * AJAX: Quarantine File.
	 */
	public function ajax_quarantine_file() {
		check_ajax_referer( 'supershield_admin_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => 'Unauthorized' ), 403 );
		}

		$file_path = isset( $_POST['file_path'] ) ? sanitize_text_field( wp_unslash( $_POST['file_path'] ) ) : '';
		if ( empty( $file_path ) ) {
			wp_send_json_error( array( 'message' => 'Invalid file path' ) );
		}

		$result = SuperShield_Cleaner::quarantine_file( $file_path );
		$is_ok = is_array( $result ) ? ! empty( $result['success'] ) : (bool) $result;
		if ( $is_ok ) {
			if ( ! empty( $_POST['issue_id'] ) ) {
				$issue_id = sanitize_text_field( wp_unslash( $_POST['issue_id'] ) );
				global $wpdb;
				if ( isset( $wpdb ) && is_object( $wpdb ) ) {
					$wpdb->update(
						SuperShield_DB::get_scan_issues_table(),
						array( 'status' => 'quarantined', 'updated_at' => current_time( 'mysql' ) ),
						array( 'id' => $issue_id )
					);
				}
			}
			wp_send_json_success( array( 'message' => ( is_array( $result ) && ! empty( $result['message'] ) ) ? $result['message'] : 'File safely isolated in quarantine vault.' ) );
		} else {
			wp_send_json_error( array( 'message' => ( is_array( $result ) && ! empty( $result['message'] ) ) ? $result['message'] : 'Failed to quarantine file. Check filesystem permissions.' ) );
		}
	}

	/**
	 * AJAX: Setup 2FA credentials for current user.
	 */
	public function ajax_setup_2fa() {
		check_ajax_referer( 'supershield_admin_nonce', 'nonce' );

		$user_id = get_current_user_id();
		if ( ! $user_id ) {
			wp_send_json_error( array( 'message' => 'User session invalid' ) );
		}

		$user = get_userdata( $user_id );
		$secret = SuperShield_2FA::generate_secret( 16 );
		$auth_url = SuperShield_2FA::get_otpauth_url( $user->user_login, $secret );
		$qr_svg = SuperShield_2FA::render_qr_code_svg( $auth_url, 180 );
		$backup_codes = SuperShield_2FA::generate_backup_codes( 8 );

		// Temporarily store pending secret in transient
		set_transient( 'supershield_pending_2fa_' . $user_id, array(
			'secret'       => $secret,
			'backup_codes' => $backup_codes,
		), 15 * MINUTE_IN_SECONDS );

		wp_send_json_success( array(
			'secret'       => $secret,
			'auth_url'     => $auth_url,
			'qr_svg'       => $qr_svg,
			'backup_codes' => $backup_codes,
		) );
	}

	/**
	 * AJAX: Verify code & activate 2FA for current user.
	 */
	public function ajax_verify_2fa() {
		check_ajax_referer( 'supershield_admin_nonce', 'nonce' );

		$user_id = get_current_user_id();
		$code = isset( $_POST['code'] ) ? sanitize_text_field( wp_unslash( $_POST['code'] ) ) : '';

		$pending = get_transient( 'supershield_pending_2fa_' . $user_id );
		if ( ! $pending || empty( $pending['secret'] ) ) {
			wp_send_json_error( array( 'message' => '2FA setup session expired. Please regenerate your QR code.' ) );
		}

		if ( SuperShield_2FA::verify_totp( $pending['secret'], $code ) ) {
			SuperShield_2FA::enable_user_2fa( $user_id, $pending['secret'], $pending['backup_codes'] );
			delete_transient( 'supershield_pending_2fa_' . $user_id );

			SuperShield_DB::log_event( 'admin_action', '2FA enabled for user: ' . wp_get_current_user()->user_login );
			wp_send_json_success( array( 'message' => 'Two-Factor Authentication is now active and enforced for your account!' ) );
		}

		wp_send_json_error( array( 'message' => 'Invalid 6-digit TOTP security code. Please try again.' ) );
	}

	/**
	 * AJAX: Disable 2FA for user.
	 */
	public function ajax_disable_2fa() {
		check_ajax_referer( 'supershield_admin_nonce', 'nonce' );

		$user_id = get_current_user_id();
		SuperShield_2FA::disable_user_2fa( $user_id );

		SuperShield_DB::log_event( 'admin_action', '2FA disabled for user: ' . wp_get_current_user()->user_login );
		wp_send_json_success( array( 'message' => 'Two-Factor Authentication has been deactivated.' ) );
	}

	/**
	 * AJAX: Destroy all other active sessions for current user.
	 */
	public function ajax_destroy_sessions() {
		check_ajax_referer( 'supershield_admin_nonce', 'nonce' );

		if ( ! is_user_logged_in() ) {
			wp_send_json_error( array( 'message' => 'Unauthorized' ), 401 );
		}

		if ( class_exists( 'WP_Session_Tokens' ) ) {
			$manager = WP_Session_Tokens::get_instance( get_current_user_id() );
			$token = wp_get_session_token();
			$manager->destroy_others( $token );
		}

		SuperShield_DB::log_event( 'admin_action', 'All other active user sessions destroyed by ' . wp_get_current_user()->user_login );
		wp_send_json_success( array( 'message' => 'All other devices and active sessions have been safely logged out.' ) );
	}

	/**
	 * AJAX: Export System Diagnostics Report.
	 */
	public function ajax_export_diagnostics() {
		check_ajax_referer( 'supershield_admin_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => 'Unauthorized' ), 403 );
		}

		$report = SuperShield_Telemetry::generate_diagnostics_report();
		wp_send_json_success( $report );
	}

	/**
	 * AJAX: Submit Feedback.
	 */
	public function ajax_submit_feedback() {
		check_ajax_referer( 'supershield_admin_nonce', 'nonce' );

		$category = isset( $_POST['category'] ) ? sanitize_text_field( wp_unslash( $_POST['category'] ) ) : 'bug_report';
		$message  = isset( $_POST['message'] ) ? sanitize_textarea_field( wp_unslash( $_POST['message'] ) ) : '';
		$email    = isset( $_POST['email'] ) ? sanitize_email( wp_unslash( $_POST['email'] ) ) : '';

		$result = SuperShield_Telemetry::submit_feedback( $category, $message, $email );
		if ( $result['success'] ) {
			wp_send_json_success( $result );
		} else {
			wp_send_json_error( $result );
		}
	}

	/**
	 * AJAX: Check GitHub Updates.
	 */
	public function ajax_check_updates() {
		check_ajax_referer( 'supershield_admin_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => 'Unauthorized' ), 403 );
		}

		$release = SuperShield_Updater::get_latest_release( true );
		if ( $release ) {
			$has_update = version_compare( $release['version'], SUPERSHIELD_VERSION, '>' );
			wp_send_json_success( array(
				'has_update'   => $has_update,
				'current'      => SUPERSHIELD_VERSION,
				'latest'       => $release['version'],
				'download_url' => $release['download_url'],
				'changelog'    => $release['body'],
			) );
		}

		wp_send_json_error( array( 'message' => 'Unable to connect to SuperShield update server. You are running version ' . SUPERSHIELD_VERSION ) );
	}

	/**
	 * AJAX: Unblock IP.
	 */
	public function ajax_unblock_ip() {
		check_ajax_referer( 'supershield_admin_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => 'Unauthorized' ), 403 );
		}

		$ip = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';
		if ( empty( $ip ) ) {
			wp_send_json_error( array( 'message' => 'Invalid IP' ) );
		}

		SuperShield_DB::unblock_ip( $ip );
		SuperShield_DB::log_event( 'admin_action', 'IP manually unblocked: ' . $ip );

		wp_send_json_success( array( 'message' => 'IP address unblocked.' ) );
	}

	/**
	 * AJAX: Clear Logs.
	 */
	public function ajax_clear_logs() {
		check_ajax_referer( 'supershield_admin_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => 'Unauthorized' ), 403 );
		}

		global $wpdb;
		$table = SuperShield_DB::get_events_table();
		$wpdb->query( "TRUNCATE TABLE $table" );

		SuperShield_DB::log_event( 'admin_action', 'Security event logs cleared by administrator.' );
		wp_send_json_success( array( 'message' => 'Logs cleared successfully.' ) );
	}

	/**
	 * AJAX: Dispatch test security alert email via native PHP mail.
	 */
	public function ajax_send_test_email() {
		check_ajax_referer( 'supershield_admin_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => 'Unauthorized' ), 403 );
		}

		$recipients = SuperShield_Notifier::get_recipients();
		if ( empty( $recipients ) ) {
			wp_send_json_error( array( 'message' => 'No valid email recipients configured.' ) );
		}

		$details = array(
			'Server Host'       => esc_html( gethostname() ?: 'Linux Server' ),
			'Outbound Engine'   => 'Native PHP mail() / wp_mail() [100% Free Zero-Cost]',
			'Target User'       => esc_html( wp_get_current_user()->user_login ),
			'Recipients Count'  => count( $recipients ),
			'Delivery Protocol' => 'Free Server Pipeline Verified',
		);

		$sent = SuperShield_Notifier::dispatch_alert(
			'test_alert',
			'Diagnostic Test Security Alert',
			'This test security alert confirms that your WordPress hosting server is successfully delivering SuperShield real-time notifications via free server PHP mail with zero paid SMTP dependencies.',
			$details,
			admin_url( 'admin.php?page=supershield-diagnostics' )
		);

		if ( $sent ) {
			wp_send_json_success( array(
				'message'    => 'Test security alert dispatched to: ' . implode( ', ', $recipients ),
				'recipients' => $recipients,
			) );
		} else {
			wp_send_json_error( array(
				'message' => 'Failed to dispatch email. Please ensure your hosting provider has PHP mail() enabled.',
			) );
		}
	}

	/**
	 * AJAX: Run chunked stage of the malware and integrity scan.
	 */
	public function ajax_scan_stage() {
		check_ajax_referer( 'supershield_admin_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => 'Unauthorized' ), 403 );
		}

		$stage = isset( $_POST['stage'] ) ? sanitize_key( $_POST['stage'] ) : 'init';
		$raw_state = isset( $_POST['state'] ) && is_array( $_POST['state'] ) ? $_POST['state'] : array();

		$state = array(
			'scanned_files' => isset( $raw_state['scanned_files'] ) ? (int) $raw_state['scanned_files'] : 0,
			'threats_found' => isset( $raw_state['threats_found'] ) ? (int) $raw_state['threats_found'] : 0,
			'issues'        => isset( $raw_state['issues'] ) && is_array( $raw_state['issues'] ) ? $raw_state['issues'] : array(),
			'start_time'    => isset( $raw_state['start_time'] ) ? (float) $raw_state['start_time'] : microtime( true ),
		);

		try {
			$stage_result = SuperShield_Scanner::run_scan_stage( $stage, $state );
			wp_send_json_success( $stage_result );
		} catch ( Throwable $e ) {
			wp_send_json_error( array(
				'message' => 'Scan stage [' . esc_html( $stage ) . '] error: ' . $e->getMessage(),
				'stage'   => $stage,
			) );
		}
	}

	/**
	 * Display high-priority cybersecurity alert banner on WordPress Admin screens.
	 */
	public function render_admin_security_notices() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		// Don't show inside SuperShield's own plugin screens where full console is already displayed
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		if ( $screen && false !== strpos( $screen->id, 'supershield' ) ) {
			return;
		}

		$metrics = SuperShield_DB::get_dashboard_metrics();

		// Alert 1: Unresolved malware or CVE vulnerabilities
		if ( ! empty( $metrics['active_threats'] ) && $metrics['active_threats'] > 0 ) {
			$scanner_url = admin_url( 'admin.php?page=supershield-scanner' );
			?>
			<div class="notice notice-error is-dismissible" style="border-left: 4px solid #ef4444; background: #fff5f5; padding: 12px 18px; margin: 16px 20px 10px 0;">
				<div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 10px;">
					<div style="display: flex; align-items: center; gap: 10px;">
						<span class="dashicons dashicons-shield-alt" style="color: #ef4444; font-size: 22px; width: 22px; height: 22px;"></span>
						<span style="font-size: 13.5px; color: #0f172a;">
							<strong>SuperShield Security Warning:</strong> Detected <strong><?php echo (int) $metrics['active_threats']; ?> unresolved security threat(s)</strong> requiring immediate attention.
						</span>
					</div>
					<a href="<?php echo esc_url( $scanner_url ); ?>" class="button button-primary" style="background: #ef4444; border-color: #dc2626; font-weight: 600;">
						Review &amp; Eradicate Threats &rarr;
					</a>
				</div>
			</div>
			<?php
			return;
		}

		// Alert 2: Informative lockout notice if attacks occurred today
		if ( ! empty( $metrics['failed_logins_today'] ) && $metrics['failed_logins_today'] >= 5 ) {
			$firewall_url = admin_url( 'admin.php?page=supershield-firewall' );
			?>
			<div class="notice notice-warning is-dismissible" style="border-left: 4px solid #f59e0b; background: #fffbeb; padding: 10px 16px; margin: 16px 20px 10px 0;">
				<div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px;">
					<div style="display: flex; align-items: center; gap: 8px;">
						<span class="dashicons dashicons-shield" style="color: #f59e0b; font-size: 18px; width: 18px; height: 18px;"></span>
						<span style="font-size: 13px; color: #1e293b;">
							<strong>SuperShield Firewall Active:</strong> Neutralized <strong><?php echo (int) $metrics['failed_logins_today']; ?> brute-force probe(s)</strong> today. Your site is actively shielded.
						</span>
					</div>
					<a href="<?php echo esc_url( $firewall_url ); ?>" style="color: #4f46e5; text-decoration: underline; font-weight: 600; font-size: 12.5px;">
						View Blocked Attacks &rarr;
					</a>
				</div>
			</div>
			<?php
		}
	}

	/**
	 * AJAX: Test Discord Webhook connection.
	 */
	public function ajax_test_discord() {
		check_ajax_referer( 'supershield_admin_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => 'Unauthorized' ), 403 );
		}

		$webhook_url = isset( $_POST['webhook_url'] ) ? esc_url_raw( wp_unslash( $_POST['webhook_url'] ) ) : '';
		if ( empty( $webhook_url ) || false === strpos( $webhook_url, 'discord.com/api/webhooks' ) ) {
			wp_send_json_error( array( 'message' => 'Please provide a valid Discord Webhook URL (https://discord.com/api/webhooks/...)' ) );
		}

		// Save URL temporarily or permanently
		SuperShield_Utils::update_option( 'discord_webhook_url', $webhook_url );

		$details = array(
			'Origin Site'     => get_bloginfo( 'name' ),
			'Site URL'        => home_url(),
			'Test Dispatched' => current_time( 'Y-m-d H:i:s T' ),
			'Status'          => 'Verified Active & Online',
		);

		$sent = SuperShield_Notifier::dispatch_discord_webhook(
			'weekly_digest',
			'Discord Webhook Test Verification',
			'SuperShield Security webhook notification dispatched successfully! Your security alerts will be transmitted directly into this channel.',
			$details,
			admin_url( 'admin.php?page=supershield-security' )
		);

		if ( $sent ) {
			wp_send_json_success( array( 'message' => 'Discord Webhook test notification transmitted successfully! Check your Discord channel.' ) );
		} else {
			wp_send_json_error( array( 'message' => 'Failed to reach Discord. Please verify that the webhook URL is active and copied correctly.' ) );
		}
	}

	/**
	 * AJAX: Bulk action on scanner findings (Bulk Disinfect, Bulk Quarantine, Bulk Clean).
	 */
	public function ajax_bulk_action() {
		check_ajax_referer( 'supershield_admin_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => 'Unauthorized' ), 403 );
		}

		$bulk_action = isset( $_POST['bulk_action'] ) ? sanitize_key( $_POST['bulk_action'] ) : '';
		$issue_ids = isset( $_POST['issue_ids'] ) && is_array( $_POST['issue_ids'] ) ? array_map( 'intval', $_POST['issue_ids'] ) : array();

		if ( empty( $issue_ids ) ) {
			wp_send_json_error( array( 'message' => 'No scan issues selected for bulk remediation.' ) );
		}

		$cleaned_count = 0;
		$errors = array();

		foreach ( $issue_ids as $id ) {
			if ( 'disinfect' === $bulk_action || 'clean' === $bulk_action ) {
				$res = SuperShield_Cleaner::clean_issue( $id );
				if ( ! empty( $res['success'] ) ) {
					$cleaned_count++;
				} else {
					$errors[] = "#$id: " . ( $res['message'] ?? 'Failed' );
				}
			} elseif ( 'ignore' === $bulk_action ) {
				SuperShield_Cleaner::mark_issue_resolved( $id, 'ignored' );
				$cleaned_count++;
			}
		}

		wp_send_json_success( array(
			'message'       => "Bulk action [{$bulk_action}] processed {$cleaned_count} finding(s) successfully.",
			'cleaned_count' => $cleaned_count,
			'errors'        => $errors,
		) );
	}

	/**
	 * AJAX: Fetch live traffic events with search, filter, and pagination.
	 */
	public function ajax_fetch_live_traffic() {
		check_ajax_referer( 'supershield_admin_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => 'Unauthorized' ), 403 );
		}

		global $wpdb;
		$events_table = SuperShield_DB::get_events_table();

		$search = isset( $_POST['search'] ) ? sanitize_text_field( wp_unslash( $_POST['search'] ) ) : '';
		$filter = isset( $_POST['filter_type'] ) ? sanitize_text_field( wp_unslash( $_POST['filter_type'] ) ) : '';
		$page = isset( $_POST['page_num'] ) ? max( 1, (int) $_POST['page_num'] ) : 1;
		$limit = 50;
		$offset = ( $page - 1 ) * $limit;

		$where_clauses = array( '1=1' );
		$params = array();

		if ( ! empty( $search ) ) {
			$where_clauses[] = '(ip_address LIKE %s OR request_uri LIKE %s OR payload LIKE %s OR details LIKE %s)';
			$like = '%' . $wpdb->esc_like( $search ) . '%';
			$params[] = $like;
			$params[] = $like;
			$params[] = $like;
			$params[] = $like;
		}

		if ( 'threats' === $filter ) {
			$where_clauses[] = "event_type IN ('waf_block', 'geoip_block', 'tamper_alert', 'rate_limit_drop')";
		} elseif ( 'logins' === $filter ) {
			$where_clauses[] = "event_type IN ('login_success', 'login_fail', 'login_lockout')";
		} elseif ( 'admin' === $filter ) {
			$where_clauses[] = "event_type = 'admin_action'";
		} elseif ( ! empty( $filter ) ) {
			$where_clauses[] = 'event_type = %s';
			$params[] = $filter;
		}

		$where_sql = implode( ' AND ', $where_clauses );

		$count_query = "SELECT COUNT(*) FROM $events_table WHERE $where_sql";
		$total_rows = ! empty( $params ) ? (int) $wpdb->get_var( $wpdb->prepare( $count_query, $params ) ) : (int) $wpdb->get_var( $count_query );

		$query = "SELECT * FROM $events_table WHERE $where_sql ORDER BY created_at DESC LIMIT %d OFFSET %d";
		$query_params = array_merge( $params, array( $limit, $offset ) );
		$events = $wpdb->get_results( $wpdb->prepare( $query, $query_params ) );

		$html = '';
		if ( empty( $events ) ) {
			$html = '<tr><td colspan="6" style="text-align:center; padding:30px; color:var(--sss-text-muted); font-style:italic;">No log records matching your criteria.</td></tr>';
		} else {
			foreach ( $events as $row ) {
				$country_code = SuperShield_GeoIP::resolve_country( $row->ip_address );
				$country_name = SuperShield_GeoIP::get_country_name( $country_code );

				$badge_class = 'info';
				$badge_label = esc_html( $row->event_type );

				if ( in_array( $row->event_type, array( 'waf_block', 'rate_limit_drop', 'login_lockout', 'tamper_alert' ), true ) ) {
					$badge_class = 'critical';
					$badge_label = 'rate_limit_drop' === $row->event_type ? 'Rate Limit' : strtoupper( str_replace( '_', ' ', $row->event_type ) );
				} elseif ( 'geoip_block' === $row->event_type ) {
					$badge_class = 'medium';
					$badge_label = 'GeoIP Block';
				} elseif ( 'login_fail' === $row->event_type ) {
					$badge_class = 'high';
					$badge_label = 'Auth Fail';
				} elseif ( 'login_success' === $row->event_type ) {
					$badge_class = 'safe';
					$badge_label = 'Success';
				}

				$html .= '<tr>';
				$html .= '<td><span class="badge-tag ' . esc_attr( $badge_class ) . '">' . $badge_label . '</span></td>';
				$html .= '<td>';
				$html .= '<div style="font-weight:600; font-family:monospace;">' . esc_html( $row->ip_address ) . '</div>';
				$html .= '<div style="font-size:11px; color:var(--sss-text-muted); display:flex; align-items:center; gap:4px; margin-top:2px;">';
				$html .= '<span class="dashicons dashicons-admin-site" style="font-size:12px; width:12px; height:12px;"></span>';
				$html .= '<span>' . esc_html( $country_name . ( 'XX' !== $country_code && 'LOCAL' !== $country_code ? ' (' . $country_code . ')' : '' ) ) . '</span>';
				$html .= '</div></td>';
				$html .= '<td><span style="display:inline-block; padding:2px 5px; font-size:10px; font-weight:700; border-radius:3px; background:#f1f5f9; color:#475569; margin-right:4px;">' . esc_html( $row->request_method ) . '</span><code style="font-size:12px;">' . esc_html( substr( $row->request_uri, 0, 45 ) . ( strlen( $row->request_uri ) > 45 ? '...' : '' ) ) . '</code></td>';
				$html .= '<td><span style="font-size:12.5px; color:var(--sss-text-primary);">' . esc_html( $row->details ) . '</span></td>';
				$html .= '<td>' . ( ! empty( $row->payload ) ? '<code style="font-size:11.5px; background:#f8fafc; padding:3px 6px; border:1px solid #e2e8f0; border-radius:4px; max-width:200px; display:inline-block; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">' . esc_html( substr( $row->payload, 0, 50 ) ) . '</code>' : '<span style="color:var(--sss-text-muted); font-size:11px;">N/A</span>' ) . '</td>';
				$html .= '<td style="font-size:12px; color:var(--sss-text-muted); white-space:nowrap;">' . esc_html( $row->created_at ) . '</td>';
				$html .= '</tr>';
			}
		}

		wp_send_json_success( array(
			'html'       => $html,
			'total_rows' => $total_rows,
			'page'       => $page,
			'total_pages'=> ceil( $total_rows / $limit ),
		) );
	}
}
