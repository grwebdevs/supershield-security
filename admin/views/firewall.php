<?php
/**
 * Firewall (WAF) & GeoIP Country Blocking Settings View — SuperShield Security
 * Light Theme & Modern SaaS Console
 *
 * @package SuperShield_Security
 * @author  Ghulam Rasool <grwebdevs.com>
 * @version 2.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$settings = get_option( 'supershield_settings', array() );

global $wpdb;
$blocked_table = SuperShield_DB::get_blocked_ips_table();
$blocked_ips = $wpdb->get_results( "SELECT * FROM $blocked_table ORDER BY blocked_at DESC LIMIT 50" );

$detected_country = SuperShield_GeoIP::resolve_country();
$cf_country = isset( $_SERVER['HTTP_CF_IPCOUNTRY'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_IPCOUNTRY'] ) ) : '';
$all_countries = SuperShield_GeoIP::get_countries();
$active_countries = isset( $settings['geoip_countries'] ) ? (array) $settings['geoip_countries'] : array( 'RU', 'CN', 'KP' );
?>

<div class="wrap supershield-wrap">
	<?php
	SuperShield_Admin::render_navigation_header(
		'firewall',
		'Web Application Firewall & GeoIP',
		'Deep packet heuristic inspection and zero-latency offline geographic access control'
	);
	?>

	<div class="supershield-main-layout">
		<!-- Left: WAF Engine Controls & GeoIP -->
		<div>
			<form class="supershield-settings-form" id="supershield-firewall-form">
				<input type="hidden" name="supershield_section" value="firewall" />

				<!-- WAF Module -->
				<div class="supershield-panel">
					<div class="supershield-panel-header">
						<h2>Heuristic WAF Inspection Modules</h2>
					</div>

					<div class="toggle-switch-row">
						<div class="toggle-info">
							<h4>Enable Web Application Firewall (WAF)</h4>
							<p>Normalizes inputs, resolves encodings, and intercepts SQLi, XSS, RCE, LFI, and bad bots before WordPress hooks execute.</p>
						</div>
						<label class="switch">
							<input type="hidden" name="waf_enabled" value="0">
							<input type="checkbox" name="waf_enabled" value="1" <?php checked( ! empty( $settings['waf_enabled'] ) ); ?>>
							<span class="slider"></span>
						</label>
					</div>

					<div class="toggle-switch-row" style="align-items: center;">
						<div class="toggle-info">
							<h4>Firewall Operational Mode</h4>
							<p>Choose between active enforcement, 7-day learning mode (auto-whitelists legitimate builder/admin actions), or silent monitoring.</p>
						</div>
						<div style="min-width: 220px;">
							<select name="waf_mode" style="width: 100%; border-radius: 6px; padding: 6px 10px; font-size: 13px; background: #ffffff; color: var(--sss-text-primary); border: 1px solid #cbd5e1;">
								<option value="block" <?php selected( isset( $settings['waf_mode'] ) ? $settings['waf_mode'] : 'block', 'block' ); ?>>🛡️ Active Blocking (Drop Threats)</option>
								<option value="learning" <?php selected( isset( $settings['waf_mode'] ) ? $settings['waf_mode'] : 'block', 'learning' ); ?>>🧠 Learning Mode (Auto-Whitelist)</option>
								<option value="simulate" <?php selected( isset( $settings['waf_mode'] ) ? $settings['waf_mode'] : 'block', 'simulate' ); ?>>👁️ Simulation (Monitor &amp; Log Only)</option>
							</select>
						</div>
					</div>

					<div class="toggle-switch-row">
						<div class="toggle-info">
							<h4>404 Vulnerability Prober Trap</h4>
							<p>Instantly locks out automated scanners (WPScan, Acunetix, Nikto) generating excessive 404 errors probing for sensitive files.</p>
						</div>
						<label class="switch">
							<input type="hidden" name="prober_404_trap_enabled" value="0">
							<input type="checkbox" name="prober_404_trap_enabled" value="1" <?php checked( ! empty( $settings['prober_404_trap_enabled'] ) || ! isset( $settings['prober_404_trap_enabled'] ) ); ?>>
							<span class="slider"></span>
						</label>
					</div>

					<div class="toggle-switch-row">
						<div class="toggle-info">
							<h4>Auto-Block Violators</h4>
							<p>Instantly bans IPs into the firewall blocklist upon high-severity attack detection (SQLi, RCE, sensitive file probes).</p>
						</div>
						<label class="switch">
							<input type="hidden" name="auto_block_waf_violators" value="0">
							<input type="checkbox" name="auto_block_waf_violators" value="1" <?php checked( ! empty( $settings['auto_block_waf_violators'] ) ); ?>>
							<span class="slider"></span>
						</label>
					</div>

					<div class="toggle-switch-row">
						<div class="toggle-info">
							<h4>Anti-DDoS &amp; Aggressive Rate Limiting</h4>
							<p>Throttles automated bot floods, rapid-fire scrapers, and volumetric HTTP bursts with instant 429 cooldowns.</p>
						</div>
						<label class="switch">
							<input type="hidden" name="rate_limit_enabled" value="0">
							<input type="checkbox" name="rate_limit_enabled" value="1" <?php checked( ! empty( $settings['rate_limit_enabled'] ) ); ?>>
							<span class="slider"></span>
						</label>
					</div>

					<div class="toggle-switch-row">
						<div class="toggle-info">
							<h4>Bypass WAF for Logged-In Administrators</h4>
							<p>Eliminate false positives when authenticated administrators submit raw JavaScript, HTML, or code in page builders.</p>
						</div>
						<label class="switch">
							<input type="hidden" name="waf_bypass_admin" value="0">
							<input type="checkbox" name="waf_bypass_admin" value="1" <?php checked( ! empty( $settings['waf_bypass_admin'] ) ); ?>>
							<span class="slider"></span>
						</label>
					</div>

					<div class="toggle-switch-row">
						<div class="toggle-info">
							<h4>Trust Cloudflare & Reverse Proxy IP Headers</h4>
							<p>Enable only if your site is behind Cloudflare, AWS CloudFront, or an Nginx reverse proxy. Enforces standard <code>REMOTE_ADDR</code> when disabled to prevent header spoofing.</p>
						</div>
						<label class="switch">
							<input type="hidden" name="trust_proxy_headers" value="0">
							<input type="checkbox" name="trust_proxy_headers" value="1" <?php checked( ! empty( $settings['trust_proxy_headers'] ) ); ?>>
							<span class="slider"></span>
						</label>
					</div>
				</div>

				<!-- GeoIP Country Blocking Module -->
				<div class="supershield-panel">
					<div class="supershield-panel-header">
						<h2>Offline GeoIP & Country Blocking (100% Free)</h2>
						<?php if ( ! empty( $cf_country ) ) : ?>
							<span class="badge-tag safe">Cloudflare GeoIP Active: <?php echo esc_html( $cf_country ); ?></span>
						<?php else : ?>
							<span class="badge-tag medium">Offline Resolver Active: <?php echo esc_html( $detected_country ); ?></span>
						<?php endif; ?>
					</div>

					<div class="toggle-switch-row">
						<div class="toggle-info">
							<h4>Enable Country / GeoIP Access Filtering</h4>
							<p>Restricts access based on geographic location using local offline databases and Cloudflare headers without slow external API calls.</p>
						</div>
						<label class="switch">
							<input type="hidden" name="geoip_enabled" value="0">
							<input type="checkbox" name="geoip_enabled" value="1" <?php checked( ! empty( $settings['geoip_enabled'] ) ); ?>>
							<span class="slider"></span>
						</label>
					</div>

					<div class="toggle-switch-row">
						<div class="toggle-info">
							<h4>Protect Admin & Login Screens Only</h4>
							<p>When enabled, country restrictions apply only to <code>wp-login.php</code> and administrative endpoints, leaving the public storefront accessible worldwide.</p>
						</div>
						<label class="switch">
							<input type="hidden" name="geoip_protect_login_only" value="0">
							<input type="checkbox" name="geoip_protect_login_only" value="1" <?php checked( ! empty( $settings['geoip_protect_login_only'] ) ); ?>>
							<span class="slider"></span>
						</label>
					</div>

					<div style="margin-top: 18px; display: grid; grid-template-columns: 1fr 2fr; gap: 20px;">
						<div>
							<label style="display:block; font-weight:600; margin-bottom:6px; color:var(--sss-text-primary); font-size:13px;">Policy Mode:</label>
							<select name="geoip_mode" class="regular-text" style="width: 100%;">
								<option value="blacklist" <?php selected( isset( $settings['geoip_mode'] ) ? $settings['geoip_mode'] : 'blacklist', 'blacklist' ); ?>>Blacklist (Block selected countries)</option>
								<option value="whitelist" <?php selected( isset( $settings['geoip_mode'] ) ? $settings['geoip_mode'] : '', 'whitelist' ); ?>>Whitelist (Allow only selected countries)</option>
							</select>
						</div>

						<div>
							<label style="display:block; font-weight:600; margin-bottom:6px; color:var(--sss-text-primary); font-size:13px;">Target Country ISO Codes (Comma-separated or space-delimited):</label>
							<input type="text" name="geoip_countries" value="<?php echo esc_attr( implode( ', ', $active_countries ) ); ?>" class="large-text" placeholder="e.g. RU, CN, KP, IR" style="font-family:monospace; text-transform:uppercase; width:100%;">
							<p style="font-size:11px; color:var(--sss-text-muted); margin:4px 0 0 0;">Detected Country for your current IP: <strong><?php echo esc_html( $detected_country ); ?></strong> (Do not block your own country!)</p>
						</div>
					</div>

					<div style="margin-top: 24px;">
						<button type="submit" class="btn-shield-primary">
							<span class="dashicons dashicons-saved" style="font-size:15px; width:15px; height:15px; margin-top:2px;"></span> Save Firewall &amp; GeoIP Settings
						</button>
					</div>
				</div>
			</form>

			<!-- Blocked IPs Management -->
			<div class="supershield-panel">
				<div class="supershield-panel-header">
					<h2>Currently Blocked IP Addresses (<span id="blocked-ips-count"><?php echo count( $blocked_ips ); ?></span>)</h2>
				</div>

				<?php if ( empty( $blocked_ips ) ) : ?>
					<p style="color: var(--sss-text-muted); font-style: italic; padding: 12px 0; margin: 0;">No active IP blocks recorded.</p>
				<?php else : ?>
					<table class="supershield-table">
						<thead>
							<tr>
								<th>IP Address</th>
								<th>Reason</th>
								<th>Type</th>
								<th>Blocked At</th>
								<th>Action</th>
							</tr>
						</thead>
						<tbody>
							<?php foreach ( $blocked_ips as $b ) : ?>
								<tr>
									<td><code><?php echo esc_html( $b->ip_address ); ?></code></td>
									<td style="font-size:13px;"><?php echo esc_html( $b->reason ); ?></td>
									<td><span class="badge-tag high"><?php echo esc_html( strtoupper( $b->block_type ) ); ?></span></td>
									<td style="font-size:12px; color:var(--sss-text-muted);"><?php echo esc_html( $b->blocked_at ); ?></td>
									<td>
										<button type="button" class="btn-shield-danger btn-unblock-ip" data-ip="<?php echo esc_attr( $b->ip_address ); ?>">Unblock</button>
									</td>
								</tr>
							<?php endforeach; ?>
						</tbody>
					</table>
				<?php endif; ?>
			</div>
		</div>

		<!-- Right: IP Access Control Lists -->
		<div>
			<form class="supershield-settings-form" id="supershield-access-lists-form">
				<input type="hidden" name="supershield_section" value="access_lists" />
				<div class="supershield-panel">
					<div class="supershield-panel-header">
						<h2>IP Access Control Lists</h2>
					</div>

					<div style="margin-bottom: 20px;">
						<div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
							<label style="font-weight:600; color:var(--sss-text-primary); font-size:13px;">Whitelisted IPs (One per line):</label>
							<button type="button" id="btn-whitelist-current-ip" class="btn-shield-secondary" style="padding:2px 8px; font-size:11px;" data-ip="<?php echo esc_attr( SuperShield_Utils::get_client_ip() ); ?>" title="Add your current IP to whitelist">
								+ Whitelist My IP
							</button>
						</div>
						<p style="font-size:12px; color:var(--sss-text-secondary); margin-top:0;">These IPs or CIDR subnets bypass all firewall rules and login lockouts.</p>
						<textarea name="ip_whitelist" id="ip-whitelist-textarea" rows="5" class="large-text" style="font-family:monospace; width:100%; border:1px solid #cbd5e1; border-radius:6px; padding:8px 10px;"><?php
							$whitelist = isset( $settings['ip_whitelist'] ) ? (array) $settings['ip_whitelist'] : array();
							echo esc_textarea( implode( "\n", $whitelist ) );
						?></textarea>
						<p style="font-size: 11px; color: var(--sss-success); margin-top: 4px; font-weight:500;">Your current IP: <strong><?php echo esc_html( SuperShield_Utils::get_client_ip() ); ?></strong></p>
					</div>

					<div>
						<label style="display:block; font-weight:600; margin-bottom:6px; color:var(--sss-text-primary); font-size:13px;">Blacklisted IPs (One per line):</label>
						<p style="font-size:12px; color:var(--sss-text-secondary); margin-top:0;">Permanently forbidden from connecting to this website.</p>
						<textarea name="ip_blacklist" rows="5" class="large-text" style="font-family:monospace; width:100%; border:1px solid #cbd5e1; border-radius:6px; padding:8px 10px;"><?php
							$blacklist = isset( $settings['ip_blacklist'] ) ? (array) $settings['ip_blacklist'] : array();
							echo esc_textarea( implode( "\n", $blacklist ) );
						?></textarea>
					</div>

					<div style="margin-top: 24px;">
						<button type="submit" class="btn-shield-primary" style="width: 100%; justify-content: center;">
							<span class="dashicons dashicons-shield" style="font-size:15px; width:15px; height:15px; margin-top:2px;"></span> Update Access Lists
						</button>
					</div>
				</div>
			</form>
		</div>
	</div>

	<?php SuperShield_Admin::render_footer(); ?>
</div>
