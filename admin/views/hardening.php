<?php
/**
 * Hardening Settings View — SuperShield Security
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
$server_type = SuperShield_Utils::get_server_type();
$upload_dir = wp_upload_dir();
$uploads_writable = is_writable( $upload_dir['basedir'] );
?>

<div class="wrap supershield-wrap">
	<?php
	SuperShield_Admin::render_navigation_header(
		'hardening',
		'8-Layer Server Hardening',
		'Enterprise Zero-Trust server lockdown neutralizing remote vectors across Apache, LiteSpeed, and Nginx'
	);
	?>

	<form class="supershield-settings-form">
		<input type="hidden" name="supershield_section" value="hardening" />
		<div class="supershield-main-layout">
			<!-- Left: Hardening Toggles -->
			<div>
				<div class="supershield-panel">
					<div class="supershield-panel-header">
						<h2>Immunity Hardening Controls (8 Zero-Trust Layers)</h2>
					</div>

					<!-- Layer 1: Uploads PHP Block -->
					<div class="toggle-switch-row">
						<div class="toggle-info">
							<h4>
								<span class="badge-tag info">Layer 1</span> 
								Block PHP Execution in Uploads
							</h4>
							<p>Enforces a read-only <code>.htaccess</code> inside <code>wp-content/uploads/</code> denying execution of any dropped <code>.php</code>, <code>.phtml</code>, or <code>.phar</code> scripts with 403 Forbidden.</p>
						</div>
						<label class="switch">
							<input type="hidden" name="block_uploads_php" value="0">
							<input type="checkbox" name="block_uploads_php" value="1" <?php checked( ! empty( $settings['block_uploads_php'] ) ); ?>>
							<span class="slider"></span>
						</label>
					</div>

					<!-- Layer 2: Disable XML-RPC -->
					<div class="toggle-switch-row">
						<div class="toggle-info">
							<h4>
								<span class="badge-tag info">Layer 2</span> 
								Disable XML-RPC (`xmlrpc.php`)
							</h4>
							<p>Kills <code>xmlrpc.php</code> execution to neutralize automated password spraying and pingback DDoS amplification vectors.</p>
						</div>
						<label class="switch">
							<input type="hidden" name="disable_xmlrpc" value="0">
							<input type="checkbox" name="disable_xmlrpc" value="1" <?php checked( ! empty( $settings['disable_xmlrpc'] ) ); ?>>
							<span class="slider"></span>
						</label>
					</div>

					<!-- Layer 3: Anti-User Enumeration -->
					<div class="toggle-switch-row">
						<div class="toggle-info">
							<h4>
								<span class="badge-tag info">Layer 3</span> 
								Block User Enumeration
							</h4>
							<p>Drops author scan queries (<code>/?author=N</code>) and blocks unauthenticated REST API requests to <code>/wp-json/wp/v2/users</code>.</p>
						</div>
						<label class="switch">
							<input type="hidden" name="block_user_enumeration" value="0">
							<input type="checkbox" name="block_user_enumeration" value="1" <?php checked( ! empty( $settings['block_user_enumeration'] ) ); ?>>
							<span class="slider"></span>
						</label>
					</div>

					<!-- Layer 4: Disable File Editing -->
					<div class="toggle-switch-row">
						<div class="toggle-info">
							<h4>
								<span class="badge-tag info">Layer 4</span> 
								Disable Dashboard File Editor
							</h4>
							<p>Enforces <code>DISALLOW_FILE_EDIT</code> at runtime so that even compromised administrator accounts cannot inject web shells.</p>
						</div>
						<label class="switch">
							<input type="hidden" name="disallow_file_edit" value="0">
							<input type="checkbox" name="disallow_file_edit" value="1" <?php checked( ! empty( $settings['disallow_file_edit'] ) ); ?>>
							<span class="slider"></span>
						</label>
					</div>

					<!-- Layer 5: Security Headers -->
					<div class="toggle-switch-row">
						<div class="toggle-info">
							<h4>
								<span class="badge-tag info">Layer 5</span> 
								Enforce HTTP Security Headers
							</h4>
							<p>Broadcasts high-grade headers: <code>X-Frame-Options: SAMEORIGIN</code>, <code>X-Content-Type-Options: nosniff</code>, and <code>Referrer-Policy</code>.</p>
						</div>
						<label class="switch">
							<input type="hidden" name="security_headers" value="0">
							<input type="checkbox" name="security_headers" value="1" <?php checked( ! empty( $settings['security_headers'] ) ); ?>>
							<span class="slider"></span>
						</label>
					</div>

					<!-- Layer 6: Hide WP Version -->
					<div class="toggle-switch-row">
						<div class="toggle-info">
							<h4>
								<span class="badge-tag info">Layer 6</span> 
								Conceal WordPress Version Fingerprints
							</h4>
							<p>Strips WordPress version numbers from HTML source, RSS generator tags, and script enqueue query strings (<code>?ver=x.x.x</code>).</p>
						</div>
						<label class="switch">
							<input type="hidden" name="hide_wp_version" value="0">
							<input type="checkbox" name="hide_wp_version" value="1" <?php checked( ! empty( $settings['hide_wp_version'] ) ); ?>>
							<span class="slider"></span>
						</label>
					</div>

					<!-- Layer 7: Protect wp-config.php & Sensitive Files -->
					<div class="toggle-switch-row">
						<div class="toggle-info">
							<h4>
								<span class="badge-tag info">Layer 7</span> 
								Core Configuration File Shield
							</h4>
							<p>Blocks direct web browser access to sensitive system files: <code>wp-config.php</code>, <code>.htaccess</code>, <code>php.ini</code>, <code>.user.ini</code>.</p>
						</div>
						<label class="switch">
							<input type="hidden" name="protect_config_files" value="0">
							<input type="checkbox" name="protect_config_files" value="1" <?php checked( ! empty( $settings['protect_config_files'] ) ); ?>>
							<span class="slider"></span>
						</label>
					</div>

					<!-- Layer 8: Stealth Dropper & Hidden File Defense -->
					<div class="toggle-switch-row">
						<div class="toggle-info">
							<h4>
								<span class="badge-tag info">Layer 8</span> 
								Stealth Dropper & Hidden Dot File Lockdown
							</h4>
							<p>Denies inbound HTTP requests to any hidden dot droppers (<code>.*.php</code>, <code>.6345dc54.php</code>) across all directories.</p>
						</div>
						<label class="switch">
							<input type="hidden" name="block_hidden_files" value="0">
							<input type="checkbox" name="block_hidden_files" value="1" <?php checked( ! empty( $settings['block_hidden_files'] ) ); ?>>
							<span class="slider"></span>
						</label>
					</div>

					<div style="margin-top: 24px;">
						<button type="submit" class="btn-shield-primary">
							<span class="dashicons dashicons-shield" style="font-size:15px; width:15px; height:15px; margin-top:2px;"></span> Apply Hardening Changes
						</button>
					</div>
				</div>
			</div>

			<!-- Right: Server Specifications & Nginx Config Snippet -->
			<div>
				<div class="supershield-panel">
					<div class="supershield-panel-header">
						<h2>Server Environment</h2>
					</div>

					<table class="supershield-table">
						<tr>
							<td><strong>Web Server:</strong></td>
							<td><code><?php echo esc_html( strtoupper( $server_type ) ); ?></code></td>
						</tr>
						<tr>
							<td><strong>PHP Version:</strong></td>
							<td><code><?php echo esc_html( PHP_VERSION ); ?></code></td>
						</tr>
						<tr>
							<td><strong>Uploads Status:</strong></td>
							<td>
								<?php if ( $uploads_writable ) : ?>
									<span class="badge-tag safe">Writable (.htaccess Immune)</span>
								<?php else : ?>
									<span class="badge-tag high">Read-Only</span>
								<?php endif; ?>
							</td>
						</tr>
						<tr>
							<td><strong>DISALLOW_FILE_EDIT:</strong></td>
							<td>
								<?php if ( defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT ) : ?>
									<span class="badge-tag safe">Enforced</span>
								<?php else : ?>
									<span class="badge-tag critical">Disabled</span>
								<?php endif; ?>
							</td>
						</tr>
					</table>
				</div>

				<!-- Nginx Configuration Snippet Drawer -->
				<div class="supershield-panel">
					<div class="supershield-panel-header">
						<h2>Nginx Directives (Optional)</h2>
					</div>
					<p style="font-size:12px; color:var(--sss-text-secondary); margin-top:0;">If running Nginx as the primary web server without Apache/LiteSpeed <code>.htaccess</code> parsing, add these directives to your vhost:</p>
					<pre style="background:#f8fafc; border:1px solid #e2e8f0; border-radius:6px; color:#0f172a; font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size:11px; padding:12px; overflow-x:auto; line-height:1.6;">
# Deny PHP execution inside media uploads
location ~* ^/wp-content/uploads/.*\.php$ {
    deny all;
}

# Deny direct access to system files
location ~* /(wp-config\.php|\.htaccess|\.env) {
    deny all;
}

# Deny hidden dot droppers
location ~ /\. {
    deny all;
}
</pre>
				</div>
			</div>
		</div>
	</form>

	<?php SuperShield_Admin::render_footer(); ?>
</div>
