<?php
/**
 * System Diagnostics & GitHub Auto-Updater View — SuperShield Security
 * Light Theme & Modern SaaS Console
 *
 * @package SuperShield_Security
 * @author  Ghulam Rasool <grwebdevs.com>
 * @version 2.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$tamper_detected = SuperShield_Utils::get_option( 'antitamper_tamper_detected', 0 );
$telemetry_enabled = SuperShield_Utils::get_option( 'telemetry_enabled', 0 );
$server_type = SuperShield_Utils::get_server_type();

$alert_emails        = SuperShield_Utils::get_option( 'alert_emails', '' );
$notify_file_changes = SuperShield_Utils::get_option( 'notify_file_changes', 1 );
$notify_brute_lockout= SuperShield_Utils::get_option( 'notify_brute_lockout', 1 );
$notify_malware_found= SuperShield_Utils::get_option( 'notify_malware_found', 1 );
$notify_admin_login  = SuperShield_Utils::get_option( 'notify_admin_login', 0 );

$export_btn_html = '<button type="button" id="btn-export-diagnostics" class="btn-shield-primary"><span class="dashicons dashicons-download" style="font-size:15px; width:15px; height:15px; margin-top:2px;"></span> Export System Report</button>';
?>

<div class="wrap supershield-wrap">
	<?php
	SuperShield_Admin::render_navigation_header(
		'diagnostics',
		'Diagnostics & Updates',
		'System diagnostic exporter, GitHub Release auto-updater, and HMAC anti-tamper monitor',
		$export_btn_html
	);
	?>

	<div class="supershield-main-layout">
		<!-- Left: Auto-Updater & Integrity -->
		<div>
			<!-- GitHub Releases Auto-Updater -->
			<div class="supershield-panel">
				<div class="supershield-panel-header">
					<h2>GitHub Releases Auto-Updater</h2>
					<button type="button" id="btn-check-github-updates" class="btn-shield-secondary">
						<span class="dashicons dashicons-update" style="font-size:14px; width:14px; height:14px; margin-top:2px;"></span> Check for Updates
					</button>
				</div>

				<div style="display:flex; align-items:center; justify-content:space-between; padding:16px 20px; background:#f8fafc; border:1px solid var(--sss-border); border-radius:8px; margin-bottom:16px;">
					<div>
						<div style="font-size:14px; font-weight:600; color:var(--sss-text-primary);">Installed Version: <code>v<?php echo esc_html( SUPERSHIELD_VERSION ); ?></code></div>
						<div style="font-size:12px; color:var(--sss-text-secondary); margin-top:4px;">Official Release Channel: <code>github.com/grwebdevs/supershield-security</code></div>
					</div>
					<div id="update-status-pill">
						<span class="badge-tag safe">Up to Date</span>
					</div>
				</div>

				<div id="update-details-box" style="display:none; background:#ffffff; border:1px solid var(--sss-border); border-radius:8px; padding:20px; margin-top:16px; box-shadow:var(--sss-shadow);">
					<h3 id="update-version-title" style="margin:0 0 10px 0; color:var(--sss-brand); font-size:15px;"></h3>
					<div id="update-changelog-text" style="font-size:13px; color:var(--sss-text-secondary); white-space:pre-wrap; background:#f8fafc; padding:12px; border-radius:6px; border:1px solid var(--sss-border); margin-bottom:16px; max-height:200px; overflow-y:auto; font-family:ui-monospace, monospace;"></div>
					<a id="btn-download-update-pkg" href="#" target="_blank" class="btn-shield-primary">Download Update ZIP Archive &rarr;</a>
				</div>
			</div>

			<!-- Cryptographic Anti-Tamper Monitor -->
			<div class="supershield-panel">
				<div class="supershield-panel-header">
					<h2>HMAC-SHA256 Cryptographic Self-Integrity</h2>
				</div>

				<div style="display:flex; align-items:center; justify-content:space-between; padding:16px 20px; background:#f8fafc; border:1px solid var(--sss-border); border-radius:8px;">
					<div>
						<div style="font-size:14px; font-weight:600; color:var(--sss-text-primary);">Code Anti-Tamper Status</div>
						<div style="font-size:12px; color:var(--sss-text-secondary); margin-top:4px;">Real-time hash verification preventing malicious hooks or firewall bypasses</div>
					</div>
					<div>
						<?php if ( ! $tamper_detected ) : ?>
							<span class="badge-tag safe">Integrity Verified (Intact)</span>
						<?php else : ?>
							<span class="badge-tag critical">Tampering Detected!</span>
						<?php endif; ?>
					</div>
				</div>

				<p style="font-size:13px; color:var(--sss-text-secondary); line-height:1.6; margin-top:16px;">
					SuperShield verifies its own PHP bytecode against an embedded signed HMAC-SHA256 manifest. If an attacker or compromised script attempts to alter firewall routines or disable malware detection, SuperShield triggers an instant tamper alert.
				</p>
			</div>

			<!-- Community Threat Telemetry (Opt-in) -->
			<div class="supershield-panel">
				<div class="supershield-panel-header">
					<h2>Community Threat Intelligence (Opt-In)</h2>
				</div>

				<form class="supershield-settings-form">
					<input type="hidden" name="supershield_section" value="diagnostics" />
					<div class="toggle-switch-row">
						<div class="toggle-info">
							<h4>Share Anonymous Threat Telemetry</h4>
							<p>Contribute anonymized threat signatures (attack patterns and hashes) to <code>SSS.grwebdevs.com</code> to help protect the global WordPress community.</p>
						</div>
						<label class="switch">
							<input type="hidden" name="telemetry_enabled" value="0">
							<input type="checkbox" name="telemetry_enabled" value="1" <?php checked( ! empty( $telemetry_enabled ) ); ?>>
							<span class="slider"></span>
						</label>
					</div>

					<div style="margin-top:16px;">
						<button type="submit" class="btn-shield-primary">
							<span class="dashicons dashicons-saved" style="font-size:15px; width:15px; height:15px; margin-top:2px;"></span> Save Telemetry Preference
						</button>
					</div>
				</form>
			</div>

			<!-- Instant Security Email Alerts (Wordfence-Style) -->
			<div class="supershield-panel">
				<div class="supershield-panel-header">
					<h2>Instant Security Email Alerts</h2>
					<span class="badge-tag safe" style="font-size:11px;">100% Free PHP Mail</span>
				</div>

				<p style="font-size:13px; color:var(--sss-text-secondary); margin-top:0; line-height:1.6;">
					Receive real-time Wordfence-style alerts when critical security events occur on your site. Delivered directly through your server's native PHP mail &mdash; <strong>zero third-party SMTP limits or fees</strong>.
				</p>

				<form class="supershield-settings-form">
					<input type="hidden" name="supershield_section" value="diagnostics" />

					<div style="margin-bottom:20px;">
						<label style="display:block; font-size:13px; font-weight:600; color:var(--sss-text-primary); margin-bottom:6px;">
							Alert Email Recipients (Multiple comma-separated emails supported):
						</label>
						<input type="text" name="alert_emails" class="regular-text" style="width:100%; max-width:100%; border:1px solid var(--sss-border); border-radius:6px; padding:8px 12px; font-size:13px;" value="<?php echo esc_attr( $alert_emails ); ?>" placeholder="<?php echo esc_attr( get_option( 'admin_email' ) ); ?>, security@agency.com">
						<p style="font-size:11px; color:var(--sss-text-secondary); margin:4px 0 0 0;">
							Leave blank to default to WordPress administrator email: <code><?php echo esc_html( get_option( 'admin_email' ) ); ?></code>
						</p>
					</div>

					<div class="toggle-switch-row">
						<div class="toggle-info">
							<h4>Critical File Integrity Alterations</h4>
							<p>Alert immediately if core files, plugin components, or unauthorized PHP files appear in uploads.</p>
						</div>
						<label class="switch">
							<input type="hidden" name="notify_file_changes" value="0">
							<input type="checkbox" name="notify_file_changes" value="1" <?php checked( ! empty( $notify_file_changes ) ); ?>>
							<span class="slider"></span>
						</label>
					</div>

					<div class="toggle-switch-row">
						<div class="toggle-info">
							<h4>Brute-Force Attacker IP Lockouts</h4>
							<p>Alert when a malicious IP exceeds failed login attempts and is quarantined.</p>
						</div>
						<label class="switch">
							<input type="hidden" name="notify_brute_lockout" value="0">
							<input type="checkbox" name="notify_brute_lockout" value="1" <?php checked( ! empty( $notify_brute_lockout ) ); ?>>
							<span class="slider"></span>
						</label>
					</div>

					<div class="toggle-switch-row">
						<div class="toggle-info">
							<h4>Malware Scan Threats Discovered</h4>
							<p>Alert when deep heuristic scans detect malicious web shells or backdoors.</p>
						</div>
						<label class="switch">
							<input type="hidden" name="notify_malware_found" value="0">
							<input type="checkbox" name="notify_malware_found" value="1" <?php checked( ! empty( $notify_malware_found ) ); ?>>
							<span class="slider"></span>
						</label>
					</div>

					<div class="toggle-switch-row">
						<div class="toggle-info">
							<h4>Administrator Login Notification</h4>
							<p>Alert when an administrator signs in, recording client IP, country, and browser.</p>
						</div>
						<label class="switch">
							<input type="hidden" name="notify_admin_login" value="0">
							<input type="checkbox" name="notify_admin_login" value="1" <?php checked( ! empty( $notify_admin_login ) ); ?>>
							<span class="slider"></span>
						</label>
					</div>

					<div style="margin-top:16px;">
						<button type="submit" class="btn-shield-primary">
							<span class="dashicons dashicons-saved" style="font-size:15px; width:15px; height:15px; margin-top:2px;"></span> Save Email Alert Settings
						</button>
					</div>
				</form>
			</div>
		</div>

		<!-- Right: Diagnostics Exporter Modal / Preview -->
		<div>
			<div class="supershield-panel">
				<div class="supershield-panel-header">
					<h2>System Diagnostic Bundle</h2>
					<button type="button" id="btn-copy-diagnostics" class="btn-shield-secondary" style="font-size:12px;">Copy Markdown</button>
				</div>

				<p style="font-size:13px; color:var(--sss-text-secondary); margin-top:0;">
					Click "Export System Report" to generate a 100% sanitized report containing server environment data, loaded extensions, and SuperShield security configurations for technical support.
				</p>

				<div style="margin-top:16px;">
					<textarea id="diagnostics-output" readonly rows="16" class="large-text" style="background:#ffffff; color:#0f172a; font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size:12px; border:1px solid #cbd5e1; border-radius:8px; padding:12px; width:100%;" placeholder="Click 'Export System Report' above to generate..."></textarea>
				</div>
			</div>
		</div>
	</div>

	<?php SuperShield_Admin::render_footer(); ?>
</div>
