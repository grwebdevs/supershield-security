<?php
/**
 * Login Security & Enterprise Two-Factor Authentication (2FA) View — SuperShield Security
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
$user_id = get_current_user_id();
$user_2fa_active = SuperShield_2FA::is_user_2fa_enabled( $user_id );
$remaining_backups = SuperShield_2FA::get_remaining_backup_codes_count( $user_id );

global $wpdb;
$events_table = SuperShield_DB::get_events_table();
$login_events = $wpdb->get_results(
	"SELECT * FROM $events_table 
	 WHERE event_type IN ('login_fail', 'login_lockout', 'login_success') 
	 ORDER BY created_at DESC LIMIT 25"
);
?>

<div class="wrap supershield-wrap">
	<?php
	SuperShield_Admin::render_navigation_header(
		'login',
		'Login Security & 2FA',
		'Progressive brute-force lockout, invisible honeypot decoys, and RFC 6238 TOTP authenticators'
	);
	?>

	<div class="supershield-main-layout">
		<!-- Left: Global Login Defense & 2FA Enforcement Form -->
		<div>
			<form class="supershield-settings-form">
				<input type="hidden" name="supershield_section" value="login" />
				<div class="supershield-panel">
					<div class="supershield-panel-header">
						<h2>Brute-Force Shield & Decoy Honeypots</h2>
					</div>

					<div class="toggle-switch-row">
						<div class="toggle-info">
							<h4>Enable Brute-Force Lockout Defense</h4>
							<p>Monitors failed authentication attempts per IP and triggers progressive temporary lockout when threshold is reached.</p>
						</div>
						<label class="switch">
							<input type="hidden" name="bruteforce_protection" value="0">
							<input type="checkbox" name="bruteforce_protection" value="1" <?php checked( ! empty( $settings['bruteforce_protection'] ) ); ?>>
							<span class="slider"></span>
						</label>
					</div>

					<div class="toggle-switch-row">
						<div class="toggle-info">
							<h4>Invisible Honeypot Anti-Bot Trap</h4>
							<p>Embeds CSS-masked decoy form fields that immediately catch and ban automated bots for 24 hours.</p>
						</div>
						<label class="switch">
							<input type="hidden" name="enable_login_honeypot" value="0">
							<input type="checkbox" name="enable_login_honeypot" value="1" <?php checked( ! empty( $settings['enable_login_honeypot'] ) ); ?>>
							<span class="slider"></span>
						</label>
					</div>

					<div style="margin-top: 18px; display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
						<div>
							<label style="display:block; font-weight:600; margin-bottom:6px; color:var(--sss-text-primary); font-size:13px;">Max Retries Before Lockout:</label>
							<input type="number" name="max_login_retries" min="1" max="50" value="<?php echo esc_attr( isset( $settings['max_login_retries'] ) ? $settings['max_login_retries'] : 5 ); ?>" class="regular-text" style="width: 100%;">
						</div>
						<div>
							<label style="display:block; font-weight:600; margin-bottom:6px; color:var(--sss-text-primary); font-size:13px;">Lockout Duration (seconds):</label>
							<input type="number" name="login_lockout_duration" min="60" max="604800" value="<?php echo esc_attr( isset( $settings['login_lockout_duration'] ) ? $settings['login_lockout_duration'] : 3600 ); ?>" class="regular-text" style="width: 100%;">
						</div>
					</div>

					<!-- Custom Secret Login URL Obfuscation -->
					<div style="margin-top:20px; padding-top:18px; border-top:1px solid var(--sss-border);">
						<label style="display:block; font-weight:600; margin-bottom:6px; color:var(--sss-text-primary); font-size:13px;">Custom Secret Login Slug (URL Obfuscation):</label>
						<p style="font-size:12px; color:var(--sss-text-secondary); margin-top:0;">Replaces standard <code>/wp-login.php</code> with a custom secret entry slug to instantly eliminate automated credential stuffing bots. Leave blank to use default WordPress login.</p>
						<div style="display:flex; align-items:center; gap:8px;">
							<span style="color:var(--sss-text-muted); font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size:13px;"><?php echo esc_html( function_exists( 'home_url' ) ? home_url( '/' ) : 'https://example.com/' ); ?></span>
							<input type="text" name="custom_login_slug" value="<?php echo esc_attr( isset( $settings['custom_login_slug'] ) ? $settings['custom_login_slug'] : '' ); ?>" class="regular-text" placeholder="e.g. portal-access" style="font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size:13px;">
						</div>
					</div>

					<!-- Global 2FA Policy Settings -->
					<div style="margin-top:24px; padding-top:20px; border-top:1px solid var(--sss-border);">
						<div class="toggle-switch-row">
							<div class="toggle-info">
								<h4>Enforce Two-Factor Authentication (2FA) Globally</h4>
								<p>Mandates TOTP security codes for privileged user roles across the site.</p>
							</div>
							<label class="switch">
								<input type="hidden" name="2fa_enabled" value="0">
								<input type="checkbox" name="2fa_enabled" value="1" <?php checked( ! empty( $settings['2fa_enabled'] ) ); ?>>
								<span class="slider"></span>
							</label>
						</div>

						<div style="margin-top:16px; display:grid; grid-template-columns: 1fr 1fr; gap:20px;">
							<div>
								<label style="display:block; font-weight:600; margin-bottom:6px; color:var(--sss-text-primary); font-size:13px;">Grace Period Days for New Users:</label>
								<input type="number" name="2fa_grace_period_days" min="0" max="30" value="<?php echo esc_attr( isset( $settings['2fa_grace_period_days'] ) ? $settings['2fa_grace_period_days'] : 3 ); ?>" class="regular-text" style="width:100%;">
								<p style="font-size:11px; color:var(--sss-text-muted); margin:4px 0 0 0;">Days before lockout occurs if user hasn't set up 2FA.</p>
							</div>
						</div>
					</div>

					<div style="margin-top: 24px;">
						<button type="submit" class="btn-shield-primary">
							<span class="dashicons dashicons-lock" style="font-size:15px; width:15px; height:15px; margin-top:2px;"></span> Save Login Defense Settings
						</button>
					</div>
				</div>
			</form>

			<!-- Recent Authentication Audit Trail -->
			<div class="supershield-panel">
				<div class="supershield-panel-header">
					<h2>Authentication Audit Trail (Last 25 Events)</h2>
				</div>

				<?php if ( empty( $login_events ) ) : ?>
					<p style="color: var(--sss-text-muted); font-style: italic; padding: 12px 0; margin:0;">No login events recorded yet.</p>
				<?php else : ?>
					<table class="supershield-table">
						<thead>
							<tr>
								<th>Status</th>
								<th>IP Address</th>
								<th>Incident Details</th>
								<th>User / Vector</th>
								<th>Timestamp</th>
							</tr>
						</thead>
						<tbody>
							<?php foreach ( $login_events as $ev ) : ?>
								<tr>
									<td>
										<?php if ( 'login_success' === $ev->event_type ) : ?>
											<span class="badge-tag safe">Success</span>
										<?php elseif ( 'login_lockout' === $ev->event_type ) : ?>
											<span class="badge-tag critical">Lockout</span>
										<?php else : ?>
											<span class="badge-tag high">Failed</span>
										<?php endif; ?>
									</td>
									<td><code><?php echo esc_html( $ev->ip_address ); ?></code></td>
									<td style="font-size:13px;"><?php echo esc_html( $ev->details ); ?></td>
									<td style="font-size:13px;"><?php echo esc_html( $ev->payload ); ?></td>
									<td style="font-size:12px; color:var(--sss-text-muted); white-space:nowrap;"><?php echo esc_html( human_time_diff( strtotime( $ev->created_at ), current_time( 'timestamp' ) ) . ' ago' ); ?></td>
								</tr>
							<?php endforeach; ?>
						</tbody>
					</table>
				<?php endif; ?>
			</div>
		</div>

		<!-- Right: User's Personal TOTP 2FA Configuration -->
		<div>
			<div class="supershield-panel">
				<div class="supershield-panel-header">
					<h2>Your Personal 2FA Authenticator</h2>
					<?php if ( $user_2fa_active ) : ?>
						<span class="badge-tag safe">2FA Active</span>
					<?php else : ?>
						<span class="badge-tag critical">Not Configured</span>
					<?php endif; ?>
				</div>

				<p style="font-size:13px; color:var(--sss-text-secondary); margin-top:0;">
					Protect your administrator account with Google Authenticator, Authy, 1Password, Bitwarden, or Microsoft Authenticator.
				</p>

				<?php if ( $user_2fa_active ) : ?>
					<div style="background:var(--sss-success-subtle); border:1px solid var(--sss-success-border); border-radius:8px; padding:18px; margin-bottom:18px;">
						<div style="color:var(--sss-success); font-weight:600; font-size:14px; margin-bottom:6px;">✓ Two-Factor Authentication is Active</div>
						<div style="font-size:12px; color:var(--sss-text-secondary);">Remaining Emergency Recovery Codes: <strong><?php echo esc_html( $remaining_backups ); ?></strong></div>
					</div>

					<div style="display:flex; gap:10px;">
						<button type="button" id="btn-reconfig-2fa" class="btn-shield-secondary" style="flex:1;">Re-Configure 2FA</button>
						<button type="button" id="btn-disable-2fa" class="btn-shield-danger" style="flex:1;">Disable 2FA</button>
					</div>
				<?php else : ?>
					<button type="button" id="btn-start-2fa-setup" class="btn-shield-primary" style="width:100%; justify-content:center;">
						Set Up Two-Factor Authentication Now
					</button>
				<?php endif; ?>

				<!-- Dynamic 2FA Setup Flow (Hidden until triggered) -->
				<div id="supershield-2fa-setup-box" style="display:none; margin-top:20px; background:#f8fafc; border:1px solid var(--sss-border); border-radius:8px; padding:20px;">
					<h3 style="margin:0 0 10px 0; color:var(--sss-text-primary); font-size:14px;">1. Scan QR Code in Authenticator App</h3>
					<div id="2fa-qr-container" style="text-align:center; padding:12px 0; background:#ffffff; border-radius:6px; border:1px solid var(--sss-border); margin-bottom:12px;"></div>

					<div style="font-size:12px; color:var(--sss-text-secondary); margin-bottom:6px;">Or enter this secret key manually:</div>
					<code id="2fa-secret-text" style="display:block; padding:10px; background:#ffffff; border:1px solid var(--sss-border); border-radius:6px; font-size:13px; color:var(--sss-brand); letter-spacing:2px; font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; word-break:break-all; margin-bottom:16px;"></code>

					<h3 style="margin:0 0 10px 0; color:var(--sss-text-primary); font-size:14px;">2. Emergency Recovery Codes</h3>
					<p style="font-size:12px; color:var(--sss-danger); margin:0 0 8px 0; font-weight:500;">Save these single-use codes safely. If you lose your phone, they are your recovery key:</p>
					<div id="2fa-backup-codes-container" style="display:grid; grid-template-columns:1fr 1fr; gap:6px; background:#ffffff; padding:12px; border-radius:6px; border:1px solid var(--sss-border); font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size:12px; color:var(--sss-text-primary); margin-bottom:16px;"></div>

					<h3 style="margin:0 0 10px 0; color:var(--sss-text-primary); font-size:14px;">3. Verify 6-Digit Code</h3>
					<div style="display:flex; gap:8px;">
						<input type="text" id="2fa-verification-code" maxlength="6" placeholder="000000" class="regular-text" style="font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size:16px; letter-spacing:3px; text-align:center; width:140px;">
						<button type="button" id="btn-confirm-2fa" class="btn-shield-primary" style="flex:1; justify-content:center;">Verify & Activate</button>
					</div>
				</div>
			</div>
		</div>
	</div>

	<?php SuperShield_Admin::render_footer(); ?>
</div>
