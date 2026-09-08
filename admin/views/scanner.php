<?php
/**
 * Deep Malware Scanner & 1-Click Surgical Disinfection View — SuperShield Security
 * Light Theme & Modern SaaS Console
 *
 * @package SuperShield_Security
 * @author  Ghulam Rasool <grwebdevs.com>
 * @version 2.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

global $wpdb;
$issues_table = SuperShield_DB::get_scan_issues_table();
$active_issues = $wpdb->get_results( "SELECT * FROM $issues_table WHERE status = 'active' ORDER BY severity DESC, created_at DESC" );
$last_results = SuperShield_Utils::get_option( 'last_scan_results', array( 'scanned_files' => 0, 'threats_found' => 0, 'duration' => 0 ) );
$settings = get_option( 'supershield_settings', array() );

$scan_btn_html = '<button type="button" id="btn-start-security-scan" class="btn-shield-primary"><span class="dashicons dashicons-search" style="font-size:15px; width:15px; height:15px; margin-top:2px;"></span> Run Full Deep Scan</button>';
?>

<div class="wrap supershield-wrap">
	<?php
	SuperShield_Admin::render_navigation_header(
		'scanner',
		'Forensic Malware Scanner',
		'WordPress Core integrity diff, Shannon entropy heuristics, stealth droppers & surgical code excision',
		$scan_btn_html
	);
	?>

	<!-- Scan Progress & Pipeline Card -->
	<div class="supershield-panel">
		<div class="supershield-panel-header">
			<h2>Forensic Scanner Pipeline</h2>
			<span style="font-size: 13px; color: var(--sss-text-muted);">
				Last Duration: <strong><?php echo esc_html( $last_results['duration'] ); ?>s</strong> &bull; 
				Files Analyzed: <strong><?php echo esc_html( number_format_i18n( $last_results['scanned_files'] ) ); ?></strong> &bull; 
				Threats: <strong><?php echo esc_html( $last_results['threats_found'] ); ?></strong>
			</span>
		</div>

		<div style="background:#e2e8f0; border-radius:9999px; height:10px; width:100%; overflow:hidden; margin-bottom:12px;">
			<div id="scan-progress-bar" style="background: var(--sss-brand); height:100%; width: 0%; transition: width 0.35s ease;"></div>
		</div>
		<p id="scan-status-text" style="color: var(--sss-text-secondary); font-size: 13px; margin: 0;">
			Click "Run Full Deep Scan" to analyze WordPress core checksums, uploads execution leaks, stealth dot droppers, packed high-entropy scripts, and database payloads.
		</p>
	</div>

	<!-- Detected Threats & Forensic Remediation -->
	<div class="supershield-panel">
		<div class="supershield-panel-header" style="flex-wrap:wrap; gap:10px;">
			<h2>Active Threat Findings (<?php echo esc_html( count( $active_issues ) ); ?> Unresolved)</h2>
			<?php if ( ! empty( $active_issues ) ) : ?>
				<div style="display:flex; gap:8px; align-items:center;">
					<button type="button" id="btn-bulk-disinfect" class="btn-shield-primary" style="font-size:12px; padding:6px 12px;">
						<span class="dashicons dashicons-shield" style="font-size:14px; width:14px; height:14px; margin-top:2px;"></span> Bulk Disinfect Selected
					</button>
					<button type="button" id="btn-bulk-ignore" class="btn-shield-secondary" style="font-size:12px; padding:6px 12px;">
						Mark Ignored
					</button>
				</div>
			<?php endif; ?>
		</div>

		<?php if ( empty( $active_issues ) ) : ?>
			<div style="padding: 40px 20px; text-align: center;">
				<span class="dashicons dashicons-yes-alt" style="font-size: 48px; width: 48px; height: 48px; color: var(--sss-success); margin-bottom: 12px;"></span>
				<h3 style="color: var(--sss-text-primary); margin: 0 0 6px 0;">No Active Threats Detected</h3>
				<p style="color: var(--sss-text-muted); margin: 0; font-size: 14px;">Your files, media uploads, database options, and installed components match official integrity checksums.</p>
			</div>
		<?php else : ?>
			<table class="supershield-table">
				<thead>
					<tr>
						<th style="width:30px;"><input type="checkbox" id="check-all-issues" title="Select All"></th>
						<th>Severity</th>
						<th>Classification</th>
						<th>Location / Target</th>
						<th>Signature</th>
						<th>Incident Details</th>
						<th>Remediation</th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $active_issues as $issue ) : ?>
						<tr id="issue-row-<?php echo esc_attr( $issue->id ); ?>">
							<td><input type="checkbox" class="issue-checkbox" value="<?php echo esc_attr( $issue->id ); ?>"></td>
							<td>
								<span class="badge-tag <?php echo esc_attr( $issue->severity ); ?>">
									<?php echo esc_html( strtoupper( $issue->severity ) ); ?>
								</span>
							</td>
							<td>
								<?php if ( 'cve_vulnerability' === $issue->issue_type ) : ?>
									<span class="badge-tag critical" style="background:#fee2e2; color:#b91c1c;">CVE Flaw</span>
								<?php else : ?>
									<code><?php echo esc_html( $issue->issue_type ); ?></code>
								<?php endif; ?>
							</td>
							<td><strong style="word-break: break-all; color:var(--sss-text-primary); font-size:12px;"><?php echo esc_html( $issue->file_path ); ?></strong></td>
							<td><span style="font-size:11px; color:var(--sss-brand); font-family:monospace;"><?php echo esc_html( $issue->signature_name ); ?></span></td>
							<td style="font-size:13px; color:var(--sss-text-secondary);"><?php echo esc_html( $issue->details ); ?></td>
							<td>
								<?php if ( 'cve_vulnerability' === $issue->issue_type ) : ?>
									<a href="<?php echo esc_url( admin_url( 'plugins.php' ) ); ?>" class="btn-shield-primary" style="padding:6px 12px; font-size:12px; text-decoration:none; display:inline-flex; align-items:center; gap:4px;">
										<span class="dashicons dashicons-update" style="font-size:13px; width:13px; height:13px; margin-top:2px;"></span> Update Component
									</a>
								<?php elseif ( 'core_modified' === $issue->issue_type ) : ?>
									<button type="button" class="btn-shield-primary btn-restore-core" data-id="<?php echo esc_attr( $issue->id ); ?>" data-path="<?php echo esc_attr( $issue->file_path ); ?>" style="padding:6px 12px; font-size:12px;">
										Restore Core Diff
									</button>
								<?php elseif ( in_array( $issue->issue_type, array( 'rogue_admin', 'encrypted_db_payload', 'malicious_post_content' ), true ) ) : ?>
									<button type="button" class="btn-shield-danger btn-surgical-clean" data-id="<?php echo esc_attr( $issue->id ); ?>" style="padding:6px 12px; font-size:12px;">
										1-Click Eradicate
									</button>
								<?php elseif ( 'worm_staging' === $issue->issue_type ) : ?>
									<button type="button" class="btn-shield-danger btn-surgical-clean" data-id="<?php echo esc_attr( $issue->id ); ?>" style="padding:6px 12px; font-size:12px;">
										Quarantine Staging
									</button>
								<?php elseif ( in_array( $issue->issue_type, array( 'malware_signature', 'obfuscated_entropy' ), true ) ) : ?>
									<button type="button" class="btn-shield-primary btn-surgical-clean" data-id="<?php echo esc_attr( $issue->id ); ?>" style="padding:6px 12px; font-size:12px;">
										Surgical Disinfect
									</button>
								<?php else : ?>
									<button type="button" class="btn-shield-danger btn-quarantine-file" data-id="<?php echo esc_attr( $issue->id ); ?>" data-path="<?php echo esc_attr( $issue->file_path ); ?>" style="padding:6px 12px; font-size:12px;">
										Quarantine File
									</button>
								<?php endif; ?>
							</td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
		<?php endif; ?>
	</div>

	<!-- Automated Scan Scheduling Panel -->
	<div class="supershield-panel">
		<div class="supershield-panel-header">
			<h2>Automated Scan Scheduling &amp; Report Delivery</h2>
		</div>
		<form class="supershield-settings-form" id="supershield-scanner-settings-form">
			<input type="hidden" name="supershield_section" value="scanner">

			<?php
			// Helper: show next cron time
			$fmt_next = function( $hook ) {
				$next = wp_next_scheduled( $hook );
				return $next
					? '<span style="color:var(--sss-success); font-size:11px;">Next: ' . esc_html( date_i18n( 'D, d M Y H:i', $next ) ) . '</span>'
					: '<span style="color:var(--sss-text-muted); font-size:11px;">Not scheduled</span>';
			};
			?>

			<!-- Daily Auto-Scan -->
			<div class="toggle-switch-row">
				<div class="toggle-info">
					<h4>Daily Auto-Scan (WP-Cron)</h4>
					<p>Runs a full multi-tier scan every 24 hours. Email alert is sent <strong>only when threats are detected</strong> — never bothers you with clean reports unless you enable the option below. <?php echo $fmt_next( 'supershield_daily_scan_cron' ); // phpcs:ignore ?></p>
				</div>
				<label class="switch">
					<input type="hidden" name="daily_scan_cron_enabled" value="0">
					<input type="checkbox" name="daily_scan_cron_enabled" value="1" <?php checked( ! empty( $settings['daily_scan_cron_enabled'] ) ); ?>>
					<span class="slider"></span>
				</label>
			</div>

			<!-- Also send clean-bill report -->
			<div class="toggle-switch-row" style="margin-left:20px; padding-left:12px; border-left:2px solid var(--sss-border);">
				<div class="toggle-info">
					<h4 style="font-size:13px; color:var(--sss-text-secondary);">Also Send Clean-Bill Report for Daily Scan</h4>
					<p>When enabled, you will also receive a confirmation email when the daily scan finds <em>nothing</em>. Default: OFF.</p>
				</div>
				<label class="switch">
					<input type="hidden" name="daily_clean_report_enabled" value="0">
					<input type="checkbox" name="daily_clean_report_enabled" value="1" <?php checked( ! empty( $settings['daily_clean_report_enabled'] ) ); ?>>
					<span class="slider"></span>
				</label>
			</div>

			<!-- Weekly Report -->
			<div class="toggle-switch-row" style="margin-top:16px; padding-top:14px; border-top:1px solid var(--sss-border);">
				<div class="toggle-info">
					<h4>Weekly Security Digest (Every 7 Days)</h4>
					<p>Scans the site every week and sends a full security summary report — regardless of whether threats are found. Great for client reports. <?php echo $fmt_next( 'supershield_weekly_scan_cron' ); // phpcs:ignore ?></p>
				</div>
				<label class="switch">
					<input type="hidden" name="weekly_scan_report_enabled" value="0">
					<input type="checkbox" name="weekly_scan_report_enabled" value="1" <?php checked( ! empty( $settings['weekly_scan_report_enabled'] ) ); ?>>
					<span class="slider"></span>
				</label>
			</div>

			<!-- Monthly Report -->
			<div class="toggle-switch-row" style="margin-top:16px; padding-top:14px; border-top:1px solid var(--sss-border);">
				<div class="toggle-info">
					<h4>Monthly Security Report (Every 30 Days)</h4>
					<p>A comprehensive monthly digest scanning every 30 days — includes full stats. Ideal for management/compliance reporting. <?php echo $fmt_next( 'supershield_monthly_scan_cron' ); // phpcs:ignore ?></p>
				</div>
				<label class="switch">
					<input type="hidden" name="monthly_scan_report_enabled" value="0">
					<input type="checkbox" name="monthly_scan_report_enabled" value="1" <?php checked( ! empty( $settings['monthly_scan_report_enabled'] ) ); ?>>
					<span class="slider"></span>
				</label>
			</div>

			<div style="margin-top: 20px;">
				<button type="submit" class="btn-shield-primary">
					<span class="dashicons dashicons-saved" style="font-size:15px; width:15px; height:15px; margin-top:2px;"></span> Save Scan Schedule
				</button>
			</div>
		</form>
	</div>

	<?php SuperShield_Admin::render_footer(); ?>
</div>
