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
$settings = SuperShield_Utils::get_settings();

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
		<div class="supershield-panel-header">
			<h2>Detected Threats & Surgical Remediation (<?php echo count( $active_issues ); ?>)</h2>
		</div>

		<?php if ( empty( $active_issues ) ) : ?>
			<div style="padding: 45px 20px; text-align: center; background: var(--sss-success-subtle); border-radius: 8px; border: 1px solid var(--sss-success-border);">
				<span class="dashicons dashicons-yes-alt" style="font-size:42px; width:42px; height:42px; color:var(--sss-success); margin-bottom:8px;"></span>
				<h3 style="margin: 0 0 6px 0; color: var(--sss-success); font-size: 18px; font-weight:700;">Clean Bill of Health!</h3>
				<p style="margin: 0; font-size: 13px; color: var(--sss-text-secondary);">Zero stealth droppers, altered core files, unauthorized administrators, or encrypted payloads detected.</p>
			</div>
		<?php else : ?>
			<table class="supershield-table">
				<thead>
					<tr>
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
							<td>
								<span class="badge-tag <?php echo esc_attr( $issue->severity ); ?>">
									<?php echo esc_html( strtoupper( $issue->severity ) ); ?>
								</span>
							</td>
							<td><code><?php echo esc_html( $issue->issue_type ); ?></code></td>
							<td><strong style="word-break: break-all; color:var(--sss-text-primary); font-size:12px;"><?php echo esc_html( $issue->file_path ); ?></strong></td>
							<td><span style="font-size:11px; color:var(--sss-brand); font-family:monospace;"><?php echo esc_html( $issue->signature_name ); ?></span></td>
							<td style="font-size:13px; color:var(--sss-text-secondary);"><?php echo esc_html( $issue->details ); ?></td>
							<td>
								<?php if ( 'core_modified' === $issue->issue_type ) : ?>
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

	<!-- Automated Daily Scan Scheduling Panel -->
	<div class="supershield-panel">
		<div class="supershield-panel-header">
			<h2>Automated Scan Scheduling &amp; Continuous Defense</h2>
		</div>
		<form class="supershield-settings-form" id="supershield-scanner-settings-form">
			<input type="hidden" name="supershield_section" value="scanner">

			<div class="toggle-switch-row">
				<div class="toggle-info">
					<h4>Automated Daily Deep Scan (WP-Cron)</h4>
					<p>Executes an autonomous full multi-tier malware, core integrity, and database audit once every 24 hours. If threats are detected, an immediate email alert is dispatched to administrators.</p>
				</div>
				<label class="switch">
					<input type="hidden" name="daily_scan_cron_enabled" value="0">
					<input type="checkbox" name="daily_scan_cron_enabled" value="1" <?php checked( ! empty( $settings['daily_scan_cron_enabled'] ) ); ?>>
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
