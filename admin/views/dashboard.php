<?php
/**
 * Cybersecurity Command Center Dashboard View — SuperShield Security
 * Handcrafted Light Theme & Modern SaaS Console
 *
 * @package SuperShield_Security
 * @author  Ghulam Rasool <grwebdevs.com>
 * @version 2.2.1
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$metrics = SuperShield_DB::get_dashboard_metrics();
$score_data = SuperShield_Utils::calculate_security_score();
$last_scan = SuperShield_Utils::get_option( 'last_scan_time', 'Never' );

global $wpdb;
$events_table = SuperShield_DB::get_events_table();
$recent_events = $wpdb->get_results( "SELECT * FROM $events_table ORDER BY created_at DESC LIMIT 8" );

$scan_btn_html = '<a href="' . esc_url( admin_url( 'admin.php?page=supershield-scanner' ) ) . '" class="btn-shield-primary"><span class="dashicons dashicons-search" style="font-size:15px; width:15px; height:15px; margin-top:2px;"></span> Run Deep Scan</a>';
?>

<div class="wrap supershield-wrap">
	<?php
	SuperShield_Admin::render_navigation_header(
		'dashboard',
		'SuperShield Security',
		'Enterprise WordPress Defense-in-Depth Suite &bull; Unified Threat Management',
		$scan_btn_html
	);
	?>

	<!-- 4 Key Metric Cards -->
	<div class="supershield-grid-4">
		<div class="supershield-card">
			<div class="card-header-flex">
				<div class="card-title">Security Health Score</div>
				<div class="card-icon-pill brand">
					<span class="dashicons dashicons-shield"></span>
				</div>
			</div>
			<div class="card-value"><?php echo esc_html( $score_data['score'] ); ?>%</div>
			<div class="card-subtitle">
				<span class="status-indicator-pill success">Grade <?php echo esc_html( $score_data['grade'] ); ?></span>
				<span>Permanent Zero-Trust</span>
			</div>
		</div>

		<div class="supershield-card">
			<div class="card-header-flex">
				<div class="card-title">Attacks Dropped by WAF</div>
				<div class="card-icon-pill warning">
					<span class="dashicons dashicons-shield-alt"></span>
				</div>
			</div>
			<div class="card-value"><?php echo esc_html( number_format_i18n( $metrics['total_blocked_requests'] ) ); ?></div>
			<div class="card-subtitle">
				<span class="status-indicator-pill success">Active</span>
				<span>Deep packet heuristics</span>
			</div>
		</div>

		<div class="supershield-card">
			<div class="card-header-flex">
				<div class="card-title">Active Malware Threats</div>
				<div class="card-icon-pill <?php echo ( $metrics['active_threats'] > 0 ) ? 'danger' : 'success'; ?>">
					<span class="dashicons <?php echo ( $metrics['active_threats'] > 0 ) ? 'dashicons-warning' : 'dashicons-yes'; ?>"></span>
				</div>
			</div>
			<div class="card-value"><?php echo esc_html( $metrics['active_threats'] ); ?></div>
			<div class="card-subtitle">
				<span class="status-indicator-pill <?php echo ( $metrics['active_threats'] > 0 ) ? 'danger' : 'success'; ?>">
					<?php echo ( $metrics['active_threats'] > 0 ) ? 'Action Required' : 'Clean'; ?>
				</span>
				<span>Last Scan: <?php echo esc_html( $last_scan ); ?></span>
			</div>
		</div>

		<div class="supershield-card">
			<div class="card-header-flex">
				<div class="card-title">Failed Logins Today</div>
				<div class="card-icon-pill purple">
					<span class="dashicons dashicons-lock"></span>
				</div>
			</div>
			<div class="card-value"><?php echo esc_html( $metrics['failed_logins_today'] ); ?></div>
			<div class="card-subtitle">
				<span class="status-indicator-pill neutral"><?php echo esc_html( $metrics['active_blocked_ips'] ); ?> Locked</span>
				<span>Brute-force shield armed</span>
			</div>
		</div>
	</div>

	<!-- Main Command Center Layout -->
	<div class="supershield-main-layout">
		<!-- Left: Real-Time Incident Stream & Telemetry -->
		<div class="supershield-panel">
			<div class="supershield-panel-header">
				<h2>Live Incident Stream & Threat Telemetry</h2>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=supershield-logs' ) ); ?>" class="panel-link">View Full Audit Trail &rarr;</a>
			</div>

			<?php if ( empty( $recent_events ) ) : ?>
				<div style="padding: 40px 20px; text-align: center; color: var(--sss-text-muted);">
					<span class="dashicons dashicons-shield-alt" style="font-size: 40px; width: 40px; height: 40px; color: var(--sss-brand); margin-bottom: 12px;"></span>
					<h3 style="margin:0 0 6px 0; color:var(--sss-text-primary); font-size:16px;">Zero Incidents Logged</h3>
					<p style="margin:0; font-size:13px;">The intelligent firewall is actively neutralizing automated probes and unauthorized scans in real-time.</p>
				</div>
			<?php else : ?>
				<table class="supershield-table">
					<thead>
						<tr>
							<th>Type</th>
							<th>Client IP</th>
							<th>Incident Details</th>
							<th>Target Endpoint</th>
							<th>Time</th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $recent_events as $event ) : ?>
							<tr>
								<td>
									<?php if ( 'waf_block' === $event->event_type ) : ?>
										<span class="badge-tag critical">WAF Block</span>
									<?php elseif ( 'geoip_block' === $event->event_type ) : ?>
										<span class="badge-tag medium">GeoIP Block</span>
									<?php elseif ( 'login_fail' === $event->event_type || 'login_lockout' === $event->event_type ) : ?>
										<span class="badge-tag high">Brute Force</span>
									<?php else : ?>
										<span class="badge-tag safe"><?php echo esc_html( $event->event_type ); ?></span>
									<?php endif; ?>
								</td>
								<td><code><?php echo esc_html( $event->ip_address ); ?></code></td>
								<td style="max-width:240px; word-break:break-word; font-size:13px;"><?php echo esc_html( $event->details ); ?></td>
								<td><span style="font-size:12px; color:var(--sss-text-muted); font-family:monospace;"><?php echo esc_html( substr( $event->request_uri, 0, 32 ) . ( strlen( $event->request_uri ) > 32 ? '...' : '' ) ); ?></span></td>
								<td style="font-size:12px; color:var(--sss-text-muted); white-space:nowrap;"><?php echo esc_html( human_time_diff( strtotime( $event->created_at ), current_time( 'timestamp' ) ) . ' ago' ); ?></td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			<?php endif; ?>
		</div>

		<!-- Right: Immunity Grade & Hardening Checklist -->
		<div class="supershield-panel">
			<div class="supershield-panel-header">
				<h2>Defense-in-Depth Status</h2>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=supershield-hardening' ) ); ?>" class="panel-link">Hardening &rarr;</a>
			</div>

			<div class="security-score-container">
				<div class="security-grade-badge <?php echo ( $score_data['score'] < 70 ) ? 'grade-f' : ''; ?>">
					<?php echo esc_html( $score_data['grade'] ); ?>
				</div>
				<div class="score-details">
					<h3><?php echo esc_html( $score_data['score'] ); ?> / 100 Points</h3>
					<p>Permanent Zero-Trust Hardening Score</p>
				</div>
			</div>

			<ul class="check-list">
				<?php foreach ( $score_data['checks'] as $check ) : ?>
					<li class="check-item">
						<span><?php echo esc_html( $check['label'] ); ?></span>
						<?php if ( 'pass' === $check['status'] ) : ?>
							<span class="check-badge pass">&#10003; +<?php echo esc_html( $check['pts'] ); ?> pts</span>
						<?php elseif ( 'optional' === $check['status'] ) : ?>
							<span class="check-badge optional">Optional</span>
						<?php else : ?>
							<span class="check-badge fail">Needs Fix</span>
						<?php endif; ?>
					</li>
				<?php endforeach; ?>
			</ul>
		</div>
	</div>

	<?php SuperShield_Admin::render_footer(); ?>
</div>