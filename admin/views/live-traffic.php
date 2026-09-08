<?php
/**
 * Live Traffic & Security Logs View — SuperShield Security
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
$events_table = SuperShield_DB::get_events_table();
$filter_type = isset( $_GET['filter_type'] ) ? sanitize_text_field( wp_unslash( $_GET['filter_type'] ) ) : '';

if ( 'threats' === $filter_type ) {
	$events = $wpdb->get_results( "SELECT * FROM $events_table WHERE event_type IN ('waf_block', 'geoip_block', 'tamper_alert') ORDER BY created_at DESC LIMIT 100" );
} elseif ( 'logins' === $filter_type ) {
	$events = $wpdb->get_results( "SELECT * FROM $events_table WHERE event_type IN ('login_success', 'login_fail', 'login_lockout') ORDER BY created_at DESC LIMIT 100" );
} elseif ( 'admin' === $filter_type ) {
	$events = $wpdb->get_results( "SELECT * FROM $events_table WHERE event_type = 'admin_action' ORDER BY created_at DESC LIMIT 100" );
} elseif ( ! empty( $filter_type ) ) {
	$events = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM $events_table WHERE event_type = %s ORDER BY created_at DESC LIMIT 100", $filter_type ) );
} else {
	$events = $wpdb->get_results( "SELECT * FROM $events_table ORDER BY created_at DESC LIMIT 100" );
}

$clear_btn_html = '<button type="button" id="btn-clear-supershield-logs" class="btn-shield-danger"><span class="dashicons dashicons-trash" style="font-size:15px; width:15px; height:15px; margin-top:2px;"></span> Clear Audit Trail</button>';
?>

<div class="wrap supershield-wrap">
	<?php
	SuperShield_Admin::render_navigation_header(
		'logs',
		'Security Audit & Live Threat Stream',
		'High-throughput telemetry of WAF drops, GeoIP blocks, brute-force stops, and admin actions',
		$clear_btn_html
	);
	?>

	<div class="supershield-filter-tabs">
		<a href="<?php echo esc_url( admin_url( 'admin.php?page=supershield-logs' ) ); ?>" class="filter-tab-pill <?php echo empty( $filter_type ) ? 'active' : ''; ?>">
			<span class="dashicons dashicons-visibility" style="font-size:14px; width:14px; height:14px;"></span> All Telemetry
		</a>
		<a href="<?php echo esc_url( admin_url( 'admin.php?page=supershield-logs&filter_type=threats' ) ); ?>" class="filter-tab-pill <?php echo ( 'threats' === $filter_type ) ? 'active' : ''; ?>">
			<span class="dashicons dashicons-shield-alt" style="font-size:14px; width:14px; height:14px;"></span> Threat Blocks
		</a>
		<a href="<?php echo esc_url( admin_url( 'admin.php?page=supershield-logs&filter_type=logins' ) ); ?>" class="filter-tab-pill <?php echo ( 'logins' === $filter_type ) ? 'active' : ''; ?>">
			<span class="dashicons dashicons-admin-users" style="font-size:14px; width:14px; height:14px;"></span> Auth Audit
		</a>
		<a href="<?php echo esc_url( admin_url( 'admin.php?page=supershield-logs&filter_type=admin' ) ); ?>" class="filter-tab-pill <?php echo ( 'admin' === $filter_type ) ? 'active' : ''; ?>">
			<span class="dashicons dashicons-admin-generic" style="font-size:14px; width:14px; height:14px;"></span> Admin Actions
		</a>
	</div>

	<div class="supershield-panel">
		<div class="supershield-panel-header">
			<h2>Event Trail (Latest 100 Records)</h2>
			<div>
				<form method="get" style="display:inline-flex; gap:8px;">
					<input type="hidden" name="page" value="supershield-logs" />
					<select name="filter_type" onchange="this.form.submit()" style="font-size:13px; background:#ffffff; color:var(--sss-text-primary); border:1px solid #cbd5e1; border-radius:6px; padding:6px 10px;">
						<option value="">Specific Filter...</option>
						<option value="waf_block" <?php selected( $filter_type, 'waf_block' ); ?>>WAF Block</option>
						<option value="geoip_block" <?php selected( $filter_type, 'geoip_block' ); ?>>GeoIP Block</option>
						<option value="rate_limit_drop" <?php selected( $filter_type, 'rate_limit_drop' ); ?>>Rate Limit Drop</option>
						<option value="login_fail" <?php selected( $filter_type, 'login_fail' ); ?>>Login Failure</option>
						<option value="login_lockout" <?php selected( $filter_type, 'login_lockout' ); ?>>Login Lockout</option>
						<option value="login_success" <?php selected( $filter_type, 'login_success' ); ?>>Login Success</option>
						<option value="tamper_alert" <?php selected( $filter_type, 'tamper_alert' ); ?>>Tamper Alert</option>
						<option value="admin_action" <?php selected( $filter_type, 'admin_action' ); ?>>Administrative Action</option>
					</select>
				</form>
			</div>
		</div>

		<?php if ( empty( $events ) ) : ?>
			<p style="color: var(--sss-text-muted); font-style: italic; padding: 30px 0; text-align: center; margin:0;">No log records matching your filter criteria.</p>
		<?php else : ?>
			<table class="supershield-table">
				<thead>
					<tr>
						<th>Event Classification</th>
						<th>Client IP &amp; Geolocation</th>
						<th>Method &amp; Targeted Endpoint</th>
						<th>Incident Details</th>
						<th>Offending Payload Snippet</th>
						<th>Timestamp</th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $events as $row ) : ?>
						<?php
						$country_code = SuperShield_GeoIP::resolve_country( $row->ip_address );
						$country_name = SuperShield_GeoIP::get_country_name( $country_code );
						?>
						<tr>
							<td>
								<?php if ( 'waf_block' === $row->event_type || 'rate_limit_drop' === $row->event_type ) : ?>
									<span class="badge-tag critical"><?php echo esc_html( 'rate_limit_drop' === $row->event_type ? 'Rate Limit' : 'WAF Block' ); ?></span>
								<?php elseif ( 'geoip_block' === $row->event_type ) : ?>
									<span class="badge-tag medium">GeoIP Block</span>
								<?php elseif ( 'login_lockout' === $row->event_type || 'tamper_alert' === $row->event_type ) : ?>
									<span class="badge-tag critical"><?php echo esc_html( strtoupper( $row->event_type ) ); ?></span>
								<?php elseif ( 'login_fail' === $row->event_type ) : ?>
									<span class="badge-tag high">Auth Fail</span>
								<?php elseif ( 'login_success' === $row->event_type ) : ?>
									<span class="badge-tag safe">Success</span>
								<?php else : ?>
									<span class="badge-tag info"><?php echo esc_html( $row->event_type ); ?></span>
								<?php endif; ?>
							</td>
							<td>
								<div style="font-weight:600; font-family:monospace;"><?php echo esc_html( $row->ip_address ); ?></div>
								<div style="font-size:11px; color:var(--sss-text-muted); display:flex; align-items:center; gap:4px; margin-top:2px;">
									<span class="dashicons dashicons-admin-site" style="font-size:12px; width:12px; height:12px;"></span>
									<span><?php echo esc_html( $country_name . ( 'XX' !== $country_code && 'LOCAL' !== $country_code ? ' (' . $country_code . ')' : '' ) ); ?></span>
								</div>
							</td>
							<td>
								<strong style="color:var(--sss-brand); font-size:12px;"><?php echo esc_html( $row->request_method ); ?></strong> 
								<span style="font-size:12px; color:var(--sss-text-secondary); word-break:break-all; font-family:monospace;"><?php echo esc_html( $row->request_uri ); ?></span>
							</td>
							<td style="font-size:13px; color:var(--sss-text-secondary);"><?php echo esc_html( $row->details ); ?></td>
							<td>
								<?php if ( ! empty( $row->payload ) ) : ?>
									<code style="font-size:11px; color:#b91c1c; background:#fef2f2; border-color:#fecaca; font-family:ui-monospace, monospace;"><?php echo esc_html( substr( $row->payload, 0, 75 ) . ( strlen( $row->payload ) > 75 ? '...' : '' ) ); ?></code>
								<?php else : ?>
									<span style="color:var(--sss-text-muted); font-size:12px;">&mdash;</span>
								<?php endif; ?>
							</td>
							<td style="font-size:12px; color:var(--sss-text-muted); white-space:nowrap;"><?php echo esc_html( $row->created_at ); ?></td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
		<?php endif; ?>
	</div>

	<?php SuperShield_Admin::render_footer(); ?>
</div>
