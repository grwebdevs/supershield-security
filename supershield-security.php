<?php
/**
 * Plugin Name:       SuperShield Security (SSS)
 * Plugin URI:        https://SSS.grwebdevs.com
 * Description:       Enterprise WordPress Defense-in-Depth Suite. Real-Time Intelligent WAF, Zero-False-Positive Deep Scanner with 1-Click Surgical Disinfection, 8-Layer Server Hardening, Enterprise TOTP 2FA, Offline GeoIP Blocking, and GitHub Releases Auto-Updater.
 * Version:           2.5.0
 * Author:            Ghulam Rasool (Founder & Principal Security Engineer, grwebdevs.com)
 * Author URI:        https://grwebdevs.com
 * License:           GPL-2.0+
 * License URI:       http://www.gnu.org/licenses/gpl-2.0.txt
 * Text Domain:       supershield-security
 * Domain Path:       /languages
 * Requires at least: 5.8
 * Requires PHP:      7.4
 *
 * @package           SuperShield_Security
 */

// If this file is called directly, abort.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Define Plugin Version & Constants
define( 'SUPERSHIELD_VERSION', '2.5.0' );
define( 'SUPERSHIELD_PLUGIN_FILE', __FILE__ );
define( 'SUPERSHIELD_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'SUPERSHIELD_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'SUPERSHIELD_BASENAME', plugin_basename( __FILE__ ) );

/**
 * Autoload core classes.
 */
require_once SUPERSHIELD_PLUGIN_DIR . 'includes/class-supershield-utils.php';
require_once SUPERSHIELD_PLUGIN_DIR . 'includes/class-supershield-db.php';
require_once SUPERSHIELD_PLUGIN_DIR . 'includes/class-supershield-ip-manager.php';
require_once SUPERSHIELD_PLUGIN_DIR . 'includes/class-supershield-geoip.php';
require_once SUPERSHIELD_PLUGIN_DIR . 'includes/class-supershield-waf.php';
require_once SUPERSHIELD_PLUGIN_DIR . 'includes/class-supershield-cleaner.php';
require_once SUPERSHIELD_PLUGIN_DIR . 'includes/class-supershield-vuln-scanner.php';
require_once SUPERSHIELD_PLUGIN_DIR . 'includes/class-supershield-scanner.php';
require_once SUPERSHIELD_PLUGIN_DIR . 'includes/class-supershield-hardening.php';
require_once SUPERSHIELD_PLUGIN_DIR . 'includes/class-supershield-login-security.php';
require_once SUPERSHIELD_PLUGIN_DIR . 'includes/class-supershield-qrcode.php';
require_once SUPERSHIELD_PLUGIN_DIR . 'includes/class-supershield-2fa.php';
require_once SUPERSHIELD_PLUGIN_DIR . 'includes/class-supershield-woocommerce.php';
require_once SUPERSHIELD_PLUGIN_DIR . 'includes/class-supershield-updater.php';
require_once SUPERSHIELD_PLUGIN_DIR . 'includes/class-supershield-antitamper.php';
require_once SUPERSHIELD_PLUGIN_DIR . 'includes/class-supershield-telemetry.php';
require_once SUPERSHIELD_PLUGIN_DIR . 'includes/class-supershield-notifier.php';
require_once SUPERSHIELD_PLUGIN_DIR . 'includes/class-supershield-activator.php';
require_once SUPERSHIELD_PLUGIN_DIR . 'includes/class-supershield-deactivator.php';
require_once SUPERSHIELD_PLUGIN_DIR . 'includes/class-supershield-core.php';

if ( is_admin() ) {
	require_once SUPERSHIELD_PLUGIN_DIR . 'admin/class-supershield-admin.php';
}

/**
 * The code that runs during plugin activation.
 */
function activate_supershield_security() {
	SuperShield_Activator::activate();
}

/**
 * The code that runs during plugin deactivation.
 */
function deactivate_supershield_security() {
	SuperShield_Deactivator::deactivate();
}

register_activation_hook( __FILE__, 'activate_supershield_security' );
register_deactivation_hook( __FILE__, 'deactivate_supershield_security' );

/**
 * Begins execution of the plugin.
 */
function run_supershield_security() {
	$plugin = SuperShield_Core::get_instance();
	$plugin->run();
}

run_supershield_security();
