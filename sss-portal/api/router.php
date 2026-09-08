<?php
/**
 * SuperShield Security — Central REST API Hub Router
 * 
 * Handles:
 *  - /api/v1/updates
 *  - /api/v1/feedback
 *  - /api/v1/telemetry
 *  - /api/v1/threats/feed
 * 
 * @package SuperShield_Portal
 * @author  Ghulam Rasool <grwebdevs.com>
 */

defined('SSS_ACCESS') or define('SSS_ACCESS', true);

require_once __DIR__ . '/../database/db.php';
require_once __DIR__ . '/../includes/mailer.php';

class SSS_API_Router {

    /**
     * Dispatch incoming API request.
     */
    public static function dispatch($endpoint) {
        header('Content-Type: application/json; charset=utf-8');
        header('Access-Control-Allow-Origin: *');
        header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
        header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With');

        if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
            http_response_code(200);
            exit;
        }

        switch ($endpoint) {
            case 'updates':
                self::handle_updates();
                break;

            case 'feedback':
                self::handle_feedback();
                break;

            case 'telemetry':
                self::handle_telemetry();
                break;

            case 'threats_feed':
            case 'threats/feed':
                self::handle_threats_feed();
                break;

            default:
                http_response_code(404);
                echo json_encode(array(
                    'error'   => true,
                    'message' => 'Invalid SuperShield API endpoint: ' . htmlspecialchars($endpoint),
                ));
                break;
        }
        exit;
    }

    /**
     * Handle updates endpoint (/api/v1/updates)
     * Rate-limited proxy & cache for GitHub releases.
     */
    private static function handle_updates() {
        $config = require __DIR__ . '/../config.php';
        $cache_file = sys_get_temp_dir() . '/sss_release_cache.json';

        // Check 1-hour cache
        if (file_exists($cache_file) && (time() - filemtime($cache_file) < 3600)) {
            $cached = @file_get_contents($cache_file);
            if (!empty($cached)) {
                echo $cached;
                return;
            }
        }

        // Fetch from GitHub
        $ch = curl_init('https://api.github.com/repos/' . $config['github_repo'] . '/releases/latest');
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_USERAGENT, 'SuperShield-Cloud-Proxy/2.1.0 (grwebdevs.com)');
        curl_setopt($ch, CURLOPT_TIMEOUT, 6);
        $response = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($http_code === 200 && !empty($response)) {
            @file_put_contents($cache_file, $response);
            echo $response;
            return;
        }

        // Fallback release metadata if GitHub is down or rate-limited
        $fallback = array(
            'tag_name'     => 'v' . $config['app_version'],
            'name'         => 'SuperShield Security v' . $config['app_version'] . ' — Enterprise Release',
            'zipball_url'  => $config['fallback_download_url'],
            'html_url'     => 'https://github.com/' . $config['github_repo'],
            'published_at' => date('Y-m-d\TH:i:s\Z'),
            'body'         => "### SuperShield Security v" . $config['app_version'] . "\n- 100% Free Zero-Day WAF Protection\n- 1-Click Surgical Malware Cleaner\n- Native TOTP Two-Factor Authentication\n- Offline ISO-3166 GeoIP Country Blocking\n- HMAC-SHA256 Anti-Tamper Core Guard\n- Enterprise WordPress Hardening Suite\n\nLead Architect: Ghulam Rasool (grwebdevs.com)",
            'assets'       => array(
                array(
                    'name'                 => 'supershield-security.zip',
                    'browser_download_url' => $config['site_url'] . '/download/latest',
                )
            ),
        );

        echo json_encode($fallback, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }

    /**
     * Handle feedback endpoint (/api/v1/feedback)
     * Ingests bug reports & reviews from WordPress plugins, emails Ghulam Rasool.
     */
    private static function handle_feedback() {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            echo json_encode(array('success' => false, 'message' => 'Method not allowed. Use POST.'));
            return;
        }

        $raw = file_get_contents('php://input');
        $data = json_decode($raw, true);

        if (!is_array($data) || empty($data['message'])) {
            http_response_code(400);
            echo json_encode(array('success' => false, 'message' => 'Feedback message is required.'));
            return;
        }

        // Store in database
        $ticket_id = SSS_Database::insert_feedback($data);

        // Send instant notification email to Ghulam Rasool
        SSS_Mailer::send_admin_feedback_alert($data, $ticket_id);

        echo json_encode(array(
            'success'   => true,
            'ticket_id' => $ticket_id,
            'message'   => 'Thank you! Your feedback has been safely received by Ghulam Rasool and the SuperShield team.',
        ));
    }

    /**
     * Handle telemetry endpoint (/api/v1/telemetry)
     * Ingests anonymous threat signatures.
     */
    private static function handle_telemetry() {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            echo json_encode(array('success' => false, 'message' => 'Method not allowed.'));
            return;
        }

        $raw = file_get_contents('php://input');
        $data = json_decode($raw, true);

        if (is_array($data) && !empty($data['threat_type']) && !empty($data['signature'])) {
            SSS_Database::record_threat(
                $data['threat_type'],
                $data['signature'],
                $data['endpoint'] ?? ''
            );
        }

        echo json_encode(array('success' => true));
    }

    /**
     * Handle public threat feed (/api/v1/threats/feed)
     */
    private static function handle_threats_feed() {
        $recent = SSS_Database::get_recent_threats(15);
        $metrics = SSS_Database::get_metrics();

        echo json_encode(array(
            'metrics' => $metrics,
            'threats' => $recent,
        ));
    }
}
