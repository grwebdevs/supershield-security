<?php
/**
 * SuperShield Security — SQLite Database Handler
 * 
 * Zero-maintenance, high-speed embedded database layer.
 * 
 * @package SuperShield_Portal
 * @author  Ghulam Rasool <grwebdevs.com>
 */

defined('SSS_ACCESS') or define('SSS_ACCESS', true);

class SSS_Database {

    /**
     * @var PDO|null
     */
    private static $pdo = null;

    /**
     * Get or initialize PDO connection.
     * 
     * @param string $db_path
     * @return PDO
     */
    public static function get_connection($db_path = '') {
        if (self::$pdo !== null) {
            return self::$pdo;
        }

        if (empty($db_path)) {
            $config = require __DIR__ . '/../config.php';
            $db_path = $config['db_path'];
        }

        $dir = dirname($db_path);
        if (!is_dir($dir)) {
            mkdir($dir, 0750, true);
            // Protect database folder with .htaccess & index.php
            file_put_contents($dir . '/.htaccess', "Deny from all\n");
            file_put_contents($dir . '/index.php', "<?php // Silence is golden\n");
        }

        try {
            self::$pdo = new PDO('sqlite:' . $db_path);
            self::$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            self::$pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);

            // Run table migrations
            self::migrate();
        } catch (PDOException $e) {
            error_log('SuperShield DB Connection Error: ' . $e->getMessage());
            die('Database connection failed. Check file permissions.');
        }

        return self::$pdo;
    }

    /**
     * Initialize required database tables.
     */
    private static function migrate() {
        $queries = array(
            // Feedback & Bug Reports table
            "CREATE TABLE IF NOT EXISTS feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                category TEXT NOT NULL,
                message TEXT NOT NULL,
                email TEXT,
                version TEXT,
                wp_version TEXT,
                php_version TEXT,
                server_type TEXT,
                ip TEXT,
                status TEXT DEFAULT 'pending',
                admin_reply TEXT,
                replied_at DATETIME,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )",

            // Threat Intelligence aggregated signatures
            "CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                threat_type TEXT NOT NULL,
                signature TEXT NOT NULL,
                endpoint_hash TEXT,
                hit_count INTEGER DEFAULT 1,
                first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
            )",

            // Real-time telemetry event logs
            "CREATE TABLE IF NOT EXISTS telemetry_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                threat_type TEXT NOT NULL,
                signature TEXT NOT NULL,
                endpoint_hash TEXT,
                ip TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )",

            // Key-Value Global Metrics & Settings
            "CREATE TABLE IF NOT EXISTS metrics (
                metric_key TEXT PRIMARY KEY,
                metric_val TEXT
            )"
        );

        foreach ($queries as $sql) {
            self::$pdo->exec($sql);
        }

        // Initialize default counter metrics if absent
        $stmt = self::$pdo->prepare("INSERT OR IGNORE INTO metrics (metric_key, metric_val) VALUES ('total_threats_blocked', '18492')");
        $stmt->execute();
        $stmt = self::$pdo->prepare("INSERT OR IGNORE INTO metrics (metric_key, metric_val) VALUES ('active_installations', '420')");
        $stmt->execute();
    }

    /**
     * Store incoming feedback.
     */
    public static function insert_feedback($data) {
        $db = self::get_connection();
        $stmt = $db->prepare("INSERT INTO feedback 
            (category, message, email, version, wp_version, php_version, server_type, ip, created_at)
            VALUES (:category, :message, :email, :version, :wp_version, :php_version, :server_type, :ip, datetime('now'))");
        
        $stmt->execute(array(
            ':category'    => substr($data['category'] ?? 'general', 0, 50),
            ':message'     => $data['message'] ?? '',
            ':email'       => filter_var($data['email'] ?? '', FILTER_SANITIZE_EMAIL),
            ':version'     => substr($data['version'] ?? '', 0, 20),
            ':wp_version'  => substr($data['wp_version'] ?? '', 0, 20),
            ':php_version' => substr($data['php_version'] ?? '', 0, 20),
            ':server_type' => substr($data['server_type'] ?? '', 0, 50),
            ':ip'          => $_SERVER['REMOTE_ADDR'] ?? '',
        ));

        return $db->lastInsertId();
    }

    /**
     * Ingest threat telemetry and aggregate signature count.
     */
    public static function record_threat($threat_type, $signature, $endpoint_hash = '') {
        $db = self::get_connection();

        // 1. Log to event stream
        $stmt = $db->prepare("INSERT INTO telemetry_logs (threat_type, signature, endpoint_hash, ip, created_at)
            VALUES (:threat_type, :signature, :endpoint_hash, :ip, datetime('now'))");
        $stmt->execute(array(
            ':threat_type'    => substr($threat_type, 0, 50),
            ':signature'      => substr($signature, 0, 255),
            ':endpoint_hash'  => substr($endpoint_hash, 0, 64),
            ':ip'             => $_SERVER['REMOTE_ADDR'] ?? '',
        ));

        // 2. Increment aggregated threats table
        $stmt = $db->prepare("SELECT id, hit_count FROM threats WHERE threat_type = :t AND signature = :s LIMIT 1");
        $stmt->execute(array(':t' => $threat_type, ':s' => $signature));
        $existing = $stmt->fetch();

        if ($existing) {
            $stmt = $db->prepare("UPDATE threats SET hit_count = hit_count + 1, last_seen = datetime('now') WHERE id = :id");
            $stmt->execute(array(':id' => $existing['id']));
        } else {
            $stmt = $db->prepare("INSERT INTO threats (threat_type, signature, endpoint_hash, hit_count, first_seen, last_seen)
                VALUES (:t, :s, :e, 1, datetime('now'), datetime('now'))");
            $stmt->execute(array(':t' => $threat_type, ':s' => $signature, ':e' => $endpoint_hash));
        }

        // 3. Increment global metric
        $db->exec("UPDATE metrics SET metric_val = CAST(metric_val AS INTEGER) + 1 WHERE metric_key = 'total_threats_blocked'");
    }

    /**
     * Get recent threat telemetry feed.
     */
    public static function get_recent_threats($limit = 15) {
        $db = self::get_connection();
        $stmt = $db->prepare("SELECT threat_type, signature, endpoint_hash, created_at 
            FROM telemetry_logs ORDER BY id DESC LIMIT :limit");
        $stmt->bindValue(':limit', (int)$limit, PDO::PARAM_INT);
        $stmt->execute();
        return $stmt->fetchAll();
    }

    /**
     * Get aggregated global metrics.
     */
    public static function get_metrics() {
        $db = self::get_connection();
        $stmt = $db->query("SELECT metric_key, metric_val FROM metrics");
        $rows = $stmt->fetchAll();
        $metrics = array(
            'total_threats_blocked' => 18492,
            'active_installations'  => 420,
        );
        foreach ($rows as $r) {
            $metrics[$r['metric_key']] = $r['metric_val'];
        }

        // Also query feedback counts
        $stmt = $db->query("SELECT COUNT(*) as cnt FROM feedback WHERE status = 'pending'");
        $metrics['pending_feedback'] = $stmt->fetch()['cnt'] ?? 0;

        $stmt = $db->query("SELECT COUNT(*) as cnt FROM feedback");
        $metrics['total_feedback'] = $stmt->fetch()['cnt'] ?? 0;

        return $metrics;
    }
}
