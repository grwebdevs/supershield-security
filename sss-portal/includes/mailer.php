<?php
/**
 * SuperShield Security — Native Server Mailer
 * 
 * High-reliability native server email dispatcher.
 * Uses local Postfix/Sendmail with zero external SMTP dependencies.
 * 
 * @package SuperShield_Portal
 * @author  Ghulam Rasool <grwebdevs.com>
 */

defined('SSS_ACCESS') or define('SSS_ACCESS', true);

class SSS_Mailer {

    /**
     * Dispatch notification to SuperShield Admin when new feedback arrives.
     * 
     * @param array $data
     * @param int   $ticket_id
     * @return bool
     */
    public static function send_admin_feedback_alert($data, $ticket_id) {
        $config = require __DIR__ . '/../config.php';
        $admin_email = $config['admin_email'];
        $from_email  = $config['system_from_email'];

        $category = strtoupper(str_replace('_', ' ', $data['category'] ?? 'FEEDBACK'));
        $subject  = "[SuperShield Alert] New {$category} #{$ticket_id} from " . (!empty($data['email']) ? $data['email'] : 'WordPress Site');

        $user_email = !empty($data['email']) ? htmlspecialchars($data['email']) : 'Not Provided';
        $wp_ver     = htmlspecialchars($data['wp_version'] ?? 'N/A');
        $php_ver    = htmlspecialchars($data['php_version'] ?? 'N/A');
        $server     = htmlspecialchars($data['server_type'] ?? 'N/A');
        $version    = htmlspecialchars($data['version'] ?? '2.1.0');
        $message    = nl2br(htmlspecialchars($data['message'] ?? ''));
        $panel_url  = $config['site_url'] . '/panel?ticket=' . $ticket_id;

        $body = "
<!DOCTYPE html>
<html>
<head>
<meta charset='utf-8'>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0b0f19; color: #f3f4f6; margin: 0; padding: 20px; }
  .container { max-width: 600px; margin: 0 auto; background: #131b2e; border: 1px solid #1e293b; border-radius: 10px; overflow: hidden; }
  .header { background: #0f172a; padding: 25px; border-bottom: 2px solid #10b981; text-align: center; }
  .header h1 { margin: 0; color: #ffffff; font-size: 20px; letter-spacing: 0.5px; }
  .badge { display: inline-block; padding: 4px 12px; border-radius: 999px; font-size: 11px; font-weight: 700; text-transform: uppercase; background: #10b981; color: #022c22; margin-top: 8px; }
  .badge-bug { background: #ef4444; color: #ffffff; }
  .content { padding: 30px; }
  .quote-box { background: #1e293b; border-left: 4px solid #38bdf8; padding: 15px; border-radius: 4px; margin: 20px 0; color: #e2e8f0; font-size: 15px; line-height: 1.6; }
  .meta-table { width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 13px; }
  .meta-table td { padding: 8px 12px; border-bottom: 1px solid #1e293b; }
  .meta-label { color: #94a3b8; width: 35%; font-weight: 600; }
  .meta-val { color: #f8fafc; font-family: monospace; }
  .btn-wrap { text-align: center; margin: 30px 0 10px; }
  .btn { display: inline-block; padding: 12px 28px; background: #10b981; color: #022c22; text-decoration: none; font-weight: 700; border-radius: 6px; font-size: 14px; }
  .footer { background: #0b0f19; padding: 15px; text-align: center; font-size: 12px; color: #64748b; border-top: 1px solid #1e293b; }
</style>
</head>
<body>
<div class='container'>
  <div class='header'>
    <h1>🛡️ SuperShield Security</h1>
    <span class='badge " . (stripos($category, 'BUG') !== false ? 'badge-bug' : '') . "'>{$category}</span>
  </div>
  <div class='content'>
    <p style='margin-top:0; color:#94a3b8; font-size:14px;'>A new feedback report was submitted from an active SuperShield installation:</p>
    
    <div class='quote-box'>
      {$message}
    </div>

    <table class='meta-table'>
      <tr><td class='meta-label'>User Contact</td><td class='meta-val'>{$user_email}</td></tr>
      <tr><td class='meta-label'>SuperShield Version</td><td class='meta-val'>v{$version}</td></tr>
      <tr><td class='meta-label'>WordPress Version</td><td class='meta-val'>{$wp_ver}</td></tr>
      <tr><td class='meta-label'>PHP Version</td><td class='meta-val'>{$php_ver}</td></tr>
      <tr><td class='meta-label'>Web Server</td><td class='meta-val'>{$server}</td></tr>
    </table>

    <div class='btn-wrap'>
      <a href='{$panel_url}' class='btn'>Open Command Center & Reply &rarr;</a>
    </div>
  </div>
  <div class='footer'>
    SuperShield Security Hub &bull; Lead Architect: Ghulam Rasool (<a href='https://grwebdevs.com' style='color:#38bdf8;'>grwebdevs.com</a>)
  </div>
</div>
</body>
</html>
";

        $headers   = array();
        $headers[] = 'MIME-Version: 1.0';
        $headers[] = 'Content-type: text/html; charset=utf-8';
        $headers[] = 'From: SuperShield Security <' . $from_email . '>';
        if (!empty($data['email']) && filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
            $headers[] = 'Reply-To: ' . $data['email'];
        }
        $headers[] = 'X-Mailer: SuperShield-Platform/2.1.0';

        // Send to primary admin
        @mail($admin_email, $subject, $body, implode("\r\n", $headers));

        // Send to secondary email if configured
        if (!empty($config['admin_email_alt']) && $config['admin_email_alt'] !== $admin_email) {
            @mail($config['admin_email_alt'], $subject, $body, implode("\r\n", $headers));
        }

        return true;
    }

    /**
     * Send email response from Admin to user.
     * 
     * @param string $to_email
     * @param string $reply_text
     * @param string $original_msg
     * @param int    $ticket_id
     * @return bool
     */
    public static function send_user_reply($to_email, $reply_text, $original_msg = '', $ticket_id = 0) {
        $config = require __DIR__ . '/../config.php';
        $from_email  = $config['system_from_email'];
        $reply_to    = $config['admin_email'];

        $subject = "[SuperShield Security] Response to your Ticket #{$ticket_id}";
        $formatted_reply = nl2br(htmlspecialchars($reply_text));
        $formatted_orig  = nl2br(htmlspecialchars(substr($original_msg, 0, 300)));

        $body = "
<!DOCTYPE html>
<html>
<head>
<meta charset='utf-8'>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0b0f19; color: #f3f4f6; margin: 0; padding: 20px; }
  .container { max-width: 600px; margin: 0 auto; background: #131b2e; border: 1px solid #1e293b; border-radius: 10px; overflow: hidden; }
  .header { background: #0f172a; padding: 25px; border-bottom: 2px solid #10b981; text-align: center; }
  .header h1 { margin: 0; color: #ffffff; font-size: 20px; letter-spacing: 0.5px; }
  .content { padding: 30px; }
  .reply-box { background: #1e293b; border-left: 4px solid #10b981; padding: 18px; border-radius: 4px; margin: 20px 0; color: #f8fafc; font-size: 15px; line-height: 1.6; }
  .orig-box { background: #0f172a; padding: 12px; border-radius: 4px; color: #94a3b8; font-size: 13px; margin-top: 25px; border: 1px dashed #334155; }
  .footer { background: #0b0f19; padding: 18px; text-align: center; font-size: 12px; color: #64748b; border-top: 1px solid #1e293b; }
</style>
</head>
<body>
<div class='container'>
  <div class='header'>
    <h1>🛡️ SuperShield Security Support</h1>
  </div>
  <div class='content'>
    <p style='color:#e2e8f0; font-size:15px; margin-top:0;'>Hello,</p>
    <p style='color:#cbd5e1; font-size:14px;'>Ghulam Rasool has reviewed your report and replied with the following update:</p>
    
    <div class='reply-box'>
      {$formatted_reply}
    </div>

    <p style='font-size:13px; color:#94a3b8;'>You can reply directly to this email if you have any follow-up questions.</p>

    " . (!empty($formatted_orig) ? "
    <div class='orig-box'>
      <strong style='color:#cbd5e1;'>Your original inquiry:</strong><br>
      {$formatted_orig}...
    </div>" : "") . "
  </div>
  <div class='footer'>
    Sent by <strong>Ghulam Rasool</strong> &bull; Founder & Lead Security Engineer<br>
    <a href='https://grwebdevs.com' style='color:#38bdf8; text-decoration:none;'>GR Web Devs</a> &bull; <a href='https://sss.grwebdevs.com' style='color:#10b981; text-decoration:none;'>SuperShield Security</a>
  </div>
</div>
</body>
</html>
";

        $headers   = array();
        $headers[] = 'MIME-Version: 1.0';
        $headers[] = 'Content-type: text/html; charset=utf-8';
        $headers[] = 'From: Ghulam Rasool <' . $from_email . '>';
        $headers[] = 'Reply-To: Ghulam Rasool <' . $reply_to . '>';
        $headers[] = 'X-Mailer: SuperShield-Platform/2.1.0';

        return @mail($to_email, $subject, $body, implode("\r\n", $headers));
    }

    /**
     * Send 2FA One-Time Verification Code (OTP) to Admin email.
     *
     * @param string $to_email
     * @param string $code
     * @param string $ip
     * @param string $user_agent
     * @return bool
     */
    public static function send_2fa_code($to_email, $code, $ip, $user_agent) {
        $config = require __DIR__ . '/../config.php';
        $from_email = $config['system_from_email'];

        $subject = "[SuperShield Security] Your Command Center 2FA Code: {$code}";
        $timestamp = gmdate('Y-m-d H:i:s') . ' UTC';
        $browser = htmlspecialchars(substr($user_agent, 0, 80));

        $body = "
<!DOCTYPE html>
<html>
<head>
<meta charset='utf-8'>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #0b0f19; color: #f3f4f6; margin: 0; padding: 25px; }
  .container { max-width: 540px; margin: 0 auto; background: #131b2e; border: 1px solid #1e293b; border-radius: 12px; overflow: hidden; }
  .header { background: #0f172a; padding: 25px; text-align: center; border-bottom: 2px solid #10b981; }
  .header h1 { margin: 0; color: #ffffff; font-size: 20px; letter-spacing: 0.5px; }
  .content { padding: 30px; text-align: center; }
  .code-box { background: #0b0f19; border: 2px dashed #10b981; border-radius: 10px; padding: 18px; margin: 25px 0; font-family: monospace; font-size: 36px; font-weight: 800; letter-spacing: 8px; color: #10b981; }
  .meta-box { background: #0f172a; border-radius: 8px; padding: 14px; margin-top: 25px; text-align: left; font-size: 12px; color: #94a3b8; line-height: 1.6; }
  .footer { background: #0b0f19; padding: 16px; text-align: center; font-size: 12px; color: #64748b; border-top: 1px solid #1e293b; }
</style>
</head>
<body>
<div class='container'>
  <div class='header'>
    <h1>🛡️ SuperShield Security 2FA</h1>
  </div>
  <div class='content'>
    <p style='color:#cbd5e1; font-size:15px; margin:0;'>Hello Ghulam,</p>
    <p style='color:#94a3b8; font-size:14px; margin:8px 0 0;'>Use the single-use 6-digit verification code below to authorize your session:</p>
    
    <div class='code-box'>{$code}</div>

    <p style='font-size:13px; color:#f59e0b; margin:0;'>⏳ This code expires in 10 minutes. Do not share it with anyone.</p>

    <div class='meta-box'>
      <strong style='color:#f8fafc;'>Sign-In Security Details:</strong><br>
      &bull; <strong>IP Address:</strong> {$ip}<br>
      &bull; <strong>Device:</strong> {$browser}<br>
      &bull; <strong>Time:</strong> {$timestamp}
    </div>
  </div>
  <div class='footer'>
    SuperShield Command Center &bull; grwebdevs.com
  </div>
</div>
</body>
</html>
";

        $headers   = array();
        $headers[] = 'MIME-Version: 1.0';
        $headers[] = 'Content-type: text/html; charset=utf-8';
        $headers[] = 'From: SuperShield Security <' . $from_email . '>';
        $headers[] = 'X-Mailer: SuperShield-Platform/2.1.0';

        return @mail($to_email, $subject, $body, implode("\r\n", $headers));
    }

    /**
     * Dispatch instant Login Alert email on successful access.
     *
     * @param string $to_email
     * @param string $username
     * @param string $ip
     * @param string $user_agent
     * @return bool
     */
    public static function send_login_alert($to_email, $username, $ip, $user_agent) {
        $config = require __DIR__ . '/../config.php';
        $from_email = $config['system_from_email'];

        $subject = "[SuperShield Security] Command Center Login Alert from {$ip}";
        $timestamp = gmdate('Y-m-d H:i:s') . ' UTC';
        $browser = htmlspecialchars(substr($user_agent, 0, 80));

        $body = "
<!DOCTYPE html>
<html>
<head>
<meta charset='utf-8'>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #0b0f19; color: #f3f4f6; margin: 0; padding: 25px; }
  .container { max-width: 540px; margin: 0 auto; background: #131b2e; border: 1px solid #1e293b; border-radius: 12px; overflow: hidden; }
  .header { background: #0f172a; padding: 20px; text-align: center; border-bottom: 2px solid #38bdf8; }
  .content { padding: 25px; }
  .meta-box { background: #0f172a; border-radius: 8px; padding: 15px; margin: 15px 0; font-size: 13px; color: #cbd5e1; line-height: 1.7; }
  .footer { background: #0b0f19; padding: 15px; text-align: center; font-size: 12px; color: #64748b; border-top: 1px solid #1e293b; }
</style>
</head>
<body>
<div class='container'>
  <div class='header'>
    <h2 style='margin:0; color:#fff; font-size:18px;'>🛡️ Command Center Session Active</h2>
  </div>
  <div class='content'>
    <p style='color:#cbd5e1; margin-top:0;'>An administrator successfully signed in to the SuperShield Security Command Center:</p>
    
    <div class='meta-box'>
      &bull; <strong>Account:</strong> {$username}<br>
      &bull; <strong>IP Address:</strong> {$ip}<br>
      &bull; <strong>Browser / OS:</strong> {$browser}<br>
      &bull; <strong>Timestamp:</strong> {$timestamp}
    </div>

    <p style='font-size:12px; color:#94a3b8;'>If this was you, you can safely disregard this notice. If not, immediately update your credentials in the Command Center.</p>
  </div>
  <div class='footer'>
    SuperShield Security Hub &bull; grwebdevs.com
  </div>
</div>
</body>
</html>
";

        $headers   = array();
        $headers[] = 'MIME-Version: 1.0';
        $headers[] = 'Content-type: text/html; charset=utf-8';
        $headers[] = 'From: SuperShield Security <' . $from_email . '>';
        $headers[] = 'X-Mailer: SuperShield-Platform/2.1.0';

        return @mail($to_email, $subject, $body, implode("\r\n", $headers));
    }

    /**
     * Send Password Reset Link to Admin.
     *
     * @param string $to_email
     * @param string $reset_url
     * @return bool
     */
    public static function send_password_reset($to_email, $reset_url) {
        $config = require __DIR__ . '/../config.php';
        $from_email = $config['system_from_email'];

        $subject = "[SuperShield Security] Password Reset Request";

        $body = "
<!DOCTYPE html>
<html>
<head>
<meta charset='utf-8'>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #0b0f19; color: #f3f4f6; margin: 0; padding: 25px; }
  .container { max-width: 540px; margin: 0 auto; background: #131b2e; border: 1px solid #1e293b; border-radius: 12px; overflow: hidden; }
  .header { background: #0f172a; padding: 20px; text-align: center; border-bottom: 2px solid #f59e0b; }
  .content { padding: 30px; text-align: center; }
  .btn { display: inline-block; padding: 14px 28px; background: #f59e0b; color: #000; font-weight: 800; border-radius: 8px; text-decoration: none; margin: 20px 0; font-size: 15px; }
  .footer { background: #0b0f19; padding: 15px; text-align: center; font-size: 12px; color: #64748b; border-top: 1px solid #1e293b; }
</style>
</head>
<body>
<div class='container'>
  <div class='header'>
    <h2 style='margin:0; color:#fff; font-size:18px;'>🔑 Reset Password Request</h2>
  </div>
  <div class='content'>
    <p style='color:#cbd5e1; margin-top:0;'>A password reset was requested for your SuperShield Security Command Center:</p>

    <a href='{$reset_url}' class='btn'>Reset Master Password &rarr;</a>

    <p style='font-size:12px; color:#94a3b8; word-break:break-all;'>Or paste this link into your browser:<br>{$reset_url}</p>
    <p style='font-size:12px; color:#f87171;'>This link expires in 30 minutes.</p>
  </div>
  <div class='footer'>
    SuperShield Security Hub &bull; grwebdevs.com
  </div>
</div>
</body>
</html>
";

        $headers   = array();
        $headers[] = 'MIME-Version: 1.0';
        $headers[] = 'Content-type: text/html; charset=utf-8';
        $headers[] = 'From: SuperShield Security <' . $from_email . '>';
        $headers[] = 'X-Mailer: SuperShield-Platform/2.1.0';

        return @mail($to_email, $subject, $body, implode("\r\n", $headers));
    }
}
