=== SuperShield Security — Firewall, Malware Scanner & 8-Layer Server Hardening ===
Contributors: ghulamrasool, grwebdevs
Donate link: https://grwebdevs.com
Tags: security, firewall, malware scanner, waf, brute force, hardening, xmlrpc, login security, two factor, 2fa, country blocking, geoip, virus scanner
Requires at least: 5.8
Tested up to: 6.7
Requires PHP: 7.4
Stable tag: 2.4.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

All-in-one enterprise WordPress cybersecurity fortress combining the intelligent WAF of Wordfence, the surgical 1-click disinfection of MalCare, and the 8-layer zero-trust hardening of AIOS — 100% free.

== Description ==

**SuperShield Security (SSS)** is an enterprise-grade defense-in-depth WordPress security suite engineered by **Ghulam Rasool** (Founder & Principal Security Engineer at `grwebdevs.com`). It permanently disrupts the legacy WordPress cybersecurity ecosystem by delivering capabilities that competitors charge $99–$299/year for **100% free**:

* **Real-Time Web Application Firewall (WAF):** Zero-delay heuristic request normalization, AST pattern matching, and deep inspection neutralizing SQLi, XSS, RCE, LFI, and vulnerability probers (`sqlmap`, `nikto`, `wpscan`).
* **Deep Forensic Scanner & 1-Click Surgical Disinfection (MalCare Killer):** Compares core files against official WordPress.org checksums, calculates Shannon entropy to detect packed obfuscated shells, detects hidden dot droppers (`.xxxx.php`), and excises malicious code while preserving legitimate plugins and themes.
* **Enterprise Two-Factor Authentication (2FA):** Standard RFC 6238 TOTP (Google Authenticator, Authy, 1Password, Bitwarden) with offline SVG QR code generation, role-based enforcement, grace periods, and 8 single-use emergency backup recovery passcodes.
* **100% Free Country / GeoIP Access Blocking:** High-speed offline IP-to-country resolution using embedded GeoLite2 ranges and Cloudflare `CF-IPCountry` header passthrough.
* **8-Layer Zero-Trust Server Hardening:** Uploads PHP execution denial, XML-RPC killswitch, anti-user enumeration, runtime `DISALLOW_FILE_EDIT`, enterprise HTTP security headers, and stealth dropper shields across Apache, LiteSpeed, and Nginx.
* **GitHub Releases API Auto-Updater:** Seamless background update distribution directly from Ghulam Rasool's GitHub releases with pre-update snapshot rollbacks.
* **Cryptographic Self-Integrity & MU Watchdog:** HMAC-SHA256 manifest checks detecting unauthorized code modifications, AES-256-GCM encrypted rule vaults, and persistent Must-Use watchdog defense.
* **Zero MySQL Drag:** Memory-capped audit logging, automated 30-day log rotation, and microsecond in-memory IP caching.

---

### 🛡️ 1. Real-Time Web Application Firewall (WAF)
* **Zero-Delay Real-Time Signatures:** Instant protection against zero-day exploit probes without artificial 30-day delays.
* **Multi-Layer Request Normalization:** Iteratively unwraps nested URL encodings (`%252e%252e%252f`), strips null bytes (`%00`), and flattens SQL comment masks (`UNION/**/SELECT`).
* **Attack Coverage:** SQL Injection (SQLi), Cross-Site Scripting (XSS), Remote Code Execution (RCE), Local/Remote File Inclusion (LFI/RFI), and PHP stream wrapper exploits (`php://filter`, `phar://`, `data://`).
* **Branded 403 Forbidden Shield Screen:** Cyber Command Center block page with unique Incident Tracking ID (`#SSS-SEC-XXXXXX`), preventing server information disclosure.

---

### 🔍 2. Deep Forensic Scanner with 1-Click Surgical Disinfection
* **Core Integrity Diff (WordPress.org API):** Verifies local core files against official MD5 checksums from `api.wordpress.org`. Offers 1-click restore to pristine copies.
* **Shannon Entropy Analysis:** Mathematical randomness scanning to detect XOR packers, base64 webshells, and variable-function backdoors.
* **Stealth Dropper Forensics:** Scans for hidden dot files (`.xxxx.php`), 8-hex droppers (`^[0-9a-f]{8}\.php`), and cross-account worm staging folders (`.sc_*`).
* **Database Threat Sanitizer:** Scans `wp_options` for bloated serialized payloads (>50KB) and purges known malware options (`wp_vcd`, `SC_DB`, `SCD1`). Detects rogue admin user registrations.
* **1-Click Surgical Disinfection:** Excises injected malware tags while leaving legitimate plugin code intact, or moves irrecoverable droppers to the locked `.quarantine/` vault with `0400` permissions.

---

### 🔑 3. Enterprise Two-Factor Authentication (2FA)
* **RFC 6238 TOTP Standard:** Seamless integration with Google Authenticator, Authy, Microsoft Authenticator, and 1Password.
* **Offline Privacy-Safe QR Generator:** Generates crisp SVG QR codes in pure PHP with zero third-party tracking or external API dependencies.
* **Emergency Backup Passcodes:** 8 cryptographically secure single-use recovery passcodes for account access if your mobile device is lost.
* **Zero-Trust Role Enforcement:** Enforce mandatory 2FA for Administrators and Editors with customizable grace periods.

---

### 🌍 4. Offline GeoIP & Country Blocking
* **High-Speed Offline Resolution:** Microsecond IP-to-country lookup without external API latency.
* **Cloudflare Native Passthrough:** Direct detection of `CF-IPCountry` headers.
* **Flexible Access Policies:** Blacklist malicious regions or whitelist trusted territories for administrative login screens.

---

### 🧱 5. 8-Layer Server Hardening Engine
* **Layer 1:** Dual Apache 2.2 / 2.4 `.htaccess` script execution lockdown in `/wp-content/uploads/`.
* **Layer 2:** Total XML-RPC killswitch blocking `xmlrpc.php`.
* **Layer 3:** Anti-User Enumeration blocking `/?author=N` scans and REST `/wp/v2/users` endpoints.
* **Layer 4:** Runtime `DISALLOW_FILE_EDIT` dashboard lockdown.
* **Layer 5:** Enterprise HTTP security headers (`X-Frame-Options`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`).
* **Layer 6:** WordPress version fingerprint removal from HTML source, feeds, and script queries (`?ver=`).
* **Layer 7:** Core configuration file shield protecting `wp-config.php`, `.htaccess`, and `.user.ini`.
* **Layer 8:** Stealth dropper and hidden dot file execution killswitch.

---

== Installation ==

1. Upload the `supershield-security` directory to your `/wp-content/plugins/` directory.
2. Activate the plugin through the **Plugins** menu in WordPress.
3. Your administrator IP address is automatically whitelisted to prevent accidental lockout.
4. Open the **SuperShield** Cybersecurity Command Center to view your Security Health Score and run a deep system scan.

== Frequently Asked Questions ==

= Does SuperShield slow down my website? =
No. SuperShield is built with sub-2ms latency regex normalization and in-memory IP caching. Scans run with memory-controlled chunking to prevent hitting PHP execution limits.

= Who is the author of SuperShield Security? =
SuperShield Security is engineered by **Ghulam Rasool**, Founder & Principal Security Engineer at `grwebdevs.com`.

= Why are features like Country Blocking and 2FA 100% free? =
SuperShield aims to permanently disrupt the WordPress security ecosystem by providing enterprise-grade defenses without annual paywalls.

== Changelog ==

= 2.4.0 =
* Fixed scan timeout & PHP memory limits: Implemented chunked multi-stage scanning engine (`run_scan_stage`) allowing sequential AJAX execution of core diffs, uploads, droppers, signatures, and database scans with granular live percentage feedback (15% -> 35% -> 55% -> 75% -> 90% -> 100%).
* Added recursive filesystem iterator error resilience: wrapped directory iterators with `RecursiveIteratorIterator::CATCH_GET_CHILD` and granular file-level exception trapping, permanently eliminating uncaught `UnexpectedValueException` permission fatal errors on restricted server directories.
* Implemented missing `ajax_start_scan` and `ajax_scan_stage` endpoints in `SuperShield_Admin`, eliminating uncaught `TypeError: Call to undefined method` 500 errors.
* Enhanced Decoy 404 Honeypot with humorous cyberpunk "404 LOL — Nice Try, Hacker!" interface, completely eliminating secret login slug leak on unauthenticated `/wp-admin` and `/wp-admin/admin.php` probes.
* Added native PHP mail() test dispatch diagnostic button in Diagnostics settings for verifying server email delivery without paid SMTP.

= 2.3.0 =
* Added Decoy 404 Honeypot Page: Direct access to /wp-admin or /wp-login.php by unauthenticated visitors now shows a convincing animated 404 error page with logged IP and request ID — attackers never see the secret login slug via redirect.
* Fixed /wp-admin redirect leak: Previously, visiting /wp-admin unauthenticated would redirect to the secret slug URL, revealing it. Now fully intercepted at the redirect filter level.
* Added Weekly Security Digest Report: Configurable WP-Cron job scans every 7 days and always sends a formatted HTML report email, perfect for client weekly reports.
* Added Monthly Security Report: Configurable 30-day cron sends a comprehensive monthly digest — ideal for management/compliance reporting.
* Added Daily Clean-Bill Notification toggle: Opt in to receive a clean-bill confirmation email even when no threats are detected. Default: OFF (threats-only alerts).
* Fixed undefined $site_name bug in handle_admin_login() causing PHP notices.
* Improved send_scheduled_report() with beautiful branded HTML templates for each report type (daily threat, daily clean, weekly digest, monthly digest).
* Cron schedules now show next scheduled run time in the scanner settings UI.

= 2.2.1 =
* Fixed Google Authenticator and mobile authenticator QR code scanning: rewrote pure-PHP QR matrix engine with ISO/IEC 18004 8-mask penalty scoring and strict otpauth URI standard compliance.
* Added 1-Click Copy Secret Key functionality for seamless manual 2FA entry.
* Fixed admin firewall form button concatenation by isolating access list management into dedicated forms.
* Added high-visibility floating toast notifications for real-time setting confirmation and AJAX alerts.
* Added Anti-DDoS Volumetric Rate Limiter with 429 Too Many Requests response headers and customizable cool-down windows.
* Added HaveIBeenPwned k-Anonymity breach checking to shield logins against compromised passwords.
* Added Automated Daily Deep Scan with WP-Cron scheduling and immediate administrator email alerts on threat detection.
* Added Active User Sessions & Devices Manager for real-time session audit and 1-click remote session revocation.
* Added human-readable country names and flag emojis to authentication audit trail and live traffic logs.
* Fixed Cloudflare edge proxy IP resolution ensuring authentic client IPs are tracked instead of Cloudflare proxy IPs.

= 2.0.0 =
* Major release: Upgraded to Enterprise Production Suite.
* Introduced 1-Click Surgical Disinfection and Core Checksum Auto-Restoration via official WordPress.org API.
* Added Enterprise TOTP Two-Factor Authentication (2FA) with offline SVG QR code generator and 8 emergency backup codes.
* Added 100% Free Offline GeoIP Country Blocking with Cloudflare CF-IPCountry passthrough.
* Added GitHub Releases API Auto-Updater engine with pre-update snapshot rollbacks.
* Added HMAC-SHA256 Cryptographic Self-Integrity verification and Must-Use (MU) Watchdog layer.
* Added Shannon Entropy Analysis for detecting obfuscated and packed webshells.
* Added One-Click Anonymous System Diagnostics Exporter and in-admin Engineering Feedback Modal.
* Upgraded Admin UI to bespoke agency-grade Cybersecurity Command Center with dark obsidian styling.

= 1.0.0 =
* Initial public release with Core WAF, 8-layer hardening, and multi-tier scanner.
