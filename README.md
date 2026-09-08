# SuperShield Security (SSS) — Enterprise WordPress Defense-in-Depth Suite

[![Version](https://img.shields.io/badge/version-2.5.0-blue.svg)](https://SSS.grwebdevs.com)
[![WordPress](https://img.shields.io/badge/WordPress-5.8%20to%206.7%2B-21759b.svg)](https://wordpress.org)
[![PHP](https://img.shields.io/badge/PHP-7.4%20to%208.3%2B-777bb4.svg)](https://php.net)
[![License](https://img.shields.io/badge/License-GPLv2%2B-green.svg)](http://www.gnu.org/licenses/gpl-2.0.txt)
[![Author](https://img.shields.io/badge/Author-Ghulam%20Rasool-6366f1.svg)](https://grwebdevs.com)

**SuperShield Security (SSS)** is an enterprise-grade cybersecurity fortress for WordPress engineered by **Ghulam Rasool** (Founder & Principal Security Engineer, `grwebdevs.com`). It permanently disrupts the legacy WordPress cybersecurity market by combining the three greatest architectural pillars of the industry into a unified, zero-overhead defense suite — **100% free with no paywalled protections**:

1. **The Real-Time Intelligent WAF & Live Threat Telemetry of Wordfence** (Zero-delay signatures, Learning Mode, and Simulation)
2. **The Zero-False-Positive Deep Scanner & 1-Click Surgical Disinfection of MalCare** (With Protected File Guard that never bricks your site)
3. **The 8-Layer Server Hardening, Anti-Enumeration & Zero-Trust Rules of AIOS**

---

## ⚡ Why Switch from Wordfence to SuperShield Security?

| Pain Point in Wordfence / Paid Competitors | SuperShield Security Advantage (100% Free) |
| :--- | :--- |
| **Severe Database Bloat:** Wordfence fills MySQL with gigabytes of `wfhits` and `wfls_` data, causing site slowdowns and ballooning backup sizes. | **Zero DB Drag:** Memory-capped telemetry, MD5 composite indexed issue lookups, and auto-purging event streams. |
| **30-Day Rule Delay on Free Tier:** Wordfence delays new threat signatures for 30 days unless you pay $149/year. | **Zero-Delay Real-Time Protection:** Enterprise heuristic WAF rules, SQLi/RCE filters, and zero-day patches active instantly. |
| **Site-Bricking File Deletion:** Wordfence's only remediation is deleting the file, which crashes your site with fatal PHP errors. | **Surgical AST Disinfection + Protected File Guard:** Excises malware tokens while preserving legitimate code. Critical files are permanently protected against accidental deletion. |
| **Paywalled Country Blocking:** Wordfence charges $149/site/year for GeoIP access blocking. | **Free Offline Country Blocking:** Microsecond IP-to-country lookup with Cloudflare `CF-IPCountry` integration built-in. |
| **Frustrating reCAPTCHA Puzzles:** Clunky image challenges that alienate legitimate users and leak visitor data to Google. | **Cloudflare Turnstile Bot Defense:** Completely invisible, non-interactive, privacy-first bot protection for logins and registrations. |
| **Carding Attacks on WooCommerce:** Fake checkout testing bots draining merchant funds and racking up transaction fees. | **WooCommerce Anti-Carding Shield:** Invisible honeypot traps and velocity limiters (3 failed attempts = 24-hr IP ban). |
| **Expensive Alerts / No Easy Chat Integration:** Setting up alerts requires paid SMTP or complex custom integrations. | **Free Discord Webhooks:** Instant incident notifications with rich embed cards dispatched directly to your Discord channel. |

---

## 🛡️ Enterprise Feature Matrix

| Feature / Capability | SuperShield Security (SSS) | Wordfence (Free / Pro) | MalCare (Free / Pro) |
| :--- | :--- | :--- | :--- |
| **Firewall (WAF) Engine** | **100% Free Real-Time WAF with Learning & Sim Mode** | Free: 30-day delayed rules<br>Pro ($149/yr): Real-time | Free: Basic sync<br>Pro ($99/yr): Real-time |
| **Malware Cleaning** | **100% Free 1-Click Surgical Disinfection & Core Diff Restore** | Free: Delete only<br>Pro ($149/yr): Manual clean | Free: View only<br>Pro ($99/yr): 1-Click clean |
| **Vulnerability Scanner (CVE)** | **Built-in curated CVE database for Core, Woo, Elementor, LiteSpeed** | Requires Pro or Premium | Paywalled in Plus/Pro |
| **Two-Factor Auth (2FA)** | **Enterprise TOTP (Google/Authy) + Emergency Backup Passcodes** | Included (Basic UI) | Not available on lower tiers |
| **Country / GeoIP Blocking**| **100% Free via offline GeoLite2 & Cloudflare passthrough** | Paywalled in Pro ($149/yr) | Paywalled in Pro ($149/yr) |
| **Bot Defense** | **Cloudflare Turnstile + 404 Prober Trap + Decoy Honeypots** | Google reCAPTCHA v2/v3 only | Proprietary bot shield |
| **WooCommerce Shield** | **Anti-Carding velocity throttling & checkout honeypots** | None (requires 3rd party) | Not included |
| **Webhook Alerts** | **100% Free Instant Discord Webhooks with Rich Embed Cards** | Email only (Free) | Email only (Free) |
| **Server Hardening** | **8-Layer Defense-in-Depth Lockdown (Apache/LiteSpeed/Nginx)** | Limited to basic WAF | Relies on external SaaS proxy |
| **Distribution / Updates** | **Dual-Channel: Native WP Admin + Direct GitHub Auto-Updater** | WP.org Repo Only | WP.org Repo + SaaS Portal |
| **Code Anti-Tampering** | **HMAC-SHA256 Manifest Integrity + MU Watchdog Guard** | Basic hash checks | Closed cloud bridge |

---

## 🚀 Key Architectural Subsystems

### 1. Real-Time Web Application Firewall (WAF) & Bot Traps
* **Zero-Delay Heuristic Inspection:** Normalizes multi-layer URL encodings, strips null bytes (`%00`), and flattens comment evasion tricks (`UNION/**/SELECT`).
* **WAF Learning Mode & Simulation Mode:** Train the firewall to observe traffic without blocking to eliminate false positives in complex bespoke setups.
* **404 Prober Trap:** Automatically detects and bans automated probers scanning for non-existent backdoors and vulnerabilities (>20 404s/min).
* **Attack Vector Coverage:** SQL Injection (SQLi), Cross-Site Scripting (XSS), Remote Code Execution (RCE), Local/Remote File Inclusion (LFI/RFI), stream wrapper exploits (`php://filter`), and prober tools (`sqlmap`, `nikto`, `wpscan`).
* **Offline Country Blocking:** Microsecond IP-to-country resolution via offline CIDR databases and Cloudflare `CF-IPCountry` header passthrough.
* **Branded 403 Forbidden Shield Screen:** Cyber Command Center block page featuring incident ID `#SSS-SEC-XXXXXX`, client IP, timestamp, and zero information disclosure.

### 2. Deep Forensic Scanner & Safe 1-Click Disinfection
* **Vulnerability Intelligence (CVE Scanner):** Scans installed plugins and themes against active CVE vulnerability catalogs (Elementor, WooCommerce, LiteSpeed Cache, CF7, WPForms, etc.) and provides 1-click update shortcuts.
* **WordPress Core Integrity Diff:** Directly pulls checksums from `api.wordpress.org/core/checksums/` to identify altered or injected core files with 1-click automatic restoration.
* **Shannon Entropy Analysis:** Detects obfuscated packers, encrypted strings, and variable-function shells by evaluating mathematical randomness.
* **Stealth Dropper Forensics:** Identifies hidden dot droppers (`.xxxx.php`), 8-hex droppers (`^[0-9a-f]{8}\.php`), and cross-account worm staging directories (`.sc_*`).
* **Database Threat Sanitizer:** Purges bloated serialized options (>50KB) and known malware entries (`wp_vcd`, `SC_DB`, `SCD1`), while discovering rogue administrator accounts.
* **1-Click Surgical Disinfection & Safe Guard:** Excises malicious code blocks from infected files while preserving legitimate functions. Protected File Guard ensures critical system files are never quarantined.
* **Bulk Remediation:** Remediate or ignore multiple threat findings simultaneously with 1 click.

### 3. WooCommerce Anti-Carding & Bot Protection
* **Checkout Velocity Limiter:** Throttles rapid checkout attempts, enforcing a 24-hour IP ban on addresses with 3 failed transactions in 10 minutes.
* **Invisible Decoy Honeypot:** Catches headless automated purchasing bots without impacting real shoppers.
* **Cloudflare Turnstile Integration:** Seamless, frictionless bot verification for logins, registrations, and checkout actions.

### 4. Enterprise Two-Factor Authentication (2FA) & Login Defense
* **RFC 6238 TOTP Standard:** Works with Google Authenticator, Authy, 1Password, Bitwarden, and Microsoft Authenticator.
* **Offline SVG QR Code Generator:** 100% offline, privacy-safe QR code generation rendered in pure PHP with zero third-party tracking.
* **Emergency Backup Passcodes:** 8 single-use recovery passcodes generated for device loss.
* **Admin Login Dashboard Alerts:** High-visibility threat notifications rendered right inside the WordPress admin dashboard on login.

### 5. 8-Layer Server Hardening Engine
* **Layer 1:** Script execution lockdown in `/wp-content/uploads/` via dual Apache 2.2 / 2.4 directives.
* **Layer 2:** Total XML-RPC killswitch (`xmlrpc.php`).
* **Layer 3:** Anti-User Enumeration blocking author query scans (`/?author=1`) and unauthenticated REST API `/wp/v2/users` endpoints.
* **Layer 4:** Runtime `DISALLOW_FILE_EDIT` dashboard lockdown.
* **Layer 5:** Enterprise HTTP security headers (`X-Frame-Options`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`).
* **Layer 6:** WordPress version fingerprint masking.
* **Layer 7:** Core configuration file shield (`wp-config.php`, `.htaccess`, `.user.ini`).
* **Layer 8:** Stealth dropper and hidden dot file execution denial.

### 6. Free Discord Webhook Dispatcher & Automated Reports
* **Instant Discord Webhooks:** Send real-time attack notifications and scan reports directly to your team's Discord channels with rich embeds and color-coded status badges.
* **Scheduled Executive Digests:** Weekly and monthly security overview reports summarizing attacks blocked, threats cleaned, and overall site posture.

### 7. GitHub Releases Auto-Updater & Anti-Tamper Shield
* **GitHub Releases API Client:** Automated background update detection and 1-click upgrades directly from Ghulam Rasool's repository (`github.com/grwebdevs/supershield-security`).
* **HMAC-SHA256 Cryptographic Self-Integrity:** Continuously verifies plugin PHP files against a signed manifest to block unauthorized tampering.
* **MU Watchdog:** Persistent Must-Use watchdog protecting the plugin against unauthorized deletion or deactivation.

---

## 📂 File Architecture

```
supershield-security/
├── supershield-security.php             # Plugin bootstrap & constants (v2.0.0)
├── uninstall.php                        # Clean uninstaller (tables & options)
├── README.md                            # Complete technical documentation
├── readme.txt                           # Official WordPress repository documentation
├── includes/
│   ├── class-supershield-core.php       # Main singleton coordinator & hooks
│   ├── class-supershield-activator.php  # Schema installer & default settings
│   ├── class-supershield-deactivator.php# Deactivation & cron cleanup
│   ├── class-supershield-db.php         # Database migration, logging, threat tracking
│   ├── class-supershield-waf.php        # High-performance WAF, Learning Mode & 404 trap
│   ├── class-supershield-ip-manager.php # CIDR matching & IP whitelist/blacklist
│   ├── class-supershield-geoip.php      # Offline GeoLite2 & Cloudflare country blocking
│   ├── class-supershield-cleaner.php    # Safe cleaner, AST excision & Protected File Guard
│   ├── class-supershield-scanner.php    # Multi-stage chunked scanner & entropy heuristics
│   ├── class-supershield-vuln-scanner.php # Vulnerability intelligence & CVE catalog matching
│   ├── class-supershield-woocommerce.php # Anti-carding checkout shield & decoy honeypot
│   ├── class-supershield-hardening.php  # 8-layer zero-trust server hardening
│   ├── class-supershield-login-security.php # Progressive lockout, Turnstile & honeypots
│   ├── class-supershield-2fa.php        # RFC 6238 TOTP 2FA & emergency backup codes
│   ├── class-supershield-notifier.php   # Discord webhook alerts & weekly digests
│   ├── class-supershield-updater.php    # GitHub Releases API client & pre-update snapshots
│   ├── class-supershield-antitamper.php # HMAC-SHA256 self-integrity & MU watchdog
│   ├── class-supershield-telemetry.php  # Diagnostics exporter & feedback modal
│   └── class-supershield-utils.php      # Security score engine (100 pts) & utilities
├── admin/
│   ├── class-supershield-admin.php      # Command center controller & AJAX API
│   ├── css/
│   │   └── supershield-admin.css        # Cybersecurity Command Center UI styling
│   ├── js/
│   │   └── supershield-admin.js         # Vanilla ES6+ controller & AJAX handlers
│   └── views/
│       ├── dashboard.php                # Health score, threat radar, live incident stream
│       ├── firewall.php                 # WAF rules, offline GeoIP, blocked IPs table
│       ├── scanner.php                  # Malware scanner & 1-click surgical disinfection
│       ├── hardening.php                # 8-layer hardening toggles & Nginx directives
│       ├── login-security.php           # Brute-force shield & personal TOTP 2FA setup
│       ├── diagnostics.php              # System diagnostic bundle & GitHub auto-updater
│       └── live-traffic.php             # Filterable security audit trail
└── tests/
    └── test-supershield-suite.php       # Comprehensive automated verification suite
```

---

## 🧪 Automated Verification Suite

SuperShield includes a standalone PHP automated verification suite (`tests/test-supershield-suite.php`) validating all security mechanisms without external dependencies:

```bash
php tests/test-supershield-suite.php
```

Tests cover:
1. IPv4 / IPv6 CIDR subnet range matching
2. IP spoofing prevention & reverse proxy trust
3. IP whitelist/blacklist priority enforcement
4. 8-Layer server hardening score engine (100% score / A+ grade)
5. WAF attack vector neutralization (SQLi, XSS, RCE, LFI, WPScan bot)
6. Malware scanner, hidden dot droppers, and double-extension detection
7. Offline GeoIP country resolution & Cloudflare passthrough
8. RFC 6238 TOTP two-factor code generation, drift verification, and backup passcodes
9. 1-Click surgical code excision and quarantine vault isolation
10. HMAC-SHA256 cryptographic self-integrity and AES-256-GCM vault
11. GitHub Releases updater semver parsing and package transient injection
12. Anonymous system diagnostics exporter (zero credential leakage)

---

## 👨‍💻 Engineering Lead & Document Control

* **Architect & Principal Security Engineer:** **Ghulam Rasool**
* **Agency Portfolio:** [grwebdevs.com](https://grwebdevs.com)
* **Official Platform:** [SSS.grwebdevs.com](https://SSS.grwebdevs.com)
* **License:** GNU General Public License v2.0+
