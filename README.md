# SuperShield Security (SSS) — Enterprise WordPress Defense-in-Depth Suite

[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](https://SSS.grwebdevs.com)
[![WordPress](https://img.shields.io/badge/WordPress-5.8%20to%206.7%2B-21759b.svg)](https://wordpress.org)
[![PHP](https://img.shields.io/badge/PHP-7.4%20to%208.3%2B-777bb4.svg)](https://php.net)
[![License](https://img.shields.io/badge/License-GPLv2%2B-green.svg)](http://www.gnu.org/licenses/gpl-2.0.txt)
[![Author](https://img.shields.io/badge/Author-Ghulam%20Rasool-6366f1.svg)](https://grwebdevs.com)

**SuperShield Security (SSS)** is an enterprise-grade cybersecurity fortress for WordPress engineered by **Ghulam Rasool** (Founder & Principal Security Engineer, `grwebdevs.com`). It permanently disrupts the legacy WordPress cybersecurity market by combining the three greatest architectural pillars of the industry into a unified, zero-overhead defense suite — **100% free with no paywalled protections**:

1. **The Real-Time Intelligent WAF & Live Threat Telemetry of Wordfence** (Zero-delay signatures)
2. **The Zero-False-Positive Deep Scanner & 1-Click Surgical Disinfection of MalCare**
3. **The 8-Layer Server Hardening, Anti-Enumeration & Zero-Trust Rules of AIOS**

---

## 🛡️ Enterprise Feature Matrix

| Feature / Capability | SuperShield Security (SSS) | Wordfence (Free / Pro) | MalCare (Free / Pro) |
| :--- | :--- | :--- | :--- |
| **Firewall (WAF) Engine** | **100% Free Real-Time WAF with AST normalization** | Free: 30-day delayed rules<br>Pro ($119/yr): Real-time | Free: Basic sync<br>Pro ($99/yr): Real-time |
| **Malware Cleaning** | **100% Free 1-Click Surgical Disinfection & Core Diff Restore** | Free: Delete only<br>Pro ($119/yr): Manual clean | Free: View only<br>Pro ($99/yr): 1-Click clean |
| **Two-Factor Auth (2FA)** | **Enterprise TOTP (Google/Authy) + Emergency Backup Passcodes** | Included (Basic UI) | Not available on lower tiers |
| **Country / GeoIP Blocking**| **100% Free via offline GeoLite2 & Cloudflare passthrough** | Paywalled in Pro ($119/yr) | Paywalled in Pro ($149/yr) |
| **Server Hardening** | **8-Layer Defense-in-Depth Lockdown (Apache/LiteSpeed/Nginx)** | Limited to basic WAF | Relies on external SaaS proxy |
| **Distribution / Updates** | **Dual-Channel: Native WP Admin + Direct GitHub Auto-Updater** | WP.org Repo Only | WP.org Repo + SaaS Portal |
| **Code Anti-Tampering** | **HMAC-SHA256 Manifest Integrity + MU Watchdog Guard** | Basic hash checks | Closed cloud bridge |

---

## 🚀 Key Architectural Subsystems

### 1. Real-Time Web Application Firewall (WAF) & GeoIP
* **Zero-Delay Heuristic Inspection:** Normalizes multi-layer URL encodings, strips null bytes (`%00`), and flattens comment evasion tricks (`UNION/**/SELECT`).
* **Attack Vector Coverage:** SQL Injection (SQLi), Cross-Site Scripting (XSS), Remote Code Execution (RCE), Local/Remote File Inclusion (LFI/RFI), stream wrapper exploits (`php://filter`), and prober tools (`sqlmap`, `nikto`, `wpscan`).
* **Offline Country Blocking:** Microsecond IP-to-country resolution via offline CIDR databases and Cloudflare `CF-IPCountry` header passthrough.
* **Branded 403 Forbidden Shield Screen:** Cyber Command Center block page featuring incident ID `#SSS-SEC-XXXXXX`, client IP, timestamp, and zero information disclosure.

### 2. Deep Forensic Scanner & 1-Click Surgical Disinfection
* **WordPress Core Integrity Diff:** Directly pulls checksums from `api.wordpress.org/core/checksums/` to identify altered or injected core files with 1-click automatic restoration.
* **Shannon Entropy Analysis:** Detects obfuscated packers, encrypted strings, and variable-function shells by evaluating mathematical randomness.
* **Stealth Dropper Forensics:** Identifies hidden dot droppers (`.xxxx.php`), 8-hex droppers (`^[0-9a-f]{8}\.php`), and cross-account worm staging directories (`.sc_*`).
* **Database Threat Sanitizer:** Purges bloated serialized options (>50KB) and known malware entries (`wp_vcd`, `SC_DB`, `SCD1`), while discovering rogue administrator accounts.
* **1-Click Surgical Disinfection:** Excises malicious code blocks from infected themes or plugins using AST pattern parsing while preserving legitimate code, or isolates files into the locked `.quarantine/` vault (`0400` permissions).

### 3. Enterprise Two-Factor Authentication (2FA) & Login Defense
* **RFC 6238 TOTP Standard:** Works with Google Authenticator, Authy, 1Password, Bitwarden, and Microsoft Authenticator.
* **Offline SVG QR Code Generator:** 100% offline, privacy-safe QR code generation rendered in pure PHP with zero third-party tracking.
* **Emergency Backup Passcodes:** 8 single-use recovery passcodes generated for device loss.
* **Progressive Lockout & Invisible Bot Honeypots:** Dynamically blocks IP addresses exceeding failed login thresholds and catches automated bots in invisible decoy traps.

### 4. 8-Layer Server Hardening Engine
* **Layer 1:** Script execution lockdown in `/wp-content/uploads/` via dual Apache 2.2 / 2.4 directives.
* **Layer 2:** Total XML-RPC killswitch (`xmlrpc.php`).
* **Layer 3:** Anti-User Enumeration blocking author query scans (`/?author=1`) and unauthenticated REST API `/wp/v2/users` endpoints.
* **Layer 4:** Runtime `DISALLOW_FILE_EDIT` dashboard lockdown.
* **Layer 5:** Enterprise HTTP security headers (`X-Frame-Options`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`).
* **Layer 6:** WordPress version fingerprint masking.
* **Layer 7:** Core configuration file shield (`wp-config.php`, `.htaccess`, `.user.ini`).
* **Layer 8:** Stealth dropper and hidden dot file execution denial.

### 5. GitHub Releases Auto-Updater & Anti-Tamper Shield
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
│   ├── class-supershield-activator.php  # Schema installer & 2.0.0 default settings
│   ├── class-supershield-deactivator.php# Deactivation & cron cleanup
│   ├── class-supershield-db.php         # Database migration, logging, threat tracking
│   ├── class-supershield-waf.php        # High-performance heuristic WAF & 403 screen
│   ├── class-supershield-ip-manager.php # CIDR matching & IP whitelist/blacklist
│   ├── class-supershield-geoip.php      # Offline GeoLite2 & Cloudflare country blocking
│   ├── class-supershield-cleaner.php    # 1-Click surgical disinfection & core diff restore
│   ├── class-supershield-scanner.php    # Core diff, Shannon entropy, dropper forensics
│   ├── class-supershield-hardening.php  # 8-layer zero-trust server hardening
│   ├── class-supershield-login-security.php # Progressive lockout & bot honeypots
│   ├── class-supershield-2fa.php        # RFC 6238 TOTP 2FA & emergency backup codes
│   ├── class-supershield-updater.php    # GitHub Releases API client & transient hooks
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
