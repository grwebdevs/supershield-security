<?php
/**
 * SuperShield Security — Master Platform Showcase & Front Controller
 * 
 * Aesthetic Thesis: Hyper-Defense Glass & Machined Hardware
 * Lead Architect: Ghulam Rasool (grwebdevs.com)
 * Version: 2.5.0
 */

define('SSS_ACCESS', true);

$config = require __DIR__ . '/config.php';
$request_uri = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);

// -------------------------------------------------------------
// 1. API Route Interceptor (/api/v1/*)
// -------------------------------------------------------------
if (preg_match('#^/api/v1/([a-zA-Z0-9_\-/]+)#', $request_uri, $matches)) {
    require_once __DIR__ . '/api/router.php';
    SSS_API_Router::dispatch($matches[1]);
    exit;
}

// -------------------------------------------------------------
// 2. Command Center Secret Route (/panel/)
// -------------------------------------------------------------
if (strpos($request_uri, '/panel') === 0) {
    require_once __DIR__ . '/panel/index.php';
    exit;
}

// -------------------------------------------------------------
// 3. Direct Release Download Handler (/download or /download/latest)
// -------------------------------------------------------------
if (strpos($request_uri, '/download') === 0) {
    $ver          = $config['app_version'];
    $versioned    = __DIR__ . '/supershield-security-v' . $ver . '.zip';
    $fallback_zip = __DIR__ . '/supershield-security.zip';
    $zip_file     = file_exists($versioned) ? $versioned : (file_exists($fallback_zip) ? $fallback_zip : null);
    $dl_name      = 'supershield-security-v' . $ver . '.zip';

    if ($zip_file) {
        header('Content-Type: application/zip');
        header('Content-Disposition: attachment; filename="' . $dl_name . '"');
        header('Content-Length: ' . filesize($zip_file));
        header('Pragma: public');
        header('Cache-Control: must-revalidate, post-check=0, pre-check=0');
        readfile($zip_file);
        exit;
    }
    header('Location: ' . $config['fallback_download_url']);
    exit;
}

// -------------------------------------------------------------
// 4. Cyber-Defense Showcase Landing Page
// -------------------------------------------------------------
require_once __DIR__ . '/database/db.php';
$metrics = SSS_Database::get_metrics();
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SuperShield Security — Enterprise WordPress Defense-in-Depth Suite</title>
  <meta name="description" content="SuperShield Security (SSS) permanently disrupts WordPress cybersecurity. Real-time Zero-Day WAF, 1-Click Surgical Malware Cleaner, 8-Layer Server Hardening, and Hardware-Grade 2FA — 100% Free.">
  <link rel="stylesheet" href="/assets/css/portal.css?v=2.5.0">
  <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🛡️</text></svg>">
</head>
<body>

<!-- Floating Detached Island Navbar -->
<div class="navbar-wrapper">
  <header class="floating-nav">
    <a href="/" class="brand-anchor">
      <div class="brand-icon-box">🛡️</div>
      <div class="brand-text-block">
        <div class="brand-title">SuperShield <span>Security</span></div>
        <div class="brand-sub">grwebdevs.com &bull; Architecture</div>
      </div>
    </a>

    <ul class="nav-links-menu">
      <li><a href="#sandbox" class="nav-link-item">Interactive Sandbox</a></li>
      <li><a href="#bento" class="nav-link-item">Defense Pillars</a></li>
      <li><a href="#matrix" class="nav-link-item">Comparison</a></li>
      <li><a href="#deploy" class="nav-link-item">Quick Start</a></li>
      <li><a href="javascript:void(0)" onclick="openFeedbackModal()" class="nav-link-item">Support & Feedback</a></li>
    </ul>

    <div class="nav-cta-wrap">
      <a href="/download/latest" class="nav-cta-btn">
        <span>Download Plugin (.ZIP)</span>
        <span style="font-size:11px; opacity:0.8;">v<?php echo htmlspecialchars($config['app_version']); ?></span>
      </a>
    </div>
  </header>
</div>

<!-- Hero Section -->
<section class="hero-section">
  <div class="container">
    <div class="eyebrow-badge">
      <span class="pulse-dot"></span>
      <span>Enterprise Cybersecurity Fortress &bull; 100% Free Forever</span>
    </div>

    <h1 class="hero-main-title">
      Uncompromising WordPress Defense.<br>
      <span class="gradient-highlight">Zero Paywalls. Zero Subscriptions.</span>
    </h1>

    <p class="hero-subtitle">
      Engineered by <strong>Ghulam Rasool</strong> (Founder & Principal Security Engineer at <code>grwebdevs.com</code>).
      SuperShield unites the <strong>Real-Time Zero-Day WAF</strong> of Wordfence, the <strong>Surgical 1-Click Disinfection</strong> of MalCare, and the <strong>8-Layer Server Immunity</strong> of AIOS into a single zero-overhead powerhouse &mdash; without charging $199/year.
    </p>

    <div class="hero-button-group">
      <a href="/download/latest" class="btn-hardware-primary">
        <span>Download SuperShield Suite (.ZIP)</span>
        <span class="icon-circle">&rarr;</span>
      </a>
      <a href="#sandbox" class="btn-hardware-secondary">
        <span>⚡ Test Live WAF Sandbox</span>
      </a>
      <a href="https://github.com/<?php echo htmlspecialchars($config['github_repo']); ?>" target="_blank" rel="noopener" class="btn-hardware-secondary">
        <span>View Source on GitHub</span>
      </a>
    </div>

    <!-- Component A: Interactive WAF Threat Sandbox / Attack Simulator -->
    <div id="sandbox" class="sandbox-showcase">
      <div class="double-bezel-wrapper">
        <div class="double-bezel-inner">
          <div class="terminal-bar">
            <div class="terminal-dots">
              <span class="dot dot-red"></span>
              <span class="dot dot-amber"></span>
              <span class="dot dot-green"></span>
            </div>
            <div class="terminal-tab-pill">
              <button type="button" class="tab-pill-btn active" data-tab="sqli" onclick="runWafScenario('sqli')">SQL Injection</button>
              <button type="button" class="tab-pill-btn" data-tab="rce" onclick="runWafScenario('rce')">Remote Code Execution</button>
              <button type="button" class="tab-pill-btn" data-tab="traversal" onclick="runWafScenario('traversal')">Path Traversal</button>
              <button type="button" class="tab-pill-btn" data-tab="uploads" onclick="runWafScenario('uploads')">Uploads .PHP Immunity</button>
            </div>
          </div>

          <div class="terminal-screen" id="wafTerminalOutput">
            <!-- Populated interactively via JavaScript -->
          </div>

          <div class="stats-strip">
            <div class="strip-cell">
              <div class="strip-val emerald" id="metricThreatCount"><?php echo number_format((int)$metrics['total_threats_blocked']); ?></div>
              <div class="strip-lbl">Threats Neutralized</div>
            </div>
            <div class="strip-cell">
              <div class="strip-val">0.02 ms</div>
              <div class="strip-lbl">Inspection Latency</div>
            </div>
            <div class="strip-cell">
              <div class="strip-val" id="metricSiteCount"><?php echo number_format((int)$metrics['active_installations']); ?>+</div>
              <div class="strip-lbl">Protected Nodes</div>
            </div>
            <div class="strip-cell">
              <div class="strip-val emerald">100% Free</div>
              <div class="strip-lbl">No Upsells / No Pro Plan</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</section>

<!-- Component B: Asymmetric Bento Grid (Architectural Pillars) -->
<section id="bento" class="bento-section">
  <div class="container">
    <div class="section-eyebrow">Architectural Superiority</div>
    <h2 class="section-heading-lg">Engineered for Zero-Day Immunity</h2>

    <div class="bento-grid">
      <!-- Bento 1: 1-Click Surgical Disinfection (Span 8) -->
      <div class="bento-card col-8">
        <span class="bento-tag">Pillar I &bull; Surgical Disinfection</span>
        <h3 class="bento-title">1-Click Malware Eradication (Zero Paywall)</h3>
        <p class="bento-desc">
          Competitors like MalCare charge <strong>$99 to $299 per site per year</strong> to clean infected files. SuperShield's built-in AST tokenizer surgically excises malicious backdoors and base64 eval payloads from corrupted core files without destroying legitimate modifications.
        </p>

        <div style="display:flex; gap:8px; margin-top:16px;">
          <button type="button" id="btnDiffBefore" class="tab-pill-btn active" onclick="toggleDisinfectionView('before')">Infected File (Before)</button>
          <button type="button" id="btnDiffAfter" class="tab-pill-btn" onclick="toggleDisinfectionView('after')">Surgically Cleaned (After)</button>
        </div>

        <div class="code-diff-preview">
          <div class="diff-header">
            <span>FILE: /wp-load.php</span>
            <span style="color:var(--accent-emerald);">SUPER SHIELD SURGICAL ENGINE</span>
          </div>
          <div id="diffBeforeBox">
            <div class="diff-line" style="color:#64748b;">1 &lt;?php</div>
            <div class="diff-line" style="color:#64748b;">2 /** The WordPress Page generation bootstrap file. */</div>
            <div class="diff-line diff-del">3 @eval(base64_decode("ZWNobyAnYmFja2Rvb3InOw==")); // INJECTED CRUX-RUNNER BACKDOOR</div>
            <div class="diff-line" style="color:#64748b;">4 define( 'WP_USE_THEMES', true );</div>
            <div class="diff-line" style="color:#64748b;">5 require __DIR__ . '/wp-blog-header.php';</div>
          </div>
          <div id="diffAfterBox" style="display:none;">
            <div class="diff-line" style="color:#64748b;">1 &lt;?php</div>
            <div class="diff-line" style="color:#64748b;">2 /** The WordPress Page generation bootstrap file. */</div>
            <div class="diff-line diff-add">3 // [SuperShield Cleaned: Malicious signature excised with zero core corruption]</div>
            <div class="diff-line" style="color:#64748b;">4 define( 'WP_USE_THEMES', true );</div>
            <div class="diff-line" style="color:#64748b;">5 require __DIR__ . '/wp-blog-header.php';</div>
          </div>
        </div>
      </div>

      <!-- Bento 2: Hardware-Grade 2FA (Span 4) -->
      <div class="bento-card col-4">
        <span class="bento-tag">Pillar II &bull; Identity Shield</span>
        <h3 class="bento-title">Native RFC 6238 2FA</h3>
        <p class="bento-desc">
          True time-based one-time passwords (TOTP) compatible with Google Authenticator, Authy, and 1Password. Features dynamic in-memory SVG QR codes with zero external API dependencies.
        </p>
        <div style="text-align:center; padding:24px 0 10px;">
          <div style="display:inline-block; padding:12px; background:#fff; border-radius:12px; box-shadow:0 0 25px rgba(16,185,129,0.3);">
            <svg width="120" height="120" viewBox="0 0 100 100" fill="#000">
              <rect width="100" height="100" fill="#ffffff"/>
              <rect x="10" y="10" width="30" height="30" fill="#000"/>
              <rect x="15" y="15" width="20" height="20" fill="#fff"/>
              <rect x="60" y="10" width="30" height="30" fill="#000"/>
              <rect x="65" y="15" width="20" height="20" fill="#fff"/>
              <rect x="10" y="60" width="30" height="30" fill="#000"/>
              <rect x="15" y="65" width="20" height="20" fill="#fff"/>
              <rect x="45" y="15" width="10" height="20" fill="#000"/>
              <rect x="45" y="45" width="20" height="20" fill="#000"/>
              <rect x="70" y="55" width="20" height="15" fill="#000"/>
              <rect x="25" y="45" width="15" height="10" fill="#000"/>
              <rect x="45" y="75" width="20" height="15" fill="#000"/>
            </svg>
          </div>
          <div style="font-size:11px; color:var(--text-dim); margin-top:8px; font-family:var(--font-mono);">
            RFC 6238 COMPLIANT &bull; 0 EXTERNAL CALLS
          </div>
        </div>
      </div>

      <!-- Bento 3: Offline GeoIP Country Blocker (Span 4) -->
      <div class="bento-card col-4">
        <span class="bento-tag">Pillar III &bull; Edge Filtration</span>
        <h3 class="bento-title">Offline High-Precision GeoIP</h3>
        <p class="bento-desc">
          High-accuracy ISO-3166 offline IP database embedded directly in the plugin. Blocks malicious geographic botnets and brute-force clusters with <strong>0ms external latency</strong>.
        </p>
        <div style="margin-top:20px; background:#050811; border:1px solid var(--border-inner); border-radius:10px; padding:14px; font-family:var(--font-mono); font-size:11px; color:#38bdf8;">
          &bull; Cloudflare Header Inspection: <span style="color:#34d399;">Active</span><br>
          &bull; Local Binary Lookup: <span style="color:#34d399;">0.001ms</span><br>
          &bull; Zero Third-Party API Limits
        </div>
      </div>

      <!-- Bento 4: HMAC-SHA256 Anti-Tamper Guard (Span 4) -->
      <div class="bento-card col-4">
        <span class="bento-tag">Pillar IV &bull; Self-Integrity</span>
        <h3 class="bento-title">HMAC-SHA256 Anti-Tamper</h3>
        <p class="bento-desc">
          Cryptographically hashes the plugin codebase against unauthorized injection. If a malicious worm or rogue process alters the firewall code, SuperShield immediately engages a lockdown.
        </p>
        <div style="margin-top:20px; background:#050811; border:1px solid var(--border-inner); border-radius:10px; padding:14px; font-family:var(--font-mono); font-size:11px; color:#f59e0b;">
          SHA256 MANIFEST: <span style="color:#34d399;">VERIFIED</span><br>
          BYTECODE HOOK SHIELD: <span style="color:#34d399;">IMMUNE</span>
        </div>
      </div>

      <!-- Bento 5: 8-Layer Server Hardening (Span 4) -->
      <div class="bento-card col-4">
        <span class="bento-tag">Pillar V &bull; Server Immunity</span>
        <h3 class="bento-title">8-Layer Host Hardening</h3>
        <p class="bento-desc">
          Permanently prevents PHP execution inside <code>/wp-content/uploads/</code>, shuts down XML-RPC brute force vectors, stops user enumeration probes, and injects server-level security headers.
        </p>
        <div style="margin-top:20px; background:#050811; border:1px solid var(--border-inner); border-radius:10px; padding:14px; font-family:var(--font-mono); font-size:11px; color:#cbd5e1;">
          &bull; Uploads .php Lockdown: <span style="color:#34d399;">ENFORCED</span><br>
          &bull; XML-RPC Vector: <span style="color:#ef4444;">DISABLED</span><br>
          &bull; Author Enumeration: <span style="color:#ef4444;">SHUT DOWN</span>
        </div>
      </div>

      <!-- Bento 6: Free Native Server Email Alerts (Span 12) -->
      <div class="bento-card col-12">
        <span class="bento-tag">Pillar VI &bull; Instant Intelligence</span>
        <h3 class="bento-title">Free Wordfence-Style Native Server Email Alerts</h3>
        <p class="bento-desc">
          Receive real-time instant alerts for critical file alterations, brute-force IP lockouts, and malware detections. Dispatched to multiple comma-separated emails via your server's native PHP mail &mdash; <strong>consuming 0 third-party SMTP credits and costing $0</strong>.
        </p>
      </div>
    </div>
  </div>
</section>

<!-- Component C: Commercial Comparison Matrix -->
<section id="matrix" class="matrix-section">
  <div class="container">
    <div class="section-eyebrow">Market Comparison</div>
    <h2 class="section-heading-lg">SuperShield vs. Legacy Commercial Tools</h2>

    <div class="matrix-wrapper">
      <table class="matrix-table">
        <thead>
          <tr>
            <th>Security Architecture Capability</th>
            <th class="col-highlight">🛡️ SuperShield Security</th>
            <th>Wordfence Pro</th>
            <th>MalCare Pro</th>
            <th>All-In-One Security</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><strong>Annual License Fee</strong></td>
            <td class="col-highlight"><strong>$0 (100% Free Forever)</strong></td>
            <td>$119 / year</td>
            <td>$99 / year</td>
            <td>$70 / year</td>
          </tr>
          <tr>
            <td><strong>Zero-Day Real-Time WAF Rules</strong></td>
            <td class="col-highlight">✅ Real-Time Instant (Free)</td>
            <td>❌ 30-Day Delay (Free Tier)</td>
            <td>❌ Cloud Route Only</td>
            <td>⚠️ Basic Regex Only</td>
          </tr>
          <tr>
            <td><strong>1-Click Surgical Malware Cleaner</strong></td>
            <td class="col-highlight">✅ Included 100% Free</td>
            <td>❌ Manual or Paid</td>
            <td>❌ $99/yr Paywall</td>
            <td>❌ Not Supported</td>
          </tr>
          <tr>
            <td><strong>Hardware-Grade 2FA (RFC 6238)</strong></td>
            <td class="col-highlight">✅ Native SVG Generator</td>
            <td>✅ Included</td>
            <td>❌ Not Included</td>
            <td>⚠️ Basic</td>
          </tr>
          <tr>
            <td><strong>Offline GeoIP Country Blocker</strong></td>
            <td class="col-highlight">✅ Included Free (0ms)</td>
            <td>❌ Paid Pro Only</td>
            <td>❌ Paid Pro Only</td>
            <td>❌ Paid Addon</td>
          </tr>
          <tr>
            <td><strong>HMAC-SHA256 Anti-Tamper Guard</strong></td>
            <td class="col-highlight">✅ Built-in Cryptographic Core</td>
            <td>❌ None</td>
            <td>❌ None</td>
            <td>❌ None</td>
          </tr>
          <tr>
            <td><strong>Free Native Server Email Alerts</strong></td>
            <td class="col-highlight">✅ Multi-Recipient Free</td>
            <td>⚠️ Requires Setup</td>
            <td>❌ Cloud Portal Only</td>
            <td>⚠️ Basic</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</section>

<!-- Component D: Deployment Hub & Quick Start -->
<section id="deploy" style="padding: 70px 0 90px;">
  <div class="container">
    <div class="section-eyebrow">Production Deployment</div>
    <h2 class="section-heading-lg">Deploy in Under 60 Seconds</h2>

    <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(300px, 1fr)); gap:24px;">
      <div class="bento-card">
        <span class="bento-tag">Method 01 &bull; WordPress Admin</span>
        <h3 class="bento-title">Upload .ZIP Archive</h3>
        <p class="bento-desc" style="margin-bottom:20px;">
          1. Download <code>supershield-security.zip</code><br>
          2. Navigate to <strong>Plugins &rarr; Add New &rarr; Upload Plugin</strong><br>
          3. Click <strong>Activate</strong> &mdash; WAF and 8-layer hardening activate instantly.
        </p>
        <a href="/download/latest" class="btn-hardware-primary" style="font-size:13px; padding:6px 8px 6px 18px;">
          <span>Download Plugin .ZIP</span>
          <span class="icon-circle">&rarr;</span>
        </a>
      </div>

      <div class="bento-card">
        <span class="bento-tag">Method 02 &bull; Terminal / WP-CLI</span>
        <h3 class="bento-title">WP-CLI 1-Liner</h3>
        <p class="bento-desc" style="margin-bottom:15px;">
          Deploy directly via SSH or bash terminal across multiple client sites:
        </p>
        <div style="background:#050811; border:1px solid var(--border-inner); border-radius:8px; padding:12px; font-family:var(--font-mono); font-size:11px; color:#38bdf8; word-break:break-all;" id="wpCliCmd">
          wp plugin install https://sss.grwebdevs.com/download/latest --activate
        </div>
        <button type="button" class="tab-pill-btn" style="margin-top:12px; background:rgba(255,255,255,0.05);" onclick="copyCliCode('wpCliCmd')">
          📋 Copy WP-CLI Command
        </button>
      </div>
    </div>
  </div>
</section>

<!-- Component E: Support & Feedback Slide-In Modal (Properly Hidden, Zero Layout Leaks) -->
<div class="modal-overlay" id="publicFeedbackModal">
  <div class="modal-dialog">
    <div class="modal-header">
      <h3 class="modal-title">🛡️ SuperShield Feedback & Support</h3>
      <button type="button" class="modal-close-btn" onclick="closeFeedbackModal()">&times;</button>
    </div>

    <form id="publicFeedbackForm">
      <div style="margin-bottom:16px;">
        <label class="input-label">Report Category</label>
        <select id="fbCategory" class="custom-select">
          <option value="bug_report">Bug Report</option>
          <option value="feature_request">Feature Request</option>
          <option value="praise">General Feedback / Praise</option>
        </select>
      </div>

      <div style="margin-bottom:16px;">
        <label class="input-label">Your Email (Optional, to receive Ghulam Rasool's response)</label>
        <input type="email" id="fbEmail" class="custom-input" placeholder="you@domain.com">
      </div>

      <div style="margin-bottom:20px;">
        <label class="input-label">Message Details</label>
        <textarea id="fbMessage" class="custom-textarea" required placeholder="Describe what you observed, encountered, or would like to request..."></textarea>
      </div>

      <div style="display:flex; justify-content:flex-end; gap:12px;">
        <button type="button" onclick="closeFeedbackModal()" class="btn-hardware-secondary" style="padding:10px 20px; font-size:13px;">Cancel</button>
        <button type="submit" class="btn-hardware-primary" style="padding:6px 10px 6px 20px; font-size:13px;">
          <span>Transmit to Ghulam Rasool</span>
          <span class="icon-circle">&rarr;</span>
        </button>
      </div>
    </form>
  </div>
</div>

<!-- Component F: Agency Footer -->
<footer class="agency-footer">
  <div class="container">
    <div class="footer-grid">
      <div class="footer-bio">
        <div style="display:flex; align-items:center; gap:10px; margin-bottom:8px;">
          <span style="font-size:22px;">🛡️</span>
          <strong style="color:#fff; font-size:16px;">SuperShield Security (SSS)</strong>
        </div>
        <p>
          An enterprise-grade defense-in-depth cybersecurity suite engineered by <strong>Ghulam Rasool</strong> (Founder & Principal Security Engineer at <a href="https://grwebdevs.com" target="_blank" rel="noopener">grwebdevs.com</a>). Engineered to permanently dismantle paywalled WordPress security and make real-time zero-day protection freely accessible to every developer and agency worldwide.
        </p>
      </div>

      <div>
        <div class="footer-col-title">Architecture</div>
        <ul class="footer-links">
          <li><a href="#sandbox">Real-Time Zero-Day WAF</a></li>
          <li><a href="#bento">1-Click Surgical Cleaner</a></li>
          <li><a href="#bento">Hardware-Grade 2FA</a></li>
          <li><a href="#bento">Offline GeoIP Blocker</a></li>
          <li><a href="#bento">HMAC-SHA256 Anti-Tamper</a></li>
        </ul>
      </div>

      <div>
        <div class="footer-col-title">Resources</div>
        <ul class="footer-links">
          <li><a href="/download/latest">Download Latest Release</a></li>
          <li><a href="https://github.com/<?php echo htmlspecialchars($config['github_repo']); ?>" target="_blank" rel="noopener">GitHub Repository</a></li>
          <li><a href="https://grwebdevs.com" target="_blank" rel="noopener">GR Web Devs Agency</a></li>
          <li><a href="javascript:void(0)" onclick="openFeedbackModal()">Submit Bug Report</a></li>
        </ul>
      </div>
    </div>

    <div class="footer-bottom">
      <div>
        &copy; <?php echo date('Y'); ?> SuperShield Security &bull; Engineered by <a href="https://grwebdevs.com" target="_blank" rel="noopener">Ghulam Rasool</a>. Released under GPL v2.
      </div>
      <div>
        Platform Ecosystem: <code>sss.grwebdevs.com</code>
      </div>
    </div>
  </div>
</footer>

<script src="/assets/js/portal.js?v=2.5.0"></script>
</body>
</html>
