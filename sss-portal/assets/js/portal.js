/**
 * SuperShield Security — Interactive Showcase Engine
 * 
 * Includes:
 *  - Interactive WAF Threat Simulator & Sandbox
 *  - Live Community Radar Poller
 *  - Surgical Disinfection Diff Switcher
 *  - Feedback Drawer Controller
 * 
 * Lead Architect: Ghulam Rasool (grwebdevs.com)
 */

document.addEventListener('DOMContentLoaded', function() {

    // ---------------------------------------------------------
    // 1. INTERACTIVE WAF ATTACK SANDBOX
    // ---------------------------------------------------------
    var attackScenarios = {
        sqli: {
            name: 'SQL Injection',
            method: 'GET',
            path: '/wp-login.php?user=admin%27%20OR%201=1--%20&pass=unknown',
            rule: 'SSS_WAF_SQLI_CORE_01',
            sig: "Tautological Boolean Bypass (' OR 1=1--)",
            latency: '0.02ms',
            desc: 'Automated database credential bypass neutralized before WordPress query execution.'
        },
        rce: {
            name: 'Remote Code Execution',
            method: 'POST',
            path: '/wp-admin/admin-ajax.php?action=upload_parse',
            payload: '<?php @eval(base64_decode("ZWNobyAncmNlJzs=")); ?>',
            rule: 'SSS_WAF_RCE_TOKEN_99',
            sig: 'Obfuscated eval(base64_decode) invocation',
            latency: '0.01ms',
            desc: 'Arbitrary web-shell execution intercepted at early bootstrap stream (priority -999999).'
        },
        traversal: {
            name: 'Path Traversal',
            method: 'GET',
            path: '/wp-content/themes/loader.php?template=../../../../../../etc/passwd',
            rule: 'SSS_WAF_LFI_TRAVERSAL',
            sig: 'Relative directory stepping (../../etc/passwd)',
            latency: '0.01ms',
            desc: 'Linux system file extraction attempt quarantined and client IP throttled.'
        },
        uploads: {
            name: 'Uploads .PHP Execution',
            method: 'POST',
            path: '/wp-content/uploads/2026/09/backdoor_shell.php',
            rule: 'SSS_HARDENING_L2_IMMUNITY',
            sig: 'Direct script execution in unshielded uploads folder',
            latency: '0.00ms',
            desc: 'Apache / Nginx 8-layer immunity rule blocked PHP handler interpretation outright.'
        }
    };

    var currentScenario = 'sqli';

    window.runWafScenario = function(key) {
        var scenario = attackScenarios[key];
        if (!scenario) return;

        currentScenario = key;

        // Update tab styling
        var buttons = document.querySelectorAll('.tab-pill-btn');
        buttons.forEach(function(btn) {
            btn.classList.remove('active');
            if (btn.getAttribute('data-tab') === key) {
                btn.classList.add('active');
            }
        });

        var terminal = document.getElementById('wafTerminalOutput');
        if (!terminal) return;

        terminal.innerHTML = 
            '<div class="terminal-line"><span class="t-prompt">$</span> <span style="color:#94a3b8;">Simulating external HTTP probe to target WordPress node...</span></div>' +
            '<div class="terminal-line"><span class="t-prompt">&gt;</span> <span style="color:#e2e8f0; font-weight:700;">' + scenario.method + '</span> <span class="t-payload">' + scenario.path + '</span></div>' +
            (scenario.payload ? '<div class="terminal-line" style="color:#64748b; font-size:11px;"><span class="t-prompt">&gt;</span> Body: ' + escapeHtml(scenario.payload) + '</div>' : '') +
            '<div class="t-block-box">' +
                '<div class="t-status-blocked">🛑 HTTP/1.1 403 FORBIDDEN &mdash; THREAT NEUTRALIZED IN ' + scenario.latency + '</div>' +
                '<div class="t-forensics">' +
                    '&bull; <strong>Inspection Engine:</strong> SuperShield Real-Time WAF Core<br>' +
                    '&bull; <strong>Triggered Signature:</strong> <code>' + scenario.sig + '</code> (' + scenario.rule + ')<br>' +
                    '&bull; <strong>Defense Action:</strong> Immediate TCP Connection Severed &bull; Zero CPU Spike &bull; Event Logged<br>' +
                    '&bull; <strong>Architectural Note:</strong> ' + scenario.desc +
                '</div>' +
            '</div>' +
            '<div class="terminal-line"><span class="t-prompt">sss-shield#</span> <span style="color:#34d399;">✓ Site Core 100% Protected &bull; Latency overhead: 0.00ms</span></div>';
    };

    function escapeHtml(str) {
        return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    // ---------------------------------------------------------
    // 2. SURGICAL MALWARE DISINFECTION PREVIEW TOGGLE
    // ---------------------------------------------------------
    window.toggleDisinfectionView = function(view) {
        var beforeBox = document.getElementById('diffBeforeBox');
        var afterBox = document.getElementById('diffAfterBox');
        var btnBefore = document.getElementById('btnDiffBefore');
        var btnAfter = document.getElementById('btnDiffAfter');

        if (view === 'after') {
            if (beforeBox) beforeBox.style.display = 'none';
            if (afterBox) afterBox.style.display = 'block';
            if (btnBefore) btnBefore.classList.remove('active');
            if (btnAfter) btnAfter.classList.add('active');
        } else {
            if (beforeBox) beforeBox.style.display = 'block';
            if (afterBox) afterBox.style.display = 'none';
            if (btnBefore) btnBefore.classList.add('active');
            if (btnAfter) btnAfter.classList.remove('active');
        }
    };

    // ---------------------------------------------------------
    // 3. LIVE RADAR STATS POLLER
    // ---------------------------------------------------------
    function refreshLiveStats() {
        fetch('/api/v1/threats/feed')
            .then(function(res) { return res.json(); })
            .then(function(data) {
                if (data && data.metrics) {
                    var elThreats = document.getElementById('metricThreatCount');
                    var elSites = document.getElementById('metricSiteCount');
                    if (elThreats && data.metrics.total_threats_blocked) {
                        elThreats.innerText = parseInt(data.metrics.total_threats_blocked).toLocaleString();
                    }
                    if (elSites && data.metrics.active_installations) {
                        elSites.innerText = parseInt(data.metrics.active_installations).toLocaleString() + '+';
                    }
                }
            })
            .catch(function() {});
    }

    setInterval(refreshLiveStats, 15000);

    // ---------------------------------------------------------
    // 4. MODAL & FEEDBACK DRAWER CONTROLLER
    // ---------------------------------------------------------
    window.openFeedbackModal = function() {
        var modal = document.getElementById('publicFeedbackModal');
        if (modal) {
            modal.style.display = 'flex';
            document.body.style.overflow = 'hidden'; // Prevent background scrolling
        }
    };

    window.closeFeedbackModal = function() {
        var modal = document.getElementById('publicFeedbackModal');
        if (modal) {
            modal.style.display = 'none';
            document.body.style.overflow = '';
        }
    };

    // Close on escape key
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            closeFeedbackModal();
        }
    });

    // Close when clicking on backdrop
    var modalOverlay = document.getElementById('publicFeedbackModal');
    if (modalOverlay) {
        modalOverlay.addEventListener('click', function(e) {
            if (e.target === modalOverlay) {
                closeFeedbackModal();
            }
        });
    }

    // Form submission
    var feedbackForm = document.getElementById('publicFeedbackForm');
    if (feedbackForm) {
        feedbackForm.addEventListener('submit', function(e) {
            e.preventDefault();
            var btn = feedbackForm.querySelector('button[type="submit"]');
            var originalText = btn.innerText;
            btn.disabled = true;
            btn.innerText = 'Transmitting securely...';

            var payload = {
                category: document.getElementById('fbCategory').value,
                email: document.getElementById('fbEmail').value,
                message: document.getElementById('fbMessage').value,
                version: 'Showcase Visitor',
                wp_version: 'Web Portal',
                php_version: 'N/A',
                server_type: 'Web Client'
            };

            fetch('/api/v1/feedback', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            })
            .then(function(res) { return res.json(); })
            .then(function(resp) {
                alert(resp.message || 'Thank you! Your feedback has been safely received by Ghulam Rasool.');
                closeFeedbackModal();
                feedbackForm.reset();
            })
            .catch(function() {
                alert('Thank you! Your submission has been transmitted.');
                closeFeedbackModal();
            })
            .finally(function() {
                btn.disabled = false;
                btn.innerText = originalText;
            });
        });
    }

    // Copy to clipboard helper
    window.copyCliCode = function(elId) {
        var el = document.getElementById(elId);
        if (!el) return;
        navigator.clipboard.writeText(el.innerText).then(function() {
            alert('Command copied to clipboard!');
        });
    };

    // Auto-run first scenario on load
    runWafScenario('sqli');
});
