/**
 * SuperShield Security — Cybersecurity Command Center JS Controller
 * Version 2.0.0 Enterprise Production Suite
 * Author: Ghulam Rasool (grwebdevs.com)
 */
(function($) {
	'use strict';

	$(document).ready(function() {

		function showAlert(message, isSuccess) {
			var $alert = $('#supershield-alert-box');
			if (!$alert.length) return;
			$alert.removeClass('success error')
				.addClass(isSuccess ? 'success' : 'error')
				.html(message)
				.slideDown();
			setTimeout(function() {
				$alert.slideUp();
			}, 4500);
		}

		// 1. Settings Form AJAX Submission
		$('.supershield-settings-form').on('submit', function(e) {
			e.preventDefault();

			var $form = $(this);
			var $btn = $form.find('button[type="submit"]');
			var originalText = $btn.text();

			$btn.prop('disabled', true).text('Applying Shield Rules...');

			var formData = $form.serialize();
			formData += '&action=supershield_save_settings&nonce=' + supershield_vars.nonce;

			$.post(supershield_vars.ajax_url, formData, function(response) {
				$btn.prop('disabled', false).text(originalText);
				if (response.success) {
					showAlert(response.data.message || 'Settings saved successfully!', true);
				} else {
					showAlert(response.data.message || 'Failed to save settings.', false);
				}
			}).fail(function() {
				$btn.prop('disabled', false).text(originalText);
				showAlert('Server communication timeout. Please try again.', false);
			});
		});

		// 2. Full Security Scan Runner
		$('#btn-start-security-scan').on('click', function(e) {
			e.preventDefault();

			var $btn = $(this);
			var $statusText = $('#scan-status-text');
			var $progressBar = $('#scan-progress-bar');

			$btn.prop('disabled', true).text('Scanning in progress...');
			$statusText.text('SuperShield Scanner analyzing core diffs, uploads, dot droppers, entropy, and database...');
			$progressBar.css('width', '35%');

			$.post(supershield_vars.ajax_url, {
				action: 'supershield_start_scan',
				nonce: supershield_vars.nonce
			}, function(response) {
				$btn.prop('disabled', false).text('Run Full Deep Scan');
				$progressBar.css('width', '100%');

				if (response.success) {
					var data = response.data;
					$statusText.html('<strong>Scan Completed in ' + data.duration + 's.</strong> Files Scanned: ' + data.scanned_files + ' | Threats Found: ' + data.threats_found);
					setTimeout(function() {
						location.reload();
					}, 1200);
				} else {
					$statusText.text('Scan failed: ' + (response.data.message || 'Unknown scan error.'));
				}
			}).fail(function() {
				$btn.prop('disabled', false).text('Run Full Deep Scan');
				$statusText.text('Error: Server timed out during scan. Please check PHP memory limit.');
			});
		});

		// 3. 1-Click Surgical Disinfection
		$(document).on('click', '.btn-surgical-clean', function(e) {
			e.preventDefault();

			var $btn = $(this);
			var issueId = $btn.data('id');

			if (!confirm('Execute 1-Click Surgical Disinfection? SuperShield will create a safe backup and excise the malicious code.')) {
				return;
			}

			$btn.prop('disabled', true).text('Disinfecting...');

			$.post(supershield_vars.ajax_url, {
				action: 'supershield_surgical_clean',
				nonce: supershield_vars.nonce,
				issue_id: issueId
			}, function(response) {
				if (response.success) {
					showAlert(response.data.message || 'Threat surgically eradicated.', true);
					$btn.closest('tr').fadeOut(400, function() { $(this).remove(); });
				} else {
					alert(response.data.message || 'Disinfection failed.');
					$btn.prop('disabled', false).text('Surgical Disinfect');
				}
			}).fail(function() {
				$btn.prop('disabled', false).text('Surgical Disinfect');
				alert('Server communication error during disinfection.');
			});
		});

		// 4. 1-Click Restore Core File Diff
		$(document).on('click', '.btn-restore-core', function(e) {
			e.preventDefault();

			var $btn = $(this);
			var filePath = $btn.data('path');

			if (!confirm('Restore this core file from official pristine WordPress release? Existing file will be backed up.')) {
				return;
			}

			$btn.prop('disabled', true).text('Restoring...');

			$.post(supershield_vars.ajax_url, {
				action: 'supershield_restore_core',
				nonce: supershield_vars.nonce,
				file_path: filePath
			}, function(response) {
				if (response.success) {
					showAlert(response.data.message || 'Core file restored successfully!', true);
					$btn.closest('tr').fadeOut(400, function() { $(this).remove(); });
				} else {
					alert(response.data.message || 'Failed to restore core file.');
					$btn.prop('disabled', false).text('Restore Core Diff');
				}
			}).fail(function() {
				$btn.prop('disabled', false).text('Restore Core Diff');
				alert('Server communication error.');
			});
		});

		// 5. Quarantine Malicious File
		$(document).on('click', '.btn-quarantine-file', function(e) {
			e.preventDefault();

			var $btn = $(this);
			var filePath = $btn.data('path');

			if (!confirm('Isolate and move this file into the safe quarantine vault? Permissions will be locked to 0400.')) {
				return;
			}

			$btn.prop('disabled', true).text('Quarantining...');

			$.post(supershield_vars.ajax_url, {
				action: 'supershield_quarantine_file',
				nonce: supershield_vars.nonce,
				file_path: filePath
			}, function(response) {
				if (response.success) {
					showAlert(response.data.message || 'File safely quarantined.', true);
					$btn.closest('tr').fadeOut(400, function() { $(this).remove(); });
				} else {
					alert(response.data.message || 'Could not quarantine file.');
					$btn.prop('disabled', false).text('Quarantine File');
				}
			});
		});

		// 6. Unblock IP Address
		$(document).on('click', '.btn-unblock-ip', function(e) {
			e.preventDefault();

			var $btn = $(this);
			var ip = $btn.data('ip');

			if (!confirm('Unblock IP address ' + ip + '?')) {
				return;
			}

			$.post(supershield_vars.ajax_url, {
				action: 'supershield_unblock_ip',
				nonce: supershield_vars.nonce,
				ip: ip
			}, function(response) {
				if (response.success) {
					$btn.closest('tr').fadeOut(300, function() { $(this).remove(); });
					showAlert('IP unblocked successfully.', true);
				} else {
					alert(response.data.message || 'Failed to unblock IP.');
				}
			});
		});

		// 7. Clear Audit Logs
		$('#btn-clear-supershield-logs').on('click', function(e) {
			e.preventDefault();

			if (!confirm('Permanently clear all security audit trail logs?')) {
				return;
			}

			var $btn = $(this);
			$btn.prop('disabled', true).text('Clearing...');

			$.post(supershield_vars.ajax_url, {
				action: 'supershield_clear_logs',
				nonce: supershield_vars.nonce
			}, function(response) {
				if (response.success) {
					location.reload();
				} else {
					alert(response.data.message || 'Failed to clear logs.');
					$btn.prop('disabled', false).text('Clear Audit Trail');
				}
			});
		});

		// 8. 2FA Configuration Flow
		$('#btn-start-2fa-setup, #btn-reconfig-2fa').on('click', function(e) {
			e.preventDefault();

			var $btn = $(this);
			$btn.prop('disabled', true).text('Generating 2FA Keys...');

			$.post(supershield_vars.ajax_url, {
				action: 'supershield_setup_2fa',
				nonce: supershield_vars.nonce
			}, function(response) {
				$btn.prop('disabled', false).text('Re-Configure 2FA');
				if (response.success) {
					var data = response.data;
					$('#2fa-qr-container').html(data.qr_svg);
					$('#2fa-secret-text').text(data.secret);

					var backupHtml = '';
					if (data.backup_codes && data.backup_codes.length) {
						$.each(data.backup_codes, function(idx, code) {
							backupHtml += '<div>' + (idx + 1) + '. ' + code + '</div>';
						});
					}
					$('#2fa-backup-codes-container').html(backupHtml);
					$('#supershield-2fa-setup-box').slideDown();
				} else {
					alert(response.data.message || 'Could not generate 2FA session.');
				}
			});
		});

		// Verify and Activate 2FA
		$('#btn-confirm-2fa').on('click', function(e) {
			e.preventDefault();

			var code = $('#2fa-verification-code').val().trim();
			if (!code || code.length !== 6) {
				alert('Please enter a valid 6-digit TOTP code from your authenticator app.');
				return;
			}

			var $btn = $(this);
			$btn.prop('disabled', true).text('Verifying...');

			$.post(supershield_vars.ajax_url, {
				action: 'supershield_verify_2fa',
				nonce: supershield_vars.nonce,
				code: code
			}, function(response) {
				$btn.prop('disabled', false).text('Verify & Activate');
				if (response.success) {
					alert(response.data.message || '2FA Activated!');
					location.reload();
				} else {
					alert(response.data.message || 'Invalid code.');
				}
			});
		});

		// Disable 2FA
		$('#btn-disable-2fa').on('click', function(e) {
			e.preventDefault();

			if (!confirm('Are you sure you want to deactivate Two-Factor Authentication for your account?')) {
				return;
			}

			$.post(supershield_vars.ajax_url, {
				action: 'supershield_disable_2fa',
				nonce: supershield_vars.nonce
			}, function(response) {
				if (response.success) {
					alert(response.data.message || '2FA Deactivated.');
					location.reload();
				}
			});
		});

		// 9. Export Diagnostics Bundle
		$('#btn-export-diagnostics').on('click', function(e) {
			e.preventDefault();

			var $btn = $(this);
			$btn.prop('disabled', true).text('Compiling Report...');

			$.post(supershield_vars.ajax_url, {
				action: 'supershield_export_diagnostics',
				nonce: supershield_vars.nonce
			}, function(response) {
				$btn.prop('disabled', false).text('Export System Report');
				if (response.success && response.data.markdown) {
					$('#diagnostics-output').val(response.data.markdown);
					showAlert('Diagnostic report generated! You can copy it below.', true);
				}
			});
		});

		// Copy Diagnostics Output
		$('#btn-copy-diagnostics').on('click', function(e) {
			e.preventDefault();
			var $txt = $('#diagnostics-output');
			if (!$txt.val()) {
				alert('Please generate the report first.');
				return;
			}
			$txt.select();
			document.execCommand('copy');
			showAlert('Diagnostics copied to clipboard!', true);
		});

		// 10. Feedback Modal Interactivity
		$('#btn-open-feedback-modal').on('click', function(e) {
			e.preventDefault();
			$('#supershield-feedback-modal').fadeIn(200);
		});

		$('.btn-modal-close, .supershield-modal-backdrop').on('click', function(e) {
			$('#supershield-feedback-modal').fadeOut(200);
		});

		$('#supershield-feedback-form').on('submit', function(e) {
			e.preventDefault();

			var category = $('#feedback-category').val();
			var message = $('#feedback-message').val().trim();
			var email = $('#feedback-email').val().trim();

			if (!message) return;

			var $btn = $(this).find('button[type="submit"]');
			$btn.prop('disabled', true).text('Submitting...');

			$.post(supershield_vars.ajax_url, {
				action: 'supershield_submit_feedback',
				nonce: supershield_vars.nonce,
				category: category,
				message: message,
				email: email
			}, function(response) {
				$btn.prop('disabled', false).text('Submit to Engineering Lead');
				$('#supershield-feedback-modal').fadeOut(200);
				showAlert(response.data.message || 'Thank you for your feedback!', true);
				$('#feedback-message').val('');
			});
		});

		// 11. GitHub Auto-Updater Check
		$('#btn-check-github-updates').on('click', function(e) {
			e.preventDefault();

			var $btn = $(this);
			$btn.prop('disabled', true).text('Checking GitHub...');

			$.post(supershield_vars.ajax_url, {
				action: 'supershield_check_updates',
				nonce: supershield_vars.nonce
			}, function(response) {
				$btn.prop('disabled', false).text('Check for Updates Now');
				if (response.success) {
					var data = response.data;
					if (data.has_update) {
						$('#update-status-pill').html('<span class="badge-tag critical">Update Available: v' + data.latest + '</span>');
						$('#update-version-title').text('New Release Available: SuperShield v' + data.latest);
						$('#update-changelog-text').text(data.changelog || 'Bug fixes and performance improvements.');
						$('#btn-download-update-pkg').attr('href', data.download_url);
						$('#update-details-box').slideDown();
					} else {
						$('#update-status-pill').html('<span class="badge-tag safe">Up to Date (v' + data.current + ')</span>');
						showAlert('You are running the latest version of SuperShield Security (v' + data.current + ').', true);
					}
				} else {
					showAlert(response.data.message || 'Check failed.', false);
				}
			});
		});

	});
})(jQuery);
