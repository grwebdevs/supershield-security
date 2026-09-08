/**
 * SuperShield Security — Administrative Control Center
 * Version 2.2.1 Enterprise Production Suite
 * Author: Ghulam Rasool <grwebdevs.com>
 */
(function($) {
	'use strict';

	$(document).ready(function() {

		var alertTimer = null;
		function showAlert(message, isSuccess) {
			var $alert = $('#supershield-alert-box');
			if (!$alert.length) {
				$('body').append('<div id="supershield-alert-box" class="supershield-alert"></div>');
				$alert = $('#supershield-alert-box');
			}

			if (alertTimer) {
				clearTimeout(alertTimer);
			}

			var iconClass = isSuccess ? 'dashicons-yes-alt' : 'dashicons-warning';
			var html = '<span class="dashicons ' + iconClass + ' supershield-alert-icon"></span>' +
				'<div class="supershield-alert-message">' + message + '</div>' +
				'<button type="button" class="supershield-alert-close" aria-label="Dismiss">&times;</button>';

			$alert.removeClass('success error')
				.addClass(isSuccess ? 'success' : 'error')
				.html(html)
				.stop(true, true)
				.css('display', 'flex')
				.hide()
				.fadeIn(200);

			alertTimer = setTimeout(function() {
				$alert.fadeOut(300);
			}, 4500);
		}

		$(document).on('click', '.supershield-alert-close', function() {
			if (alertTimer) clearTimeout(alertTimer);
			$('#supershield-alert-box').fadeOut(200);
		});

		function setButtonLoading($btn, text) {
			if (!$btn || !$btn.length) return;
			$btn = $($btn[0]);
			if (!$btn.data('original-html')) {
				$btn.data('original-html', $btn.html());
			}
			$btn.prop('disabled', true).html('<span class="dashicons dashicons-update ss-spin" style="font-size:14px; width:14px; height:14px; margin-top:2px;"></span> ' + (text || 'Processing...'));
		}

		function restoreButton($btn) {
			if (!$btn || !$btn.length) return;
			$btn = $($btn[0]);
			if ($btn.data('original-html')) {
				$btn.prop('disabled', false).html($btn.data('original-html'));
			} else {
				$btn.prop('disabled', false);
			}
		}

		// Track which submit button was clicked in any settings form
		$(document).on('click', '.supershield-settings-form button[type="submit"]', function() {
			$(this).closest('form').data('active-submit-btn', $(this));
		});

		// 1. Settings Form AJAX Submission
		$(document).on('submit', '.supershield-settings-form', function(e) {
			e.preventDefault();

			var $form = $(this);
			var $clickedBtn = $form.data('active-submit-btn');
			if (!$clickedBtn || !$clickedBtn.length || !$clickedBtn.closest($form).length) {
				$clickedBtn = $form.find('button[type="submit"]').first();
			}

			// Store and protect original button HTML
			if (!$clickedBtn.data('original-html')) {
				$clickedBtn.data('original-html', $clickedBtn.html());
			}

			setButtonLoading($clickedBtn, 'Saving Changes...');

			var formData = $form.serialize();
			formData += '&action=supershield_save_settings&nonce=' + encodeURIComponent(supershield_vars.nonce);

			$.post(supershield_vars.ajax_url, formData, function(response) {
				restoreButton($clickedBtn);
				$form.removeData('active-submit-btn');

				if (response.success) {
					showAlert(response.data.message || 'Settings saved successfully!', true);
				} else {
					showAlert(response.data.message || 'Failed to save settings.', false);
				}
			}).fail(function() {
				restoreButton($clickedBtn);
				$form.removeData('active-submit-btn');
				showAlert('Server communication timeout. Please try again.', false);
			});
		});

		// Quick Whitelist Current IP Action
		$(document).on('click', '#btn-whitelist-current-ip', function(e) {
			e.preventDefault();
			var ip = $(this).data('ip');
			if (!ip) return;

			var $ta = $('#ip-whitelist-textarea');
			var current = $ta.val().trim();
			var lines = current ? current.split('\n') : [];
			lines = $.map(lines, function(l) { return l.trim(); });

			if (lines.indexOf(ip) === -1) {
				lines.push(ip);
				$ta.val(lines.join('\n'));
				showAlert('Added current IP (' + ip + ') to whitelist. Remember to click "Update Access Lists" to save.', true);
			} else {
				showAlert('IP ' + ip + ' is already present in your whitelist.', true);
			}
		});

		// 2. Full Security Scan Runner
		$('#btn-start-security-scan').on('click', function(e) {
			e.preventDefault();

			var $btn = $(this);
			var $statusText = $('#scan-status-text');
			var $progressBar = $('#scan-progress-bar');

			setButtonLoading($btn, 'Scanning in progress...');
			$statusText.text('SuperShield Scanner analyzing core diffs, uploads, dot droppers, entropy, and database...');
			$progressBar.css('width', '35%');

			$.post(supershield_vars.ajax_url, {
				action: 'supershield_start_scan',
				nonce: supershield_vars.nonce
			}, function(response) {
				restoreButton($btn);
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
				restoreButton($btn);
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

			setButtonLoading($btn, 'Disinfecting...');

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
					restoreButton($btn);
				}
			}).fail(function() {
				restoreButton($btn);
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

			setButtonLoading($btn, 'Restoring...');

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
					restoreButton($btn);
				}
			}).fail(function() {
				restoreButton($btn);
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

			setButtonLoading($btn, 'Quarantining...');

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
					restoreButton($btn);
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

			setButtonLoading($btn, 'Unblocking...');

			$.post(supershield_vars.ajax_url, {
				action: 'supershield_unblock_ip',
				nonce: supershield_vars.nonce,
				ip: ip
			}, function(response) {
				if (response.success) {
					$btn.closest('tr').fadeOut(300, function() {
						$(this).remove();
					});
					var $countEl = $('#blocked-ips-count');
					if ($countEl.length) {
						var count = parseInt($countEl.text(), 10);
						if (!isNaN(count) && count > 0) {
							$countEl.text(count - 1);
						}
					}
					showAlert('IP ' + ip + ' unblocked successfully.', true);
				} else {
					alert(response.data.message || 'Failed to unblock IP.');
					restoreButton($btn);
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
			setButtonLoading($btn, 'Clearing...');

			$.post(supershield_vars.ajax_url, {
				action: 'supershield_clear_logs',
				nonce: supershield_vars.nonce
			}, function(response) {
				if (response.success) {
					location.reload();
				} else {
					alert(response.data.message || 'Failed to clear logs.');
					restoreButton($btn);
				}
			});
		});

		// 8. 2FA Configuration Flow
		$('#btn-start-2fa-setup, #btn-reconfig-2fa').on('click', function(e) {
			e.preventDefault();

			var $btn = $(this);
			setButtonLoading($btn, 'Generating 2FA Keys...');

			$.post(supershield_vars.ajax_url, {
				action: 'supershield_setup_2fa',
				nonce: supershield_vars.nonce
			}, function(response) {
				restoreButton($btn);
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
					showAlert(response.data.message || 'Could not generate 2FA session.', false);
				}
			});
		});

		// Copy 2FA Secret Key to Clipboard
		$(document).on('click', '#btn-copy-2fa-secret', function(e) {
			e.preventDefault();
			var secret = $('#2fa-secret-text').text().trim();
			if (!secret) return;

			var $btn = $(this);
			var copySuccess = function() {
				$btn.addClass('copied').html('<span class="dashicons dashicons-yes" style="font-size:14px; width:14px; height:14px; margin-top:2px;"></span> Copied!');
				showAlert('Secret key copied to clipboard!', true);
				setTimeout(function() {
					$btn.removeClass('copied').html('<span class="dashicons dashicons-admin-page" style="font-size:14px; width:14px; height:14px; margin-top:2px;"></span> Copy Key');
				}, 2500);
			};

			if (navigator.clipboard && navigator.clipboard.writeText) {
				navigator.clipboard.writeText(secret).then(copySuccess).catch(function() {
					fallbackCopy(secret, copySuccess);
				});
			} else {
				fallbackCopy(secret, copySuccess);
			}
		});

		function fallbackCopy(text, callback) {
			var $temp = $('<input>');
			$('body').append($temp);
			$temp.val(text).select();
			try {
				document.execCommand('copy');
				callback();
			} catch (err) {
				showAlert('Could not copy automatically. Please copy manually.', false);
			}
			$temp.remove();
		}

		// Log Out Other User Sessions
		$(document).on('click', '#btn-destroy-other-sessions', function(e) {
			e.preventDefault();
			if (!confirm('Are you sure you want to log out all other active devices and browser sessions for your account?')) {
				return;
			}

			var $btn = $(this);
			setButtonLoading($btn, 'Logging out other sessions...');

			$.post(supershield_vars.ajax_url, {
				action: 'supershield_destroy_sessions',
				nonce: supershield_vars.nonce
			}, function(response) {
				restoreButton($btn);
				if (response.success) {
					showAlert(response.data.message || 'All other active sessions destroyed!', true);
					setTimeout(function() {
						location.reload();
					}, 1500);
				} else {
					showAlert(response.data.message || 'Failed to destroy other sessions.', false);
				}
			}).fail(function() {
				restoreButton($btn);
				showAlert('Server communication timeout. Please try again.', false);
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
			setButtonLoading($btn, 'Verifying...');

			$.post(supershield_vars.ajax_url, {
				action: 'supershield_verify_2fa',
				nonce: supershield_vars.nonce,
				code: code
			}, function(response) {
				restoreButton($btn);
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

			var $btn = $(this);
			setButtonLoading($btn, 'Deactivating...');

			$.post(supershield_vars.ajax_url, {
				action: 'supershield_disable_2fa',
				nonce: supershield_vars.nonce
			}, function(response) {
				restoreButton($btn);
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
			setButtonLoading($btn, 'Compiling Report...');

			$.post(supershield_vars.ajax_url, {
				action: 'supershield_export_diagnostics',
				nonce: supershield_vars.nonce
			}, function(response) {
				restoreButton($btn);
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
			setButtonLoading($btn, 'Submitting...');

			$.post(supershield_vars.ajax_url, {
				action: 'supershield_submit_feedback',
				nonce: supershield_vars.nonce,
				category: category,
				message: message,
				email: email
			}, function(response) {
				restoreButton($btn);
				$('#supershield-feedback-modal').fadeOut(200);
				showAlert(response.data.message || 'Thank you for your feedback!', true);
				$('#feedback-message').val('');
			}).fail(function() {
				restoreButton($btn);
				showAlert('Failed to submit feedback.', false);
			});
		});

		// 11. GitHub Auto-Updater Check
		$('#btn-check-github-updates').on('click', function(e) {
			e.preventDefault();

			var $btn = $(this);
			setButtonLoading($btn, 'Checking GitHub...');

			$.post(supershield_vars.ajax_url, {
				action: 'supershield_check_updates',
				nonce: supershield_vars.nonce
			}, function(response) {
				restoreButton($btn);
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
			}).fail(function() {
				restoreButton($btn);
				showAlert('Could not contact GitHub API.', false);
			});
		});

	});
})(jQuery);