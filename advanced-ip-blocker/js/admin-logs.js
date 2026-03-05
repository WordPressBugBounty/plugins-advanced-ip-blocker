jQuery(document).ready(function ($) {

    const adminData = window.advaipbl_admin_data || {};
    const showConfirmModal = window.AdvaipblAdmin.showConfirmModal;
    const showAdminNotice = window.AdvaipblAdmin.showAdminNotice;

    /**
    * Maneja las acciones en la tabla de IP Trust Log.
    */
    function initIpTrustLogActions() {
        const table = $('#the-list');
        if (!table.length) return;

        // Acción para Resetear Puntuación
        table.on('click', '.advaipbl-reset-score', function (e) {
            e.preventDefault();
            const $button = $(this);
            const $row = $button.closest('tr');
            const ip = $row.data('ip');

            showConfirmModal({
                title: 'Reset Score?',
                message: `Are you sure you want to reset the threat score for <strong>${ip}</strong> to 0? This action will unblock the IP and remove it from this list.`,
                confirmText: 'Yes, Reset Score',
                onConfirm: function () {
                    $row.css('opacity', '0.5');
                    $.post(ajaxurl, {
                        action: 'advaipbl_reset_threat_score',
                        nonce: adminData.nonces.reset_score,
                        ip: ip
                    }).done(function (response) {
                        if (response.success) {
                            $row.fadeOut('slow', function () { $(this).remove(); });
                        } else {
                            showAdminNotice(response.data.message, 'error');
                            $row.css('opacity', '1');
                        }
                    }).fail(function () {
                        showAdminNotice(adminData.text.ajax_error, 'error');
                        $row.css('opacity', '1');
                    });
                }
            });
        });

        // Add to Whitelist Action
        table.on('click', '.advaipbl-add-whitelist-ajax', function (e) {
            e.preventDefault();
            const $button = $(this);
            const $row = $button.closest('tr');
            const ip = $row.data('ip'); // Should be data-ip in TR or data-ip in button?
            // The button has data-ip and data-detail.
            // Let's use the button's data if available, otherwise row.
            const ipToWhitelist = $button.data('ip') || ip;
            const detail = $button.data('detail') || 'Added via IP Trust Log';
            const originalHtml = $button.html();

            $button.prop('disabled', true).html('<span class="dashicons dashicons-update" style="animation: rotation 2s infinite linear;"></span>');

            $.post(ajaxurl, {
                action: 'advaipbl_add_ip_to_whitelist',
                nonce: adminData.nonces.add_whitelist,
                ip: ipToWhitelist,
                detail: detail
            }).done(function (response) {
                if (response.success) {
                    $button.replaceWith('<span class="dashicons dashicons-yes" style="color: green;" title="Whitelisted"></span>');
                    // Optional: Fade out row since it's now whitelisted and arguably shouldn't be in the trust log of 'threats'
                    // $row.fadeOut('slow'); 
                } else {
                    showAdminNotice(response.data.message || 'Error', 'error');
                    $button.prop('disabled', false).html(originalHtml);
                }
            }).fail(function () {
                showAdminNotice(adminData.text.ajax_error, 'error');
                $button.prop('disabled', false).html(originalHtml);
            });
        });

        // Acción para Ver Historial
        const modal = $('#advaipbl-score-history-modal');
        table.on('click', '.advaipbl-view-score-history', function (e) {
            e.preventDefault();
            const $button = $(this);
            const ip = $button.closest('tr').data('ip');

            modal.find('.modal-ip-placeholder').text(ip);
            modal.find('.history-content').hide().empty();
            modal.find('.advaipbl-loader-wrapper').show();
            modal.fadeIn('fast');

            $.post(ajaxurl, {
                action: 'advaipbl_get_score_history',
                nonce: adminData.nonces.get_history,
                ip: ip
            }).done(function (response) {
                if (response.success && response.data.history) {
                    let historyHtml = '<table class="widefat"><thead><tr><th>Date/Time</th><th>Event</th><th>Points</th><th>Details</th></tr></thead><tbody>';
                    if (response.data.history.length === 0) {
                        historyHtml += '<tr><td colspan="4">No history found.</td></tr>';
                    } else {
                        response.data.history.forEach(function (ev) {
                            const date = new Date(ev.ts * 1000).toLocaleString();

                            let detailsText = '-';
                            if (ev.details) {
                                // Usamos plantillas de texto para escapar HTML y evitar XSS
                                const escapeHtml = (text) => {
                                    if (!text) return 'N/A';
                                    const div = document.createElement('div');
                                    div.textContent = text;
                                    return div.innerHTML;
                                };

                                const uri = escapeHtml(ev.details.uri || ev.details.url);

                                switch (ev.event) {
                                    case 'waf':
                                        detailsText = `Rule: <strong>${escapeHtml(ev.details.rule)}</strong><br><small>URI: ${uri}</small>`;
                                        break;
                                    case 'user_agent':
                                        detailsText = `UA: <strong>${escapeHtml(ev.details.user_agent)}</strong><br><small>URI: ${uri}</small>`;
                                        break;
                                    case 'asn':
                                        const source = escapeHtml(ev.details.source);
                                        const name = escapeHtml(ev.details.asn_name);
                                        detailsText = `ASN: <strong>${escapeHtml(ev.details.asn_number)} (${name})</strong> - ${source}<br><small>URI: ${uri}</small>`;
                                        break;
                                    case 'login':
                                        detailsText = `User: <strong>${escapeHtml(ev.details.username)}</strong>`;
                                        break;
                                    case 'impersonation':
                                        detailsText = `Impersonated UA: <strong>${escapeHtml(ev.details.impersonated_user_agent)}</strong><br><small>URI: ${uri}</small>`;
                                        break;
                                    case 'honeypot':
                                    case '404':
                                    case '403':
                                        detailsText = `URI: ${uri}`;
                                        break;
                                    default:
                                        detailsText = uri !== 'N/A' ? `URI: ${uri}` : '-';
                                }
                            }

                            historyHtml += `<tr><td>${date}</td><td>${ev.event}</td><td>+${ev.points}</td><td>${detailsText}</td></tr>`;
                        });
                    }
                    historyHtml += '</tbody></table>';
                    modal.find('.history-content').html(historyHtml);
                } else {
                    modal.find('.history-content').html('<p>Error retrieving history.</p>');
                }
            }).fail(function () {
                modal.find('.history-content').html('<p>AJAX error.</p>');
            }).always(function () {
                modal.find('.advaipbl-loader-wrapper').hide();
                modal.find('.history-content').show();
            });
        });

        modal.find('.advaipbl-modal-cancel').on('click', function () {
            modal.fadeOut('fast');
        });
    }

    /**
    * Maneja la acción de eliminar firmas maliciosas.
    */
    function initBlockedSignaturesActions() {
        $('body').on('click', '.advaipbl-delete-signature', function (e) {
            e.preventDefault();
            const $button = $(this);
            const $row = $button.closest('tr');
            const hash = $row.data('hash');
            const shortHash = hash.substring(0, 12) + '...';

            showConfirmModal({
                title: 'Delete Signature?',
                message: `Are you sure you want to delete the signature <strong>${shortHash}</strong>? This will immediately stop challenging visitors with this fingerprint.`,
                confirmText: 'Yes, Delete Signature',
                onConfirm: function () {
                    $row.css('opacity', '0.5');
                    $.post(ajaxurl, {
                        action: 'advaipbl_delete_signature',
                        nonce: adminData.nonces.delete_signature,
                        hash: hash
                    }).done(function (response) {
                        if (response.success) {
                            $row.fadeOut('slow', function () { $(this).remove(); });
                        } else {
                            // Comprobamos si el mensaje de error existe antes de mostrarlo.
                            const errorMessage = (response.data && response.data.message) ? response.data.message : 'An unknown error occurred.';
                            showAdminNotice(errorMessage, 'error');
                            $row.css('opacity', '1');
                        }
                    }).fail(function () {
                        showAdminNotice(adminData.text.ajax_error, 'error');
                        $row.css('opacity', '1');
                    });
                }
            });
        });

        const modal = $('#advaipbl-signature-details-modal');
        $('body').on('click', '.advaipbl-view-signature-details', function (e) {
            e.preventDefault();
            const hash = $(this).closest('tr').data('hash');
            const shortHash = hash.substring(0, 12) + '...';

            modal.find('.modal-hash-placeholder').text(shortHash);
            modal.find('.details-content').hide().empty();
            modal.find('.advaipbl-loader-wrapper').show();
            modal.fadeIn('fast');

            $.post(ajaxurl, {
                action: 'advaipbl_get_signature_details',
                nonce: adminData.nonces.get_signature_details,
                hash: hash
            }).done(function (response) {
                if (response.success && response.data.details) {
                    const details = response.data.details;
                    let detailsHtml = '<h4>Signature Components:</h4><ul class="signature-components">';
                    detailsHtml += `<li><strong>User-Agent:</strong> <code>${details.sample_user_agent || 'N/A'}</code></li>`;

                    if (details.sample_headers) {
                        for (const [key, value] of Object.entries(details.sample_headers)) {
                            detailsHtml += `<li><strong>${key}:</strong> <code>${value}</code></li>`;
                        }
                    }
                    detailsHtml += '</ul>';

                    detailsHtml += '<h4>Attack Evidence (last 15 entries):</h4><table class="widefat"><thead><tr><th>IP Hash (Anonymous)</th><th>Target URI</th><th>Time</th><th>Notes</th></tr></thead><tbody>';
                    if (details.evidence && details.evidence.length > 0) {
                        details.evidence.forEach(function (ev) {
                            const ipHashShort = ev.ip_hash.substring(0, 12) + '...';
                            const timeAgo = new Date(ev.timestamp * 1000).toLocaleString();
                            let notesCell = '-';
                            if (ev.is_impersonator == 1) {
                                notesCell = '<strong style="color: red;">Impersonator</strong>';
                            }
                            detailsHtml += `<tr><td><code title="${ev.ip_hash}">${ipHashShort}</code></td><td>${ev.request_uri}</td><td>${timeAgo}</td><td>${notesCell}</td></tr>`;
                        });
                    } else {
                        detailsHtml += '<tr><td colspan="3">No evidence found.</td></tr>';
                    }
                    detailsHtml += '</tbody></table>';

                    modal.find('.details-content').html(detailsHtml);
                } else {
                    modal.find('.details-content').html('<p>Error retrieving details.</p>');
                }
            }).fail(function () {
                modal.find('.details-content').html('<p>AJAX error.</p>');
            }).always(function () {
                modal.find('.advaipbl-loader-wrapper').hide();
                modal.find('.details-content').show();
            });
        });

        modal.find('.advaipbl-modal-cancel').on('click', function () {
            modal.fadeOut('fast');
        });

        // Lógica para el botón "Copy Hash"
        $('body').on('click', '.advaipbl-copy-hash', function (e) {
            e.preventDefault();
            const hashToCopy = $(this).data('hash');
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(hashToCopy)
                    .then(() => {
                        const originalText = $(this).text();
                        $(this).text('Copied!').prop('disabled', true);
                        setTimeout(() => {
                            $(this).text(originalText).prop('disabled', false);
                        }, 1500);
                    })
                    .catch(err => {
                        alert('Failed to copy text: ' + err);
                    });
            } else {
                // Fallback para navegadores antiguos (no recomendado para producción)
                const tempInput = $('<input>');
                $('body').append(tempInput);
                tempInput.val(hashToCopy).select();
                document.execCommand('copy');
                tempInput.remove();
                alert('Hash copied to clipboard!');
            }
        });

        $('body').on('click', '.advaipbl-whitelist-signature', function (e) {
            e.preventDefault();
            const $button = $(this);
            const $row = $button.closest('tr');
            const hash = $row.data('hash');

            $row.css('opacity', '0.5');
            $button.prop('disabled', true);

            $.post(ajaxurl, {
                action: 'advaipbl_whitelist_signature',
                nonce: adminData.nonces.whitelist_signature,
                hash: hash
            }).done(function (response) {
                if (response.success) {
                    $row.fadeOut('slow', function () { $(this).remove(); });
                } else {
                    showAdminNotice(response.data.message || 'An unknown error occurred.', 'error');
                    $row.css('opacity', '1');
                    $button.prop('disabled', false);
                }
            }).fail(function () {
                showAdminNotice(adminData.text.ajax_error, 'error');
                $row.css('opacity', '1');
                $button.prop('disabled', false);
            });
        });

    }

    function initLogFilterSelector() {
        const $logFilter = $('#advaipbl-log-filter');
        if (!$logFilter.length) { return; }
        $logFilter.on('change', function () {
            const $form = $(this).closest('form');
            if ($form.length) {
                $form.submit();
            }
        });
    }

    function initClearLogModal() {
        const $openButton = $('#advaipbl-open-clear-log-modal');
        if (!$openButton.length) { return; }
        const $modal = $('#advaipbl-clear-log-modal');
        const $checkboxContainer = $('#advaipbl-log-types-checkboxes');

        $openButton.on('click', function () {
            $checkboxContainer.empty();
            let checkboxesHtml = '';
            let availableLogTypes = {};
            const $logFilter = $('#advaipbl-log-filter');
            if ($logFilter.length) {
                $logFilter.find('option').each(function () {
                    const value = $(this).val();
                    const text = $(this).text();
                    if (value && value !== 'all') {
                        availableLogTypes[value] = text;
                    }
                });
            }
            availableLogTypes['general'] = 'General Log';
            availableLogTypes['wp_cron'] = 'WP-Cron Log';

            for (const [value, text] of Object.entries(availableLogTypes)) {
                checkboxesHtml += `<p><label><input type="checkbox" name="log_types_to_clear[]" value="${value}"> ${text}</label></p>`;
            }
            $checkboxContainer.html(checkboxesHtml);
            $modal.fadeIn('fast');
        });

        $modal.find('.advaipbl-modal-cancel').on('click', function () {
            $modal.fadeOut('fast');
        });
    }

    function initAuditLogActions() {
        const clearBtn = $('#advaipbl-clear-audit-log-btn');
        if (clearBtn.length) {
            clearBtn.on('click', function (e) {
                e.preventDefault();
                showConfirmModal({
                    title: 'Clear Audit Log',
                    message: 'Are you sure you want to clear the audit log?',
                    confirmText: 'Yes, Clear Log',
                    onConfirm: function () {
                        clearBtn.prop('disabled', true).text('Processing...');
                        $.post(ajaxurl, { action: 'advaipbl_clear_audit_log', nonce: adminData.nonces.clear_log_nonce }).done(function (response) {
                            if (response.success) { location.reload(); }
                            else { alert(response.data.message || 'Error.'); clearBtn.prop('disabled', false).text('Clear Audit Log'); }
                        }).fail(function () { alert('AJAX Error'); clearBtn.prop('disabled', false).text('Clear Audit Log'); });
                    }
                });
            });
        }
    }

    // Initialize Logs Logic
    initIpTrustLogActions();
    initBlockedSignaturesActions();
    initLogFilterSelector();
    initClearLogModal();
    initAuditLogActions();
});
