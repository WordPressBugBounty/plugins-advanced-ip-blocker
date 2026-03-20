jQuery(document).ready(function ($) {

    const adminData = window.advaipbl_admin_data || {};
    const showConfirmModal = window.AdvaipblAdmin.showConfirmModal;
    const showAdminNotice = window.AdvaipblAdmin.showAdminNotice;

    function initSettingsSideNav() {
        const $nav = $('.advaipbl-settings-nav');
        if (!$nav.length) return;
        const $navLinks = $nav.find('a');
        const $sections = $('.advaipbl-settings-section');
        const offsetTop = 100;

        $navLinks.on('click', function (e) {
            e.preventDefault();
            const targetId = $(this).attr('href');
            const $target = $(targetId);
            if ($target.length) {
                $('html, body').animate({ scrollTop: $target.offset().top - offsetTop + 20 }, 300, function () {
                    // Update hash quietly if supported
                    if (history.pushState) {
                        history.pushState(null, null, targetId);
                    } else {
                        window.location.hash = targetId;
                    }
                });
            }
        });

        // Initial Hash handling
        if (window.location.hash) {
            const $target = $(window.location.hash);
            if ($target.length && $target.hasClass('advaipbl-settings-section')) {
                // Scroll to it
                $('html, body').animate({ scrollTop: $target.offset().top - offsetTop + 20 }, 500);
            }
        }

        $(window).on('scroll', function () {
            const scrollPos = $(document).scrollTop();
            let currentId = null;

            $sections.each(function () {
                const $currentSection = $(this);
                const sectionTop = $currentSection.offset().top - offsetTop;

                // Standard check: "Have we scrolled past the top of this section?"
                if (scrollPos >= sectionTop - 20) {
                    currentId = $currentSection.attr('id');
                }
            });

            // "At Bottom" handling
            if ($(window).scrollTop() + $(window).height() > $(document).height() - 10) {
                // If we are at the bottom, usually the last item is active.
                // However, check if the URL hash matches a currently visible section (e.g. Internal Security vs Uninstall)
                let hashId = window.location.hash.replace('#', '');
                if (hashId && $('#' + hashId).length && $('#' + hashId).offset().top > $(document).scrollTop()) {
                    // If the hash target is visible (its top is below current scroll, meaning it's on screen), keep it active
                    currentId = hashId;
                } else {
                    // Fallback to the very last section if the loop didn't catch a better one (or if distinct from hash)
                    // But strictly, let's just use the last section found by the loop unless it's really the footer.
                    // The loop above naturally finds the last "started" section.
                    // We force the LAST section if standard loop failed to reach it (short section at bottom)
                    const $last = $sections.last();
                    if ($last.length && scrollPos < $last.offset().top - offsetTop - 20) {
                        // Only force if we haven't 'reached' it by the standard math, but we are at bottom
                        // But we must respect the hash if valid!
                        if (hashId !== $last.attr('id')) {
                            // If hash is Internal Security, and it's visible, allow it.
                            // Actually, simply: If we are at bottom, default to last, UNLESS hash matches the second-to-last and it is visible.
                            if (hashId && $('#' + hashId).is(':visible')) {
                                currentId = hashId;
                            } else {
                                currentId = $sections.last().attr('id');
                            }
                        } else {
                            currentId = $sections.last().attr('id');
                        }
                    }
                }
            }

            if (currentId) {
                $navLinks.removeClass('active');
                $nav.find('a[href="#' + currentId + '"]').addClass('active');
            } else {
                // Default to first if nothing active (top of page)
                if (scrollPos < 100) {
                    $navLinks.removeClass('active');
                    $navLinks.first().addClass('active');
                }
            }

        }).scroll();
    }

    function initGeolocationOptionsToggle() {
        const methodSelector = $('#advaipbl_geolocation_method');
        const providerSelector = $('#advaipbl_geolocation_provider_select');
        if (!methodSelector.length) return;

        const toggleApiProviderFields = function () {
            const selectedProvider = providerSelector.val();
            $('.api-key-field').closest('tr').hide();
            if (selectedProvider) { $(`input[data-provider="${selectedProvider}"]`).closest('tr').show(); }
        };

        const toggleOptionsVisibility = function () {
            const selectedMethod = methodSelector.val();
            if (selectedMethod === 'api') {
                $('.advaipbl-geolocation-api-option').closest('tr').show();
                $('.advaipbl-geolocation-db-option').closest('tr').hide();
                toggleApiProviderFields();
            } else if (selectedMethod === 'local_db') {
                $('.advaipbl-geolocation-api-option').closest('tr').hide();
                $('.advaipbl-geolocation-db-option').closest('tr').show();
            }
        };

        toggleOptionsVisibility();
        methodSelector.on('change', toggleOptionsVisibility);
        providerSelector.on('change', toggleApiProviderFields);
    }

    function initGeoIpDownloader() {
        $('body').on('click', '#advaipbl-update-geoip-db', function () {
            const $button = $(this);
            const $feedback = $('#advaipbl-geoip-update-feedback');
            const originalText = $button.text();
            $button.prop('disabled', true).text('Updating...');
            $feedback.text('Starting update process...').css('color', '');
            $.post(ajaxurl, { action: 'advaipbl_update_geoip_db', nonce: $button.data('nonce') }).done(function (response) {
                if (response.success) {
                    $feedback.text(response.data.message).css('color', 'green');
                    $(window).off('beforeunload');
                    setTimeout(() => window.location.reload(), 2000);
                } else {
                    $feedback.text('Error: ' + (response.data.message || 'Unknown error')).css('color', 'red');
                    $button.prop('disabled', false).text(originalText);
                }
            }).fail(function () { $feedback.text(adminData.text.ajax_error).css('color', 'red'); $button.prop('disabled', false).text(originalText); });
        });
    }

    function initSettingsSearch() {
        const searchInput = $('#advaipbl-settings-search');
        if (!searchInput.length) return;
        const sideMenu = $('.advaipbl-settings-nav');
        const noResultsMessage = $('.no-results-message');

        searchInput.on('keyup', function () {
            const term = $(this).val().toLowerCase().trim();
            if (term === '') { $('.advaipbl-settings-section, .advaipbl-card').show(); sideMenu.find('li').show(); noResultsMessage.hide(); return; }
            let globalMatch = false;
            $('.advaipbl-settings-section').hide();
            sideMenu.find('li').hide();
            $('.advaipbl-settings-section').each(function () {
                const $section = $(this);
                const sectionId = $section.attr('id');
                let sectionHasMatch = false;
                $section.find('.advaipbl-card').each(function () {
                    const $card = $(this);
                    const cardText = $card.text().toLowerCase();
                    let inputsText = "";
                    $card.find('input[type="text"], textarea').each(function () { inputsText += $(this).val().toLowerCase() + " "; });
                    if (cardText.includes(term) || inputsText.includes(term)) { $card.show(); sectionHasMatch = true; } else { $card.hide(); }
                });
                if (sectionHasMatch) { $section.show(); globalMatch = true; if (sectionId) { sideMenu.find(`a[href="#${sectionId}"]`).parent().show(); } }
            });
            noResultsMessage.toggle(!globalMatch);
        });
    }



    function initDeepScanLogic() {
        // Toggle Handler for Vulnerability Details
        $('#advaipbl-scan-details').on('click', '.advaipbl-toggle-vuln-details', function (e) {
            e.preventDefault();
            const btn = $(this);
            const icon = btn.find('.dashicons');
            const row = btn.closest('tr');
            const detailsRow = row.next('.advaipbl-vuln-details-row');

            if (detailsRow.is(':visible')) {
                detailsRow.hide();
                icon.removeClass('dashicons-arrow-down-alt2').addClass('dashicons-arrow-right-alt2');
            } else {
                detailsRow.show();
                icon.removeClass('dashicons-arrow-right-alt2').addClass('dashicons-arrow-down-alt2');
            }
        });

        $('#advaipbl-run-deep-scan').on('click', function () {
            const btn = $(this);
            const nonce = btn.data('nonce');
            const statusDiv = $('#advaipbl-scan-message');
            const loadingDiv = $('#advaipbl-scan-loading');
            const resultsDiv = $('#advaipbl-scan-details');
            const iconDiv = $('#advaipbl-scan-status-icon');
            const text = advaipbl_admin_data.text;

            btn.hide(); loadingDiv.show(); resultsDiv.hide(); statusDiv.html('<p>' + text.scan_checking + '</p>');

            $.post(ajaxurl, { action: 'advaipbl_run_deep_scan', nonce: nonce }, function (response) {
                loadingDiv.hide(); btn.show().text(text.scan_again);
                if (response.success) {
                    const data = response.data;
                    if (data.status === 'clean') {
                        iconDiv.html('<span class="dashicons dashicons-yes-alt" style="color:green;"></span>');
                        statusDiv.html('<h3 style="color:green; margin:0;">' + text.scan_clean_title + '</h3><p>' + text.scan_clean_desc + '</p>');
                    } else if (data.status === 'vulnerable') {
                        iconDiv.html('<span class="dashicons dashicons-warning" style="color:#d63638;"></span>');
                        statusDiv.html(`<h3 style="color:#d63638; margin:0;">${text.scan_vuln_title.replace('%d', data.count)}</h3><p>${text.scan_vuln_desc}</p>`);
                        let rows = '';
                        $.each(data.details, function (slug, info) {
                            const vuln = Array.isArray(info) ? info[0] : info;
                            if (!vuln) return;
                            const severityColor = (vuln.severity === 'Critical' || vuln.severity === 'High') ? '#d63638' : '#f59e0b';

                            // Build references Links
                            let links = '';
                            if (vuln.cve_link) {
                                links += `<li><a href="${vuln.cve_link}" target="_blank" rel="noopener noreferrer">CVE Reference ↗</a></li>`;
                            }
                            if (vuln.references && Array.isArray(vuln.references)) {
                                vuln.references.forEach(ref => {
                                    // Avoid duplicate if same as CVE
                                    if (ref !== vuln.cve_link) {
                                        links += `<li><a href="${ref}" target="_blank" rel="noopener noreferrer">Reference ↗</a></li>`;
                                    }
                                });
                            }
                            if (!links) links = '<li>No references available.</li>';


                            // Main Row
                            rows += `<tr class="advaipbl-vuln-row">
                                <td>
                                    <button type="button" class="button-link advaipbl-toggle-vuln-details" aria-expanded="false">
                                        <span class="dashicons dashicons-arrow-right-alt2"></span>
                                    </button>
                                </td>
                                <td><strong>${slug}</strong></td>
                                <td><strong style="color:${severityColor}">${info.severity}</strong></td>
                                <td>${vuln.title}</td>
                                <td>${vuln.fix || 'No patch'}</td>
                            </tr>`;

                            // Details Row
                            rows += `<tr class="advaipbl-vuln-details-row" style="display:none; background-color: #f9f9f9;">
                                <td colspan="5" style="padding: 15px;">
                                    <div class="advaipbl-vuln-details-wrapper">
                                        <p><strong>Description:</strong><br> ${vuln.description || 'No description provided.'}</p>
                                        <p><strong>References:</strong></p>
                                        <ul style="list-style: disc; margin-left: 20px;">${links}</ul>
                                    </div>
                                </td>
                            </tr>`;
                        });
                        resultsDiv.find('tbody').html(rows);
                        resultsDiv.show();
                    }
                } else { statusDiv.html('<p style="color:red;">Error: ' + response.data.message + '</p>'); }
            }).fail(function () { loadingDiv.hide(); btn.show(); statusDiv.html('<p style="color:red;">AJAX Error</p>'); });
        });
    }

    function initServerReputationLogic() {
        $('#advaipbl-run-rep-check').on('click', function () {
            const btn = $(this);
            const nonce = btn.data('nonce');
            const statusDiv = $('#advaipbl-rep-message');
            const loadingDiv = $('#advaipbl-rep-loading');
            const resultsDiv = $('#advaipbl-rep-details');
            const iconDiv = $('#advaipbl-rep-status-icon');
            const text = advaipbl_admin_data.text;

            btn.hide(); loadingDiv.show(); resultsDiv.hide(); statusDiv.html('<p>' + text.rep_analyzing + '</p>');

            $.post(ajaxurl, { action: 'advaipbl_check_server_reputation', nonce: nonce }, function (response) {
                loadingDiv.hide(); btn.show().text(text.rep_check_again);
                if (response.success) {
                    const data = response.data;
                    if (data.status === 'clean') {
                        iconDiv.html('<span class="dashicons dashicons-yes-alt" style="color:green;"></span>');
                        statusDiv.html('<h3 style="color:green; margin:0;">' + text.rep_clean_title + '</h3>');
                    } else {
                        iconDiv.html('<span class="dashicons dashicons-warning" style="color:#d63638;"></span>');
                        statusDiv.html('<h3 style="color:#d63638; margin:0;">' + text.rep_listed_title + '</h3>');
                    }
                    let rows = '';
                    $.each(data.checks, function (key, info) {
                        let color = info.status === 'clean' ? 'green' : (info.status === 'listed' ? 'red' : '#999');
                        rows += `<tr><td><strong>${info.label}</strong></td><td><span style="color:${color}">${info.status}</span></td><td>${info.detail || '-'}</td></tr>`;
                    });
                    resultsDiv.find('tbody').html(rows); resultsDiv.show();
                } else { statusDiv.html('<p style="color:red;">Error: ' + response.data.message + '</p>'); }
            }).fail(function () { loadingDiv.hide(); btn.show(); statusDiv.html('<p style="color:red;">AJAX Error</p>'); });
        });
    }

    function toggleRecaptchaV3Options() {
        const version = $('#advaipbl_recaptcha_version').val();
        $('#advaipbl-recaptcha-v3-options-row').toggle(version === 'v3');
    }

    function initConnectionTest() {
        $('#advaipbl-test-connection-btn').on('click', function (e) {
            e.preventDefault();
            const $button = $(this);
            const $resultSpan = $('#advaipbl-test-connection-result');
            const originalText = $button.text();
            $button.text('Testing...').prop('disabled', true);
            $resultSpan.text('').removeClass('success error');

            $.post(ajaxurl, {
                action: 'advaipbl_test_outbound_connection',
                nonce: adminData.nonces.test_connection
            }).done(function (response) {
                if (response.success) {
                    $resultSpan.text(response.data.message).css('color', 'green');
                } else {
                    $resultSpan.text(response.data.message).css('color', '#d63638');
                }
            }).fail(function () {
                showAdminNotice(adminData.text.ajax_error, 'error');
            }).always(function () {
                $button.text(originalText).prop('disabled', false);
            });
        });
    }



    /**
     * Maneja la exportación de ajustes vía AJAX y descarga en el cliente.
     */
    function initExportLogic() {
        $('#advaipbl-export-template, #advaipbl-export-full').on('click', function (e) {
            e.preventDefault();
            const $button = $(this);
            const originalText = $button.text();
            $button.text('Exporting...').prop('disabled', true);
            const exportType = $button.data('export-type');

            $.post(ajaxurl, {
                action: 'advaipbl_export_settings_ajax',
                nonce: adminData.nonces.export,
                export_type: exportType
            })
                .done(function (response) {
                    if (response.success) {
                        const data = response.data;
                        const blob = new Blob([JSON.stringify(data.settings, null, 2)], { type: 'application/json' });
                        const url = URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        const date = new Date().toISOString().slice(0, 10);
                        a.href = url;
                        a.download = `advaipbl-settings-${data.type}-${date}.json`;
                        document.body.appendChild(a);
                        a.click();
                        document.body.removeChild(a);
                        URL.revokeObjectURL(url);
                    } else {
                        showAdminNotice('Export failed: ' + response.data.message, 'error');
                    }
                })
                .fail(function () {
                    showAdminNotice(adminData.text.ajax_error, 'error');
                })
                .always(function () {
                    $button.text(originalText).prop('disabled', false);
                });
        });
    }

    /**
    * Maneja los clics en el aviso de consentimiento de telemetría.
    */
    function initTelemetryNotice() {
        $(document).on('click', '#advaipbl-allow-telemetry, #advaipbl-dismiss-telemetry-notice', function (e) {
            e.preventDefault();
            const $button = $(this);
            const $notice = $button.closest('.advaipbl-telemetry-notice');
            const action = $button.attr('id') === 'advaipbl-allow-telemetry' ? 'allow' : 'dismiss';

            $notice.css('opacity', '0.5');

            $.post(ajaxurl, {
                action: 'advaipbl_handle_telemetry_notice',
                nonce: adminData.nonces.telemetry,
                telemetry_action: action
            })
                .done(function (response) {
                    if (response.success) {
                        $notice.fadeOut('slow', function () { $(this).remove(); });
                        if (action === 'allow') {
                            const $checkbox = $('input[name="advaipbl_settings[allow_telemetry]"]');
                            if ($checkbox.length) {
                                $checkbox.prop('checked', true);
                            }
                        }
                    }
                });
        });
    }

    /**
     * Maneja la lógica de la sección 2FA en la página de perfil de usuario.
     */
    function initTwoFactorAuthProfile() {
        $(document).on('click', '#advaipbl-2fa-activate-btn', function () {
            const $button = $(this);
            const userId = $button.closest('#advaipbl-2fa-section').data('user-id');
            const setupContainer = $('#advaipbl-2fa-setup-container');

            $button.prop('disabled', true);
            setupContainer.slideDown();
            setupContainer.find('.advaipbl-loader-wrapper').show();
            setupContainer.find('.advaipbl-setup-content').hide();

            $.post(ajaxurl, {
                action: 'advaipbl_2fa_generate',
                nonce: $button.data('nonce'),
                user_id: userId
            }).done(function (response) {
                if (response.success) {
                    $('#advaipbl-qr-code-wrapper').html(`<img src="${response.data.qr_url}" alt="QR Code">`);
                    $('#advaipbl-secret-key').text(response.data.secret);
                    let backupCodesHtml = '';
                    response.data.backup_codes.forEach(code => {
                        backupCodesHtml += `<code>${code}</code>`;
                    });
                    $('#advaipbl-backup-codes-wrapper').html(backupCodesHtml);
                    setupContainer.find('.advaipbl-setup-content').data('backup-codes', response.data.backup_codes);
                    setupContainer.find('.advaipbl-loader-wrapper').hide();
                    setupContainer.find('.advaipbl-setup-content').slideDown();
                } else {
                    showAdminNotice(response.data.message || 'Failed to generate 2FA secret.', 'error');
                    setupContainer.slideUp();
                    $button.prop('disabled', false);
                }
            }).fail(function () {
                showAdminNotice(adminData.text.ajax_error, 'error');
                setupContainer.slideUp();
                $button.prop('disabled', false);
            });
        });

        $(document).on('click', '#advaipbl-2fa-finalize-btn', function () {
            const $button = $(this);
            const userId = $button.closest('#advaipbl-2fa-section-wrapper').find('#advaipbl-2fa-section').data('user-id');
            const setupContent = $('#advaipbl-2fa-setup-container .advaipbl-setup-content');
            const feedbackSpan = $('#advaipbl-2fa-feedback');
            const code = $('#advaipbl-2fa-verify-code').val();
            const backupCodes = setupContent.data('backup-codes');

            if (!code || code.length !== 6 || !/^\d+$/.test(code)) {
                feedbackSpan.text('Please enter a valid 6-digit code.').css('color', 'red'); return;
            }
            $button.prop('disabled', true);
            feedbackSpan.text('Verifying...').css('color', '');

            $.post(ajaxurl, {
                action: 'advaipbl_2fa_activate',
                nonce: $button.data('nonce'),
                user_id: userId,
                code: code,
                backup_codes: backupCodes
            }).done(function (response) {
                if (response.success) {
                    feedbackSpan.text('Success! Reloading page...').css('color', 'green');
                    $(window).off('beforeunload');
                    setTimeout(() => window.location.reload(), 500);
                } else {
                    feedbackSpan.text(response.data.message || 'Verification failed.').css('color', 'red');
                    $button.prop('disabled', false);
                }
            }).fail(function () {
                const errorText = (adminData && adminData.text && adminData.text.ajax_error) ? adminData.text.ajax_error : 'AJAX error.';
                feedbackSpan.text(errorText).css('color', 'red');
                $button.prop('disabled', false);
            });
        });

        // Disable 2FA
        $(document).on('click', '#advaipbl-2fa-deactivate-btn', function () {
            const $button = $(this);
            const userId = $button.closest('#advaipbl-2fa-section').data('user-id');
            const texts = (adminData && adminData.text) ? adminData.text : {};

            showConfirmModal({
                title: texts.deactivate_2fa_title || 'Deactivate Two-Factor Authentication?',
                message: texts.deactivate_2fa_message || 'Are you sure you want to deactivate 2FA? Your account will be less secure.',
                confirmText: texts.deactivate_2fa_confirm_btn || 'Yes, Deactivate',
                onConfirm: function () {
                    $.post(ajaxurl, {
                        action: 'advaipbl_2fa_deactivate',
                        nonce: $button.data('nonce'),
                        user_id: userId
                    }).done(function (response) {
                        if (response.success) {
                            location.reload();
                        } else {
                            alert(response.data.message);
                        }
                    });
                }
            });
        });
    }

    function initApiVerification() {
        $('body').on('click', '.advaipbl-verify-api-key', function (e) {
            e.preventDefault();
            const $button = $(this);
            const provider = $button.data('provider');
            const keyId = $button.data('key-id');
            const apiKey = $('#' + keyId).val();
            const $status = $button.siblings('.advaipbl-api-status');
            const texts = adminData.text || {};

            $status.text(texts.verifying_api || 'Verifying...').css('color', '');
            $button.prop('disabled', true);

            if (!apiKey) {
                $status.text(texts.enter_api_key || 'Please enter an API key.').css('color', 'orange');
                $button.prop('disabled', false);
                return;
            }
            // Determinamos dinámicamente qué acción AJAX y nonce usar
            let ajaxAction = 'advaipbl_verify_api_key'; // Acción por defecto para Geolocation
            let nonce = adminData.nonces.verify_api;

            if (provider === 'abuseipdb') {
                ajaxAction = 'advaipbl_verify_abuseipdb_key';
                nonce = adminData.nonces.verify_abuseipdb;
            }

            $.post(ajaxurl, {
                action: ajaxAction,
                nonce: nonce,
                provider: provider, // Se sigue enviando por si el backend lo necesita
                api_key: apiKey
            })
                .done(function (response) {
                    if (response.success) {
                        $status.text(response.data.message).css('color', 'green');
                    } else {
                        $status.text('Error: ' + response.data.message).css('color', 'red');
                    }
                })
                .fail(function () {
                    $status.text(texts.ajax_error || 'AJAX error.').css('color', 'red');
                })
                .always(function () {
                    $button.prop('disabled', false);
                });
        });

        // Handler específico para el Token API V3
        $('body').on('click', '#advaipbl-verify-api-token', function (e) {
            e.preventDefault();
            const $button = $(this);
            // El selector del token V3 ahora usa _display o el input oculto tras darle a editar
            let apiKey = $('#advaipbl_api_token_v3_display').val() || $('#advaipbl_api_token_v3').val();
            const $statusContainer = $button.closest('.advaipbl-status-indicator');
            const texts = adminData.text || {};

            $button.text(texts.verifying_api || 'Verifying...').prop('disabled', true);

            if (!apiKey || apiKey.indexOf('•') !== -1) { // If it's obfuscated, we just grab the real one
                apiKey = $('#advaipbl_api_token_v3').val();
            }

            if (!apiKey) {
                showAdminNotice(texts.enter_api_key || 'Please enter an API key first.', 'error');
                $button.text('Verify Connection').prop('disabled', false);
                return;
            }

            $.post(ajaxurl, {
                action: 'advaipbl_verify_api_key',
                nonce: adminData.nonces.verify_api,
                provider: 'api_token_v3',
                api_key: apiKey
            })
                .done(function (response) {
                    const $resultSpan = $('#advaipbl-api-verification-result');
                    if (response.success) {
                        $resultSpan.text(response.data.message).css({ 'color': 'green', 'font-weight': 'bold' });
                        $button.text('Verify Connection');
                    } else {
                        $resultSpan.text('Error: ' + response.data.message).css({ 'color': 'red', 'font-weight': 'bold' });
                        $button.text('Verify Connection');
                    }
                })
                .fail(function () {
                    const $resultSpan = $('#advaipbl-api-verification-result');
                    $resultSpan.text(texts.ajax_error || 'AJAX error.').css({ 'color': 'red', 'font-weight': 'bold' });
                    $button.text('Verify Connection');
                })
                .always(function () {
                    $button.prop('disabled', false);
                });
        });

        // Handler para generar una clave gratuita (In-App Registration)
        $('body').on('click', '#advaipbl-get-api-token', function (e) {
            e.preventDefault();
            const $button = $(this);
            const $spinner = $('#advaipbl-api-token-spinner');
            const originalText = $button.text();

            $button.prop('disabled', true).text('Generating...');
            $spinner.addClass('is-active');

            $.post(ajaxurl, {
                action: 'advaipbl_get_free_api_key',
                nonce: adminData.nonces.verify_api, // Reutilizamos el nonce de ajustes generales
                _t: Date.now() // Cache buster para Cloudflare
            })
                .done(function (response) {
                    if (response.success) {
                        showAdminNotice(response.data.message, 'success');
                        // Actualizar el valor visual localmente sin recargar
                        const newHtml = `
                        <input type="text" id="advaipbl_api_token_v3_display" class="regular-text" style="font-family: monospace;" value="${response.data.api_token_visual}" disabled>
                        <input type="hidden" name="advaipbl_settings[api_token_v3]" id="advaipbl_api_token_v3" value="${response.data.api_token}">
                        <button type="button" class="button" id="advaipbl-edit-api-token" title="Edit API Key"><span class="dashicons dashicons-edit" style="margin-top: 2px;"></span></button>
                    `;
                        // Recargar suavemente para asegurar que todo WordPress se actualice (ahora es seguro porque el PHP guarda el token y sincroniza la lista)
                        setTimeout(() => {
                            window.location.reload();
                        }, 2500);
                        
                        // Actualizamos el texto de validación para avisar del reload
                        $('#advaipbl-api-verification-result').html('<span style="color: green;">' + (adminData.text.api_key_generated || 'API Key Generated!') + ' Sincronizando y recargando...</span>');
                        
                        // Localizar el indicador de estado de la red AIB y cambiarlo a activo visualmente
                        var $statusIndicator = $('.advaipbl-status-indicator');
                        if($statusIndicator.length) {
                             $statusIndicator.css({
                                 'background': '#f0f6fc',
                                 'border': '1px solid #cce5ff'
                             });
                             $statusIndicator.html('<span class="dashicons dashicons-cloud-saved" style="color: #2271b1; vertical-align: middle;"></span> <strong>' + (adminData.text.protection_active || 'Protection Active:') + '</strong> <span style="margin-left:5px;">Connected (Waiting for first sync)</span>');
                        } else {
                             // Si estaba 'Not Connected', no existe el div con esa clase, así que lo inyectamos
                             var $card = $button.closest('.advaipbl-card');
                             var $header = $card.find('h3').first();
                             $header.after('<div class="advaipbl-status-indicator" style="margin-bottom: 15px; padding: 10px; background: #f0f6fc; border: 1px solid #cce5ff; border-radius: 4px;"><span class="dashicons dashicons-cloud-saved" style="color: #2271b1; vertical-align: middle;"></span> <strong>' + (adminData.text.protection_active || 'Protection Active:') + '</strong> <span style="margin-left:5px;">Connected (Waiting for first sync)</span></div>');
                             // Si hay un texto de 'No Conectado' previo en la tabla, podríamos querer ocultarlo
                             $card.find('td:contains("Not Connected"), td:contains("No Conectado")').html('<span style="color:green; font-weight:bold;">' + (adminData.text.connected || 'Connected') + '</span>');
                        }
                        
                        // Insert the generated input elements and replace the button
                        $button.parent().html(newHtml);
                        $spinner.removeClass('is-active');
                    } else {
                        showAdminNotice('Error: ' + response.data.message, 'error');
                        $button.prop('disabled', false).text(originalText);
                        $spinner.removeClass('is-active');
                    }
                })
                .fail(function () {
                    showAdminNotice(adminData.text.ajax_error || 'AJAX error.', 'error');
                    $button.prop('disabled', false).text(originalText);
                    $spinner.removeClass('is-active');
                });
        });
    }

    function initFIMActions() {
        const startScanBtn = $('#advaipbl-manual-fim-scan-btn');
        if (startScanBtn.length) {
            startScanBtn.on('click', function (e) {
                e.preventDefault();
                const $button = $(this);
                const originalText = $button.text();
                const nonce = adminData.nonces.run_fim_scan;

                showConfirmModal({
                    title: adminData.text.fim_scan_title || 'Start File Scan',
                    message: adminData.text.fim_scan_confirm || "Start manual file integrity scan? This may take a few seconds.",
                    confirmText: adminData.text.fim_scan_btn || 'Scan Now',
                    onConfirm: function () {
                        $button.prop('disabled', true).text((adminData.text.scan_checking || 'Scanning') + '...');

                        $.post(ajaxurl, {
                            action: 'advaipbl_run_fim_scan',
                            nonce: nonce
                        }).done(function (response) {
                            if (response.success) {
                                // Show success modal instead of notice to ensure visibility before reload
                                showConfirmModal({
                                    title: adminData.text.fim_complete_title || 'Scan Complete',
                                    message: response.data.message || 'Scan finished successfully.',
                                    confirmText: adminData.text.reload_btn || 'Reload',
                                    onConfirm: function () {
                                        location.reload();
                                    }
                                });
                            } else {
                                showAdminNotice(response.data.message || adminData.text.scan_error_generic || 'Error occurred during scan.', 'error');
                            }
                        }).fail(function () {
                            showAdminNotice(adminData.text.ajax_error || 'AJAX Error', 'error');
                        }).always(function () {
                            $button.prop('disabled', false).text(originalText);
                        });
                    }
                });
            });
        }
    }

    function initFloatingSaveBar() {
        const $form = $('form[action="options.php"]');
        if (!$form.length) { return; }
        const $saveBar = $('#advaipbl-floating-save-bar');
        const $discardButton = $('#advaipbl-discard-changes');
        const $saveButtonFloating = $('#advaipbl-save-changes-floating');
        const $originalSaveButton = $form.find('input[type="submit"][name="submit"]');
        let isDirty = false;
        let isSubmitting = false;

        const showBar = () => {
            if (!isDirty) {
                isDirty = true;
                $saveBar.removeClass('advaipbl-save-bar-hidden').addClass('advaipbl-save-bar-visible');
            }
        };
        const hideBar = () => {
            isDirty = false;
            $saveBar.removeClass('advaipbl-save-bar-visible').addClass('advaipbl-save-bar-hidden');
        };

        $form.on('change keyup', 'input, select, textarea', showBar);

        $saveButtonFloating.on('click', function (e) {
            e.preventDefault();
            isSubmitting = true;
            $originalSaveButton.click();
        });

        $discardButton.on('click', function () {
            showConfirmModal({
                title: adminData.text.discard_title || 'Discard Changes?',
                message: adminData.text.discard_message || 'You have unsaved changes. Are you sure you want to discard them?',
                confirmText: adminData.text.discard_confirm_btn || 'Yes, Discard',
                onConfirm: function () {
                    isSubmitting = true;
                    location.reload();
                }
            });
        });

        $form.on('submit', function () {
            isSubmitting = true;
            hideBar();
        });

        $(window).on('beforeunload', function (e) {
            // Buscamos la variable global que creamos en initTwoFactorAuthProfile - wait, that's not global there.
            // But we don't need it. We just check isDirty.
            // If 2FA submitted via Ajax, we need to bypass this?
            // The original code had window.advaipbl_isSubmittingAjax.
            // Since we moved 2FA here, let's just assume simple dirty check is fine, or set it if needed.
            // For now simplified.

            if (isDirty && !isSubmitting) {
                const confirmationMessage = 'You have unsaved changes that will be lost.';
                e.returnValue = confirmationMessage;
                return confirmationMessage;
            }
        });
    }

    function initCountrySelectors() {
        if ($.fn.select2) {
            $('.advaipbl-country-select').select2({
                width: '100%',
                allowClear: true
            });
        }
    }

    function initRawCountryEditor() {
        $('body').on('click', '.advaipbl-toggle-raw-countries', function() {
            const $wrapper = $(this).closest('.advaipbl-country-selector-wrapper');
            const selectId = $wrapper.data('target');
            const $select = $('#' + selectId);
            const $container = $wrapper.find('.advaipbl-raw-countries-container');
            const $textarea = $wrapper.find('.advaipbl-raw-countries-input');
            const $feedback = $wrapper.find('.advaipbl-raw-countries-feedback');
            
            const currentSelected = $select.val() || [];
            $textarea.val(currentSelected.join(', '));
            $feedback.text('').css('color', '');
            
            $(this).hide();
            $container.slideDown('fast');
        });

        $('body').on('click', '.advaipbl-cancel-raw-countries', function() {
            const $wrapper = $(this).closest('.advaipbl-country-selector-wrapper');
            $wrapper.find('.advaipbl-raw-countries-container').slideUp('fast', function() {
                $wrapper.find('.advaipbl-toggle-raw-countries').show();
            });
        });

        $('body').on('click', '.advaipbl-apply-raw-countries', function() {
            const $wrapper = $(this).closest('.advaipbl-country-selector-wrapper');
            const selectId = $wrapper.data('target');
            const $select = $('#' + selectId);
            const $textarea = $wrapper.find('.advaipbl-raw-countries-input');
            const $feedback = $wrapper.find('.advaipbl-raw-countries-feedback');
            
            const rawText = $textarea.val().toUpperCase();
            const matches = rawText.match(/\b[A-Z]{2}\b/g) || [];
            
            const validOptions = new Set();
            $select.find('option').each(function() {
                const val = $(this).val();
                if (val) validOptions.add(val);
            });
            
            const selectedCodes = [];
            let invalidCount = 0;
            
            matches.forEach(code => {
                if (validOptions.has(code)) {
                    if (!selectedCodes.includes(code)) {
                        selectedCodes.push(code);
                    }
                } else {
                    invalidCount++;
                }
            });
            
            $select.val(selectedCodes).trigger('change');
            if ($.fn.select2) {
                $select.trigger('change.select2');
            }
            
            let feedbackText = `Applied ${selectedCodes.length} codes.`;
                
            if (invalidCount > 0) {
                feedbackText += ` (Ignored ${invalidCount} invalid)`;
                $feedback.css('color', '#f56e28');
            } else {
                $feedback.css('color', '#00a32a');
            }
            
            $feedback.text(feedbackText);
            $textarea.val(selectedCodes.join(', '));
        });
    }

    // Initialize Settings Logic
    initGeolocationOptionsToggle();
    initSettingsSideNav();
    initSettingsSearch();
    initGeoIpDownloader();
    initDeepScanLogic();
    initServerReputationLogic();

    toggleRecaptchaV3Options();
    $('#advaipbl_recaptcha_version').on('change', toggleRecaptchaV3Options);
    initConnectionTest();

    initExportLogic();
    initTelemetryNotice();
    initTwoFactorAuthProfile();
    initApiVerification();
    initFloatingSaveBar();
    initFIMActions();
    initCountrySelectors();
    initRawCountryEditor();
    initWhitelistAjaxButton();

    function initWhitelistAjaxButton() {
        $('body').on('click', '.advaipbl-add-whitelist-ajax', function (e) {
            e.preventDefault();
            const $button = $(this);
            const ip = $button.data('ip');
            const detail = $button.data('detail');
            const originalText = $button.html();
            const texts = adminData.text || {};

            $button.text(texts.adding_to_whitelist || 'Adding...').prop('disabled', true);

            $.post(ajaxurl, {
                action: 'advaipbl_add_ip_to_whitelist',
                nonce: adminData.nonces.add_whitelist,
                ip: ip,
                detail: detail
            }).done(function (response) {
                if (response.success) {
                    const successHtml = `<span class="advaipbl-status-icon success" title="${response.data.message}">✔ ${texts.added_to_whitelist || 'Added'}</span>`;
                    const $notice = $button.closest('.advaipbl-notice, .notice');
                    $button.replaceWith(successHtml);
                    if ($notice.length) {
                        $notice.removeClass('advaipbl-notice-error advaipbl-notice-warning notice-error').addClass('advaipbl-notice-info notice-success');
                    }
                } else {
                    $button.html(originalText).prop('disabled', false);
                    showAdminNotice('Error: ' + response.data.message, 'error');
                }
            }).fail(function () {
                $button.html(originalText).prop('disabled', false);
                showAdminNotice(texts.ajax_error || 'AJAX Error', 'error');
            });
        });
    }

    initWhitelistAjaxButton();

});
