jQuery(document).ready(function ($) {

    // Global Namespace for sharing functions between modules
    window.AdvaipblAdmin = window.AdvaipblAdmin || {};

    // Objeto global con todos los datos y textos pasados desde PHP.
    const adminData = window.advaipbl_admin_data || {};

    // ========================================================================
    // FUNCIONES DE UI REUTILIZABLES (Exposed globally)
    // ========================================================================

    window.AdvaipblAdmin.showAdminNotice = function (message, type = 'error') {
        if (typeof message === 'undefined' || message === '') return;
        const container = $('#advaipbl-notices-container');
        if (!container.length) return;
        const noticeHtml = `<div class="notice notice-${type} is-dismissible"><p>${message}</p><button type="button" class="notice-dismiss"><span class="screen-reader-text">Dismiss this notice.</span></button></div>`;
        container.append(noticeHtml);
        container.find('.notice-dismiss').last().on('click', function (e) { e.preventDefault(); $(this).closest('.notice').fadeOut('slow', function () { $(this).remove(); }); });
    };

    window.AdvaipblAdmin.showConfirmModal = function (options) {
        const modal = $('#advaipbl-general-confirm-modal');
        modal.find('.advaipbl-modal-title').html(options.title || 'Are you sure?');
        modal.find('.advaipbl-modal-body').html(options.message || '');
        modal.find('#advaipbl-confirm-action-btn').text(options.confirmText || 'Confirm');

        modal.fadeIn('fast');

        const confirmBtn = modal.find('#advaipbl-confirm-action-btn');
        const cancelBtn = modal.find('.advaipbl-modal-cancel');

        confirmBtn.off('click');
        cancelBtn.off('click');

        confirmBtn.on('click', function () {
            if (typeof options.onConfirm === 'function') { options.onConfirm(); }
            modal.fadeOut('fast');
        });

        cancelBtn.on('click', function () {
            modal.fadeOut('fast');
        });
    };

    // ========================================================================
    // INITIALIZATIONS
    // ========================================================================

    function initMobileNav() {
        $('#advaipbl-nav-select').on('change', function () {
            const newUrl = $(this).val();
            if (newUrl) {
                window.location.href = newUrl;
            }
        });
    }

    function initAdminMenuCounter() {
        if (typeof adminData.counts === 'undefined' || typeof adminData.counts.blocked === 'undefined') { return; }
        const blockedCount = adminData.counts.blocked;
        if (blockedCount > 0) {
            const menuLink = $('ul#adminmenu a[href="options-general.php?page=advaipbl_settings_page"]');
            if (menuLink.length) {
                const counterHtml = ` <span class="update-plugins count-${blockedCount}"><span class="plugin-count">${blockedCount}</span></span>`;
                menuLink.append(counterHtml);
            }
        }
    }

    function initConfirmActions() {
        $('body').on('click', '.advaipbl-confirm-action', function (e) {
            e.preventDefault();
            const $button = $(this);
            const form = $button.closest('form');
            const options = {
                title: $button.data('confirm-title') || 'Confirmation Required',
                message: $button.data('confirm-message') || 'Are you sure you want to proceed?',
                confirmText: $button.data('confirm-button') || 'Confirm',
                onConfirm: function () {
                    form.get(0).submit();
                }
            };
            window.AdvaipblAdmin.showConfirmModal(options);
        });
    }

    // Run Initializations
    initMobileNav();
    initAdminMenuCounter();
    initConfirmActions();

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

    initTelemetryNotice();

});
