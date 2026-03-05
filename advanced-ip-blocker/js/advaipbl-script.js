jQuery(document).ready(function ($) {

    const ajax_obj = window.advaipbl_ajax_obj || {};

    // ========================================================================
    // MODAL Y NOTIFICACIONES PERSONALIZADAS
    // ========================================================================
    // Delegated to admin-core.js (window.AdvaipblAdmin)

    // ========================================================================
    // GESTIÓN DEL MODAL DEL MAPA
    // ========================================================================

    $('.wrap').on('click', '.advaipbl-btn-map', function (e) {
        e.preventDefault();
        const lat = $(this).data('lat');
        const lon = $(this).data('lon');
        if (!lat || !lon) return;

        const url = `https://www.openstreetmap.org/export/embed.html?bbox=${lon - 0.01},${lat - 0.01},${lon + 0.01},${lat + 0.01}&layer=mapnik&marker=${lat},${lon}`;
        $('#mapModalFrame').attr('src', url);
        $('#mapModal').css('display', 'flex');
    });

    function closeModal() {
        $('#mapModal').hide();
        $('#mapModalFrame').attr('src', '');
    }

    $('#closeModalBtn').on('click', closeModal);
    $('#mapModal').on('click', function (e) {
        if (e.target.id === 'mapModal') {
            closeModal();
        }
    });

    // ========================================================================
    // ACCIONES AJAX PARA CERRAR SESIONES (USANDO MODAL)
    // ========================================================================

    const ajaxHandler = function (action, data, nonceValue) {
        const postData = { action: action, nonce: nonceValue, ...data };
        const buttonsToDisable = $('.advaipbl-btn-close-user, #advaipbl-close-all-btn, #advaipbl-close-role-btn');
        buttonsToDisable.prop('disabled', true);

        $.post(ajax_obj.ajax_url, postData)
            .done(function (response) {
                if (response.success) {
                    location.reload();
                } else {
                    let errorMessage = "An unknown error occurred.";
                    if (response.data) {
                        errorMessage = response.data.message || (typeof response.data === 'string' ? response.data : errorMessage);
                    }
                    window.AdvaipblAdmin.showAdminNotice("Error: " + errorMessage, 'error');
                    buttonsToDisable.prop('disabled', false);
                }
            })
            .fail(function (jqXHR, textStatus, errorThrown) {
                window.AdvaipblAdmin.showAdminNotice("Communication error while executing the action: " + textStatus + " - " + errorThrown, 'error');
                buttonsToDisable.prop('disabled', false);
            });
    };

    $('.wrap').on('click', '.advaipbl-btn-close-user', function () {
        const userId = $(this).data('user-id');
        window.AdvaipblAdmin.showConfirmModal({
            // Usamos las nuevas claves del objeto ajax_obj
            title: ajax_obj.title_close_user,
            message: ajax_obj.text_confirm_close_user,
            confirmText: ajax_obj.btn_close_user,
            onConfirm: function () {
                ajaxHandler('advaipbl_close_user_session', { user_id: userId }, ajax_obj.nonce_close_session);
            }
        });
    });

    $('#advaipbl-close-all-btn').on('click', function () {
        window.AdvaipblAdmin.showConfirmModal({
            title: ajax_obj.title_close_all,
            message: ajax_obj.text_confirm_close_all,
            confirmText: ajax_obj.btn_close_all,
            onConfirm: function () {
                ajaxHandler('advaipbl_close_all_user_sessions', {}, ajax_obj.nonce_close_all);
            }
        });
    });

    $('#advaipbl-close-role-btn').on('click', function () {
        const role = $('#role-selector').val();
        if (!role) {
            // Usamos la cadena traducida para la advertencia
            window.AdvaipblAdmin.showAdminNotice(ajax_obj.text_select_role, 'warning');
            return;
        }
        window.AdvaipblAdmin.showConfirmModal({
            title: ajax_obj.title_close_role,
            message: ajax_obj.text_confirm_close_role,
            confirmText: ajax_obj.btn_close_role,
            onConfirm: function () {
                ajaxHandler('advaipbl_close_sessions_by_role', { role: role }, ajax_obj.nonce_close_by_role);
            }
        });
    });

    $('#advaipbl-btn-clear-location-cache').on('click', function (e) {
        e.preventDefault();
        const $form = $('#advaipbl-clear-location-cache-form');
        window.AdvaipblAdmin.showConfirmModal({
            title: ajax_obj.title_clear_cache,
            message: ajax_obj.text_confirm_clear_cache,
            confirmText: ajax_obj.btn_clear_cache,
            onConfirm: function () {
                $form.submit();
            }
        });
    });

    /**
     * Maneja el cambio del selector de "items por página" para recargar la página.
     */
    function initPerPageSelector() {
        $('body').on('change', '.advaipbl-per-page-selector', function () {
            const $form = $(this).closest('form');
            if ($form.length) {
                $form.get(0).submit();
            }
        });
    }

    initPerPageSelector();

});