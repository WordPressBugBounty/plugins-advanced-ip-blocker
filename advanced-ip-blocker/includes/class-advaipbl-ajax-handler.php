<?php

if ( ! defined( 'ABSPATH' ) ) exit;

class ADVAIPBL_Ajax_Handler {

    /**
     * Instancia de la clase principal del plugin.
     * @var ADVAIPBL_Main
     */
    private $plugin;

    /**
 * Constructor.
 * @param ADVAIPBL_Main $plugin_instance La instancia de la clase principal.
 */
    public function __construct(ADVAIPBL_Main $plugin_instance) {
    $this->plugin = $plugin_instance;
}

    public function ajax_get_dashboard_stats() {
        // 1. Verificamos el nonce. El primer argumento debe coincidir con la acción del nonce que creamos.
        check_ajax_referer('wp_ajax_advaipbl_get_dashboard_stats', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Permission denied.']);
        }
        $stats = $this->plugin->dashboard_manager->get_dashboard_stats();
        if ($stats) {
            wp_send_json_success($stats);
        } else {
            wp_send_json_error(['message' => 'Could not retrieve stats.']);
        }
    }
	/**
     * AJAX callback para resetear la puntuación de amenaza de una IP.
     */
        public function ajax_reset_threat_score() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Permission denied.', 'advanced-ip-blocker')]);
        }
        check_ajax_referer('advaipbl_reset_score_nonce', 'nonce');

        $ip = isset($_POST['ip']) ? sanitize_text_field(wp_unslash($_POST['ip'])) : '';
        if (!$ip) {
            wp_send_json_error(['message' => __('Invalid IP address.', 'advanced-ip-blocker')]);
        }

        $success = $this->plugin->threat_score_manager->reset_score($ip);

        $this->plugin->desbloquear_ip($ip);

        if ($success) {
            $this->plugin->purge_all_page_caches();
			/* translators: %1$s: IP, %2$s: Username. */
            $this->plugin->log_event(sprintf(__('Threat score for IP %1$s was manually reset by %2$s.', 'advanced-ip-blocker'), $ip, $this->plugin->get_current_admin_username()), 'info');
            wp_send_json_success(['message' => __('Score reset and IP unblocked successfully.', 'advanced-ip-blocker')]);
        } else {
            wp_send_json_error(['message' => __('Failed to reset score.', 'advanced-ip-blocker')]);
        }
    }
	/**
     * AJAX callback para añadir una firma a la lista blanca y eliminarla de la lista de bloqueo.
     */
    public function ajax_whitelist_signature() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Permission denied.', 'advanced-ip-blocker')]);
        }
        check_ajax_referer('advaipbl_whitelist_signature_nonce', 'nonce');

        $hash = isset($_POST['hash']) ? sanitize_text_field(wp_unslash($_POST['hash'])) : '';
        if (strlen($hash) !== 64) {
            wp_send_json_error(['message' => __('Invalid signature hash.', 'advanced-ip-blocker')]);
        }

        // 1. Obtenemos los detalles de la firma para construir los comentarios.
        $details = $this->plugin->fingerprint_manager->get_signature_details($hash);
        if ($details === false) {
            wp_send_json_error(['message' => __('Could not retrieve signature details to create whitelist entry.', 'advanced-ip-blocker')]);
        }
        
        // 2. Construimos la entrada para la lista blanca con comentarios.
        $entry_lines = ["\n# Signature Components:"];
        $entry_lines[] = "# User-Agent: " . ($details['sample_user_agent'] ?? 'N/A');
        if (!empty($details['sample_headers'])) {
            foreach ($details['sample_headers'] as $key => $value) {
                $entry_lines[] = "# " . $key . ": " . $value;
            }
        }
        $entry_lines[] = $hash;
        $entry_to_add = implode("\n", $entry_lines);
        
        // 3. Obtenemos el array COMPLETO de settings, modificamos la clave y guardamos.
        $options = get_option(ADVAIPBL_Main::OPTION_SETTINGS, []);
        $current_whitelist = $options['trusted_signature_hashes'] ?? '';
        $new_whitelist = $current_whitelist . "\n" . $entry_to_add;
        
        // Actualizamos la clave dentro del array de opciones.
        $options['trusted_signature_hashes'] = trim($new_whitelist);
        
        // Guardamos el array de opciones completo.
        update_option(ADVAIPBL_Main::OPTION_SETTINGS, $options);

        // 4. Eliminamos la firma de la lista de maliciosos.
        $this->plugin->fingerprint_manager->delete_signature($hash);
        /* translators: %s: hash, %s: Username. */
        $this->plugin->log_event(sprintf(__('Signature %1$s... whitelisted by %2$s.', 'advanced-ip-blocker'), substr($hash, 0, 12), $this->plugin->get_current_admin_username()), 'info');
        wp_send_json_success(['message' => __('Signature whitelisted successfully.', 'advanced-ip-blocker')]);
    }
	/**
     * AJAX callback para eliminar una firma maliciosa.
     */
    public function ajax_delete_signature() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Permission denied.', 'advanced-ip-blocker')]);
        }
        check_ajax_referer('advaipbl_delete_signature_nonce', 'nonce');

        $signature_hash = isset($_POST['hash']) ? sanitize_text_field(wp_unslash($_POST['hash'])) : '';
        // Validamos que el hash tenga la longitud correcta de un sha256.
        if (strlen($signature_hash) !== 64) {
            wp_send_json_error(['message' => __('Invalid signature hash format.', 'advanced-ip-blocker')]);
        }       
        $success = $this->plugin->fingerprint_manager->delete_signature($signature_hash);

        if ($success) {
			/* translators: %1$s: Hash, %2$s: Username */
            $this->plugin->log_event(sprintf(__('Malicious signature %1$s... was manually deleted by %2$s.', 'advanced-ip-blocker'), substr($signature_hash, 0, 12), $this->plugin->get_current_admin_username()), 'warning');
            wp_send_json_success(['message' => __('Signature deleted successfully.', 'advanced-ip-blocker')]);
        } else {
            wp_send_json_error(['message' => __('Failed to delete signature. It might have already expired or been removed.', 'advanced-ip-blocker')]);
        }
    }
	
	    /**
     * AJAX callback para obtener los detalles de una firma maliciosa.
     */
    public function ajax_get_signature_details() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Permission denied.', 'advanced-ip-blocker')]);
        }
        check_ajax_referer('advaipbl_get_signature_details_nonce', 'nonce');

        $signature_hash = isset($_POST['hash']) ? sanitize_text_field(wp_unslash($_POST['hash'])) : '';
        if (strlen($signature_hash) !== 64) {
            wp_send_json_error(['message' => __('Invalid signature hash format.', 'advanced-ip-blocker')]);
        }
        
        $details = $this->plugin->fingerprint_manager->get_signature_details($signature_hash);

        if ($details !== false) {
            wp_send_json_success(['details' => $details]);
        } else {
            wp_send_json_error(['message' => __('Could not retrieve signature details.', 'advanced-ip-blocker')]);
        }
    }
	
	    /**
     * AJAX callback para obtener los detalles de un Endpoint Lockdown.
     */
    public function ajax_get_lockdown_details() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Permission denied.', 'advanced-ip-blocker')]);
        }
        check_ajax_referer('advaipbl_get_lockdown_details_nonce', 'nonce');

        $lockdown_id = isset($_POST['id']) ? absint($_POST['id']) : 0;
        if (!$lockdown_id) {
            wp_send_json_error(['message' => __('Invalid Lockdown ID.', 'advanced-ip-blocker')]);
        }

        global $wpdb;
        $table_name = $wpdb->prefix . 'advaipbl_endpoint_lockdowns';
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $lockdown = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$table_name} WHERE id = %d", $lockdown_id), ARRAY_A);

        if ($lockdown) {
            wp_send_json_success(['details' => $lockdown]);
        } else {
            wp_send_json_error(['message' => __('Could not retrieve lockdown details.', 'advanced-ip-blocker')]);
        }
    }
	/**
     * AJAX callback para obtener el historial de eventos de una IP.
     */
    public function ajax_get_score_history() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Permission denied.', 'advanced-ip-blocker')]);
        }
        check_ajax_referer('advaipbl_get_history_nonce', 'nonce');

        $ip = isset($_POST['ip']) ? sanitize_text_field(wp_unslash($_POST['ip'])) : '';
        if (!$ip) {
            wp_send_json_error(['message' => __('Invalid IP address.', 'advanced-ip-blocker')]);
        }        
        $history = $this->plugin->threat_score_manager->get_log_details($ip);

        if ($history !== false) {
            wp_send_json_success(['history' => $history]);
        } else {
            wp_send_json_error(['message' => __('Could not retrieve history.', 'advanced-ip-blocker')]);
        }
    }
	/**
     * AJAX callback to test the server's outbound connection.
     */
    public function ajax_test_outbound_connection() {
        if ( ! current_user_can('manage_options') ) {
            wp_send_json_error( [ 'message' => 'Permission denied.' ] );
        }
        check_ajax_referer( 'advaipbl_test_connection_nonce', 'nonce' );

        $response = wp_remote_get('https://api.ipify.org?format=json', [ 'timeout' => 10 ]);

        if ( is_wp_error($response) ) {
            wp_send_json_error( [ 'message' => 'Error: ' . $response->get_error_message() ] );
        }

        $http_code = wp_remote_retrieve_response_code( $response );
        if ( $http_code !== 200 ) {
            wp_send_json_error( [ 'message' => sprintf( 'Error: Received HTTP status code %d.', $http_code ) ] );
        }

        $body = json_decode( wp_remote_retrieve_body( $response ), true );
        if ( isset( $body['ip'] ) && filter_var( $body['ip'], FILTER_VALIDATE_IP ) ) {
            wp_send_json_success( [ 'message' => sprintf( 'Success! Connection established from IP: %s', $body['ip'] ) ] );
        }

        wp_send_json_error( [ 'message' => 'Error: The response from the test service was invalid.' ] );
    }
	/**
     * AJAX callback to add a specific IP to the whitelist.
     * This is used by the interactive buttons in the admin interface.
     */

    public function ajax_add_ip_to_whitelist() {
    // 1. Validar permisos y nonce de seguridad (esto no cambia).
    if ( ! current_user_can('manage_options') ) {
        wp_send_json_error( [ 'message' => __( 'Permission denied.', 'advanced-ip-blocker' ) ] );
    }
    check_ajax_referer( 'advaipbl_add_whitelist_nonce', 'nonce' );

    // 2. Obtener y validar la IP del POST. Esta función AJAX solo maneja IPs individuales.
    if ( ! isset( $_POST['ip'] ) || ! filter_var( wp_unslash( $_POST['ip'] ), FILTER_VALIDATE_IP ) ) {
        wp_send_json_error( [ 'message' => __( 'Invalid or missing IP address.', 'advanced-ip-blocker' ) ] );
    }
    $ip = sanitize_text_field( wp_unslash( $_POST['ip'] ) );
    
    $detail = isset( $_POST['detail'] ) ? sanitize_text_field( wp_unslash( $_POST['detail'] ) ) : __('Added via admin action', 'advanced-ip-blocker');

    // 3. Reutilizar nuestra nueva lógica centralizada.
    $success = $this->plugin->add_to_whitelist_and_unblock( $ip, $detail );

    if ( $success ) {
        /* translators: %s: The IP address that was successfully whitelisted. */
        wp_send_json_success( [ 'message' => sprintf( __( '%s successfully added to the whitelist.', 'advanced-ip-blocker' ), $ip ) ] );
    } else {
        /* translators: %s: The IP address that is already whitelisted. */
        wp_send_json_success( [ 'message' => sprintf( __( '%s is already whitelisted.', 'advanced-ip-blocker' ), $ip ) ] );
    }
}
    /**
    * AJAX callback para verificar una API key de geolocalización o de Cloudflare.
    */
    public function ajax_verify_api_key() {
        if ( ! current_user_can('manage_options') ) {
            wp_send_json_error( ['message' => __('Permission denied.', 'advanced-ip-blocker')] );
        }
        check_ajax_referer( 'advaipbl_verify_api_nonce', 'nonce' );

        $provider = isset($_POST['provider']) ? sanitize_text_field(wp_unslash($_POST['provider'])) : '';
        $api_key = isset($_POST['api_key']) ? sanitize_text_field(wp_unslash($_POST['api_key'])) : '';

        if (empty($provider)) {
            wp_send_json_error( ['message' => __('Provider is missing.', 'advanced-ip-blocker')] );
        }
        
        if ($provider === 'cloudflare') {
            if (empty($api_key)) {
                wp_send_json_error(['message' => __('API Token is missing.', 'advanced-ip-blocker')]);
            }
            
            // Llamamos al Cloudflare Manager
            $result = $this->plugin->cloudflare_manager->verify_token($api_key);
            
            if (is_wp_error($result)) {
                wp_send_json_error(['message' => $result->get_error_message()]);
            } else {
                wp_send_json_success(['message' => __('Token verified successfully! (Status: Active)', 'advanced-ip-blocker')]);
            }
            return; // Terminamos aquí para Cloudflare
        }

        // --- Verificación del Token API V3 (Servidor Central AIB) ---
        if ($provider === 'api_token_v3') {
            if (empty($api_key)) {
                $this->plugin->log_event('AIB Network connection failed: API Key is missing.', 'error');
                wp_send_json_error(['message' => __('API Key is missing.', 'advanced-ip-blocker')]);
            }

            // Llamada al servidor central para verificar el token real
            $response = wp_remote_get('https://advaipbl.com/wp-json/aib-api/v3/verify-token', [
                'headers' => [
                    'Authorization' => 'Bearer ' . $api_key,
                    'Accept'        => 'application/json'
                ],
                'timeout' => 10
            ]);

            if (is_wp_error($response)) {
                $this->plugin->log_event('AIB Network connection failed: ' . $response->get_error_message(), 'error');
                wp_send_json_error(['message' => __('Connection failed: ', 'advanced-ip-blocker') . $response->get_error_message()]);
            }

            $status_code = wp_remote_retrieve_response_code($response);
            $body = wp_remote_retrieve_body($response);
            $data = json_decode($body, true);

            if ($status_code === 200 && isset($data['status']) && in_array($data['status'], ['active', 'connected'], true)) {
                $this->plugin->log_event('AIB Network connection verified successfully. API Key is active.', 'info');
                wp_send_json_success(['message' => __('API Key is valid and active!', 'advanced-ip-blocker')]);
            } else {
                $error_msg = $data['message'] ?? __('Invalid or inactive API Key.', 'advanced-ip-blocker');
                $this->plugin->log_event('AIB Network connection failed: ' . $error_msg, 'error');
                wp_send_json_error(['message' => $error_msg]);
            }
            return;
        }

        // --- Lógica existente para Geolocalización ---
        $this->plugin->geolocation_manager->set_transient_api_key($provider, $api_key);
        $result = $this->plugin->geolocation_manager->fetch_location('8.8.8.8');
        $this->plugin->geolocation_manager->clear_transient_api_key($provider);

        if ( $result && !isset($result['error']) ) {
            wp_send_json_success(['message' => __('API Key is valid!', 'advanced-ip-blocker')]);
        } else {
            $error_message = $result['error_message'] ?? __('Invalid API Key or connection error.', 'advanced-ip-blocker');
            wp_send_json_error(['message' => $error_message]);
        }
    } 

    /**
     * AJAX action to get a free API Key from the Central Server automatically.
     */
    public function ajax_get_free_api_key() {
        check_ajax_referer('advaipbl_verify_api_nonce', 'nonce'); // Usamos este nonce existente

        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Unauthorized', 'advanced-ip-blocker')]);
        }

        $result = $this->plugin->community_manager->register_site();

        if (is_wp_error($result)) {
            wp_send_json_error(['message' => __('Connection to Central Server failed: ', 'advanced-ip-blocker') . $result->get_error_message()]);
        }

        if (isset($result['api_token'])) {
            // Trigger an immediate sync so the blocklist and stats update to V3 levels instantly.
            $this->plugin->community_manager->update_list();

            wp_send_json_success([
                'message' => __('API Key generated and saved successfully!', 'advanced-ip-blocker'),
                'api_token_visual' => 'AIB_' . str_repeat('•', 24) . substr($result['api_token'], -4)
            ]);
        } else {
            wp_send_json_error(['message' => __('Failed to generate API Key.', 'advanced-ip-blocker')]);
        }
    }

    /**
     * Callback de AJAX para gestionar la respuesta al aviso de telemetría.
     */
    public function ajax_handle_telemetry_notice() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error();
        }
        check_ajax_referer('advaipbl_telemetry_nonce', 'nonce');

        $action = isset($_POST['telemetry_action']) ? sanitize_key($_POST['telemetry_action']) : '';

        if ('allow' === $action) {
            // Obtenemos las opciones a través de la instancia del plugin.
            $options = $this->plugin->options;
            $options['allow_telemetry'] = '1';

            update_option(ADVAIPBL_Main::OPTION_SETTINGS, $options);
            update_option('advaipbl_telemetry_notice_dismissed', '1');

            if (!wp_next_scheduled('advaipbl_send_telemetry_data_event')) {
                wp_schedule_event(time() + DAY_IN_SECONDS, 'weekly', 'advaipbl_send_telemetry_data_event');

                $this->plugin->log_event('Telemetry cron job scheduled after user consent.', 'info');
            }

            wp_send_json_success();

        } elseif ('dismiss' === $action) {
            update_option('advaipbl_telemetry_notice_dismissed', '1');
            wp_clear_scheduled_hook('advaipbl_send_telemetry_data_event');
            
            wp_send_json_success();
        }

        wp_send_json_error();
    }
	/**
     * AJAX callback para generar un nuevo secreto 2FA para un usuario.
     */
    public function ajax_2fa_generate() {
        check_ajax_referer( 'advaipbl_2fa_generate_nonce', 'nonce' );
        $user_id = isset( $_POST['user_id'] ) ? absint( $_POST['user_id'] ) : 0;
        if ( ! $user_id || ! current_user_can( 'edit_user', $user_id ) ) {
            wp_send_json_error( [ 'message' => __( 'Permission denied.', 'advanced-ip-blocker' ) ] );
        }
        $user = get_user_by( 'id', $user_id );
        if ( ! $user ) {
            wp_send_json_error( [ 'message' => __( 'Invalid user.', 'advanced-ip-blocker' ) ] );
        }
        $data = $this->plugin->tfa_manager->generate_new_secret_for_user( $user );
        wp_send_json_success( $data );
    }

    /**
     * AJAX callback para verificar y activar 2FA para un usuario.
     */
    public function ajax_2fa_activate() {
        check_ajax_referer( 'advaipbl_2fa_activate_nonce', 'nonce' );
        $user_id      = isset( $_POST['user_id'] ) ? absint( $_POST['user_id'] ) : 0;
        $code         = isset( $_POST['code'] ) ? sanitize_text_field( wp_unslash( $_POST['code'] ) ) : '';
        $backup_codes = isset( $_POST['backup_codes'] ) && is_array( $_POST['backup_codes'] ) ? array_map( 'sanitize_text_field', wp_unslash( $_POST['backup_codes'] ) ) : [];

        if ( ! $user_id || ! current_user_can( 'edit_user', $user_id ) ) {
            wp_send_json_error( [ 'message' => __( 'Permission denied.', 'advanced-ip-blocker' ) ] );
        }
        $success = $this->plugin->tfa_manager->verify_and_activate( $user_id, $code, $backup_codes );
        if ( $success ) {
            wp_send_json_success();
        } else {
            wp_send_json_error( [ 'message' => __( 'Invalid verification code. Please try again.', 'advanced-ip-blocker' ) ] );
        }
    }

    /**
     * AJAX callback para desactivar 2FA para un usuario.
     */
        public function ajax_2fa_deactivate() {
        check_ajax_referer( 'advaipbl_2fa_deactivate_nonce', 'nonce' );
        $user_id = isset( $_POST['user_id'] ) ? absint( $_POST['user_id'] ) : 0;
        if ( ! $user_id || ! current_user_can( 'edit_user', $user_id ) ) {
            wp_send_json_error( [ 'message' => __( 'Permission denied.', 'advanced-ip-blocker' ) ] );
        }
        $this->plugin->tfa_manager->deactivate_for_user( $user_id );
        wp_send_json_success();
    }
	/**
     * AJAX callback para iniciar la descarga de la base de datos GeoIP.
     */
    public function ajax_update_geoip_db() {
        if ( ! isset( $_POST['nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['nonce'] ) ), 'advaipbl_update_geoip_nonce' ) ) {
            wp_send_json_error( ['message' => 'Nonce verification failed.'], 403 );
        }
        if ( ! current_user_can( 'manage_options' ) || ! $this->plugin->geoip_manager ) {
            wp_send_json_error( ['message' => 'Permission denied or module not available.'], 403 );
        }
        
        // Aumentamos el límite de tiempo de ejecución para la descarga
        // phpcs:ignore Squiz.PHP.DiscouragedFunctions.Discouraged
        set_time_limit(300);

        $this->plugin->log_event('Starting manual GeoIP database update from Dashboard.', 'info');
        $result = $this->plugin->geoip_manager->download_and_unpack_databases();
        
        if ( $result['success'] ) {
            $this->plugin->log_event('Manual GeoIP database update completed successfully.', 'info');
            wp_send_json_success( ['message' => $result['message']] );
        } else {
            $this->plugin->log_event('Manual GeoIP database update failed: ' . $result['message'], 'error');
            wp_send_json_error( ['message' => $result['message']] );
        }
    }

   /**
 * AJAX callback para obtener las reglas avanzadas, con soporte para paginación.
 */
public function ajax_get_advanced_rules() {
    if (!current_user_can('manage_options')) {
        wp_send_json_error(['message' => __('Permission denied.', 'advanced-ip-blocker')]);
        wp_die();
    }
    check_ajax_referer('advaipbl_get_rules_nonce', 'nonce');
    if (ob_get_level()) {
        ob_clean();
    }
    
    // Support fetching a single rule for editing
    if (isset($_POST['rule_id'])) {
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash
        $rule_id = sanitize_text_field($_POST['rule_id']);
        $all_rules = $this->plugin->rules_engine->get_rules();
        $found_rule = null;
        foreach ($all_rules as $r) {
            if (isset($r['id']) && $r['id'] === $rule_id) {
                $found_rule = $r;
                break;
            }
        }
        
        if ($found_rule) {
             wp_send_json_success(['rules' => [$found_rule]]);
        } else {
             wp_send_json_error(['message' => __('Rule not found.', 'advanced-ip-blocker')]);
        }
    }

    $page = isset($_POST['page']) ? absint($_POST['page']) : 1;
    $per_page = 20;
    $all_rules = $this->plugin->rules_engine->get_rules();
    // REMOVED REVERSE: We want to display rules in priority order (index 0 first).
    $all_rules = is_array($all_rules) ? $all_rules : [];
    $total_items = count($all_rules);
    $total_pages = ceil($total_items / $per_page);
    $rules_for_page = array_slice($all_rules, ($page - 1) * $per_page, $per_page);
    wp_send_json_success([
        'rules'       => $rules_for_page,
        'pagination'  => [
            'total_items' => $total_items,
            'total_pages' => $total_pages,
            'current_page'=> $page,
        ]
    ]);
    wp_die();
}

    /**
     * AJAX callback para guardar (crear o actualizar) una regla avanzada.
     */
    public function ajax_save_advanced_rule() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Permission denied.', 'advanced-ip-blocker')]);
        }
        check_ajax_referer('advaipbl_save_rule_nonce', 'nonce');

        // Decode JSON directly after unslashing. We do NOT use sanitize_text_field here as it breaks JSON structure
        // and stripslashes breaks escaped characters within the JSON strings (e.g., regex backslashes).
        // Individual fields are sanitized later in Rules_Engine::sanitize_rule().
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
        $rule_data = isset($_POST['rule']) ? json_decode(wp_unslash($_POST['rule']), true) : null;
        if (json_last_error() !== JSON_ERROR_NONE || !is_array($rule_data)) {
            wp_send_json_error(['message' => __('Invalid rule data received.', 'advanced-ip-blocker')]);
        }

        // Aquí deberíamos añadir una sanitización profunda, pero por ahora confiamos en la entrada
        $rule_id = $rule_data['id'] ?? null;

        if (empty($rule_id)) { // Es una nueva regla
            $saved_rule = $this->plugin->rules_engine->add_rule($rule_data);
            if ($saved_rule) {
                wp_send_json_success(['message' => __('Rule created successfully.', 'advanced-ip-blocker'), 'rule' => $saved_rule]);
            } else {
                wp_send_json_error(['message' => __('Failed to create rule.', 'advanced-ip-blocker')]);
            }
        } else { // Es una actualización
            if ($this->plugin->rules_engine->update_rule($rule_id, $rule_data)) {
                wp_send_json_success(['message' => __('Rule updated successfully.', 'advanced-ip-blocker'), 'rule' => $rule_data]);
            } else {
                wp_send_json_error(['message' => __('Failed to update rule. It may not exist.', 'advanced-ip-blocker')]);
            }
        }
    }

    /**
     * AJAX callback para eliminar una regla avanzada.
     */
    public function ajax_delete_advanced_rule() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Permission denied.', 'advanced-ip-blocker')]);
        }
        check_ajax_referer('advaipbl_delete_rule_nonce', 'nonce');

        $rule_id = isset($_POST['rule_id']) ? sanitize_text_field(wp_unslash($_POST['rule_id'])) : null;
        if (empty($rule_id)) {
            wp_send_json_error(['message' => __('Invalid rule ID.', 'advanced-ip-blocker')]);
        }

        if ($this->plugin->rules_engine->delete_rule($rule_id)) {
            wp_send_json_success(['message' => __('Rule deleted successfully.', 'advanced-ip-blocker')]);
        } else {
            wp_send_json_error(['message' => __('Failed to delete rule. It may have already been deleted.', 'advanced-ip-blocker')]);
        }
    }
	
	/**
 * AJAX callback para eliminar reglas avanzadas en lote.
 */
public function ajax_bulk_delete_advanced_rules() {
    if (!current_user_can('manage_options')) {
        wp_send_json_error(['message' => __('Permission denied.', 'advanced-ip-blocker')]);
        wp_die();
    }
    check_ajax_referer('advaipbl_bulk_delete_rules_nonce', 'nonce');

    $rule_ids = isset($_POST['rule_ids']) && is_array($_POST['rule_ids']) ? array_map('sanitize_text_field', wp_unslash($_POST['rule_ids']) ) : [];
    if (empty($rule_ids)) {
        wp_send_json_error(['message' => __('No rules selected.', 'advanced-ip-blocker')]);
        wp_die();
    }

    $deleted_count = 0;
    foreach ($rule_ids as $rule_id) {
        if ($this->plugin->rules_engine->delete_rule($rule_id)) {
            $deleted_count++;
        }
    }

    if ($deleted_count > 0) {
        /* translators: %d: Number of rules deleted. */
        $message = sprintf(_n('%d rule deleted successfully.', '%d rules deleted successfully.', $deleted_count, 'advanced-ip-blocker'), $deleted_count);
        wp_send_json_success(['message' => $message]);
    } else {
        wp_send_json_error(['message' => __('Failed to delete the selected rules.', 'advanced-ip-blocker')]);
    }
    wp_die();
}

/**
 * AJAX callback para verificar una clave API de AbuseIPDB.
 */
public function ajax_verify_abuseipdb_key() {
    if (!current_user_can('manage_options')) {
        wp_send_json_error(['message' => __('Permission denied.', 'advanced-ip-blocker')]);
        wp_die();
    }
    check_ajax_referer('advaipbl_verify_abuseipdb_nonce', 'nonce');

    $api_key = isset($_POST['api_key']) ? sanitize_text_field(wp_unslash($_POST['api_key'])) : '';
    
    // La lógica de verificación ya está en el manager, simplemente la llamamos.
    $result = $this->plugin->abuseipdb_manager->verify_api_key($api_key);

    if ($result['success']) {
        wp_send_json_success(['message' => $result['message']]);
    } else {
        wp_send_json_error(['message' => $result['message']]);
    }
    wp_die();
}

/**
     * AJAX callback para ejecutar el escaneo profundo de vulnerabilidades.
     */
    public function ajax_run_deep_scan() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Permission denied.', 'advanced-ip-blocker')]);
        }
        check_ajax_referer('advaipbl_deep_scan_nonce', 'nonce');

        // Asegurar que el scanner está cargado
        if (!isset($this->plugin->site_scanner)) {
             require_once plugin_dir_path(__FILE__) . 'class-advaipbl-site-scanner.php';
             $this->plugin->site_scanner = new ADVAIPBL_Site_Scanner($this->plugin);
        }

        $result = $this->plugin->site_scanner->check_vulnerabilities_via_api();

        if (isset($result['status']) && $result['status'] === 'error') {
            wp_send_json_error(['message' => __('API connection failed. Please try again later.', 'advanced-ip-blocker')]);
        }

        wp_send_json_success($result);
    }
	
	/**
     * AJAX callback para comprobar la reputación del servidor.
     */
    public function ajax_check_server_reputation() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Permission denied.', 'advanced-ip-blocker')]);
        }
        check_ajax_referer('advaipbl_reputation_nonce', 'nonce');

        if (!isset($this->plugin->site_scanner)) {
             require_once plugin_dir_path(__FILE__) . 'class-advaipbl-site-scanner.php';
             $this->plugin->site_scanner = new ADVAIPBL_Site_Scanner($this->plugin);
        }

        $result = $this->plugin->site_scanner->check_server_reputation();
        
        if (isset($result['status']) && $result['status'] === 'error') {
             wp_send_json_error(['message' => $result['message']]);
        }

        wp_send_json_success($result);
    }

    /**
     * Ajax handler to reorder advanced rules.
     */
    public function ajax_reorder_advanced_rules() {
        check_ajax_referer('advaipbl_reorder_rules_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Permission denied.', 'advanced-ip-blocker')]);
        }

        $rule_id = isset($_POST['rule_id']) ? sanitize_text_field(wp_unslash($_POST['rule_id'])) : '';
        $direction = isset($_POST['direction']) ? sanitize_text_field(wp_unslash($_POST['direction'])) : '';

        if (empty($rule_id) || !in_array($direction, ['up', 'down'], true)) {
            wp_send_json_error(['message' => __('Invalid parameters.', 'advanced-ip-blocker')]);
        }

        $rules = $this->plugin->rules_engine->get_rules();
        
        $rules = array_values($rules);
        
        $target_index = -1;

        // Find current index
        foreach ($rules as $index => $rule) {
            if (isset($rule['id']) && $rule['id'] === $rule_id) {
                $target_index = $index;
                break;
            }
        }

        if ($target_index === -1) {
            wp_send_json_error(['message' => __('Rule not found.', 'advanced-ip-blocker')]);
        }

        // Swap logic
        if ($direction === 'up') {
            if ($target_index > 0 && isset($rules[$target_index - 1])) {
                $temp = $rules[$target_index - 1];
                $rules[$target_index - 1] = $rules[$target_index];
                $rules[$target_index] = $temp;
            }
        } elseif ($direction === 'down') {
            if ($target_index < count($rules) - 1 && isset($rules[$target_index + 1])) {
                $temp = $rules[$target_index + 1];
                $rules[$target_index + 1] = $rules[$target_index];
                $rules[$target_index] = $temp;
            }
        }

        update_option(ADVAIPBL_Rules_Engine::OPTION_RULES, $rules);

        wp_send_json_success(['message' => __('Rule reordered successfully.', 'advanced-ip-blocker')]);
    }
    
    /**
     * AJAX action to clear audit logs.
     */
    public function ajax_clear_audit_logs() {
        check_ajax_referer('advaipbl_clear_audit_logs_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Permission denied.', 'advanced-ip-blocker')]);
        }

        if (!isset($this->plugin->audit_logger)) {
            wp_send_json_error(['message' => __('Audit Logger not active.', 'advanced-ip-blocker')]);
        }

        $result = $this->plugin->audit_logger->clear_all_logs();

        if ($result !== false) {
            /* translators: %s: Username. */
            $this->plugin->log_event(sprintf(__('Audit logs manually cleared by %s.', 'advanced-ip-blocker'), $this->plugin->get_current_admin_username()), 'warning');
            wp_send_json_success(['message' => __('Audit logs cleared successfully.', 'advanced-ip-blocker')]);
        } else {
            wp_send_json_error(['message' => __('Failed to clear logs.', 'advanced-ip-blocker')]);
        }
    }

    /**
     * AJAX Handler for manual FIM Scan.
     */


    public function ajax_run_fim_scan() {
        check_ajax_referer('advaipbl_run_fim_scan_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Permission denied.', 'advanced-ip-blocker')]);
        }

        if (empty($this->plugin->options['enable_fim'])) {
            wp_send_json_error(['message' => __('File Integrity Monitor is disabled.', 'advanced-ip-blocker')]);
        }

        if (!isset($this->plugin->file_verifier)) {
             wp_send_json_error(['message' => __('File Verifier module not loaded.', 'advanced-ip-blocker')]);
        }

        $changes = $this->plugin->file_verifier->scan_files();

        if (empty($changes)) {
            wp_send_json_success(['message' => __('Scan complete. No changes detected.', 'advanced-ip-blocker')]);
        } else {
            // Summary count
            $count = count($changes);
            /* translators: %d: Number of files changed. */
            $msg = sprintf(_n('Scan complete. %d file change detected (Alert sent).', 'Scan complete. %d file changes detected (Alert sent).', $count, 'advanced-ip-blocker'), $count);
            wp_send_json_success(['message' => $msg]);
        }
    }

    /**
     * AJAX callback for Bulk Import of IPs to Whitelist.
     */
    public function ajax_bulk_import_whitelist() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Permission denied.', 'advanced-ip-blocker')]);
        }
        check_ajax_referer('advaipbl_bulk_import_whitelist_nonce', 'nonce');

        $raw_data = isset($_POST['ip_list']) ? sanitize_textarea_field(wp_unslash($_POST['ip_list'])) : '';
        $detail = isset($_POST['detail']) ? sanitize_text_field(wp_unslash($_POST['detail'])) : __('Bulk Import', 'advanced-ip-blocker');

        if (empty($raw_data)) {
            wp_send_json_error(['message' => __('No data provided.', 'advanced-ip-blocker')]);
        }

        // Split by new lines
        $lines = preg_split('/\r\n|\r|\n/', $raw_data);
        $imported_count = 0;
        $skipped_count = 0;
        $errors = [];

        foreach ($lines as $line) {
            $ip_or_range = trim($line);
            if (empty($ip_or_range)) continue;

            // Use the main class function to handle validation, unblocking, and adding
            if ($this->plugin->add_to_whitelist_and_unblock($ip_or_range, $detail)) {
                $imported_count++;
            } else {
                $skipped_count++; // Duplicate or invalid
            }
        }

        if ($imported_count > 0) {
            $this->plugin->purge_all_page_caches();
        }

        $message = sprintf(
            /* translators: 1: Number of imported IPs, 2: Number of skipped IPs. */
            __('Import complete. Imported: %1$d. Skipped/Invalid/Duplicate: %2$d.', 'advanced-ip-blocker'),
            $imported_count,
            $skipped_count
        );

        wp_send_json_success(['message' => $message, 'imported' => $imported_count, 'skipped' => $skipped_count]);
    }

    /**
     * AJAX callback for Bulk Export of Whitelisted IPs.
     */
    public function ajax_bulk_export_whitelist() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Permission denied.', 'advanced-ip-blocker')]);
        }
        check_ajax_referer('advaipbl_bulk_export_whitelist_nonce', 'nonce');

        $include_details = isset($_POST['include_details']) && $_POST['include_details'] === 'true';

        // Get whitelist from options
        $whitelist = get_option(ADVAIPBL_Main::OPTION_WHITELIST, []);

        if (empty($whitelist)) {
            wp_send_json_error(['message' => __('Whitelist is empty.', 'advanced-ip-blocker')]);
        }

        $export_data = "";
        
        if ($include_details) {
            // CSV Header
            $export_data .= "IP,Detail,Date\n";
            foreach ($whitelist as $key => $entry) {
                $ip = '';
                $detail = '';
                $date = '';

                // Method 1: IP is the Array Key (Standard Format)
                if (filter_var($key, FILTER_VALIDATE_IP) || strpos($key, '/') !== false) {
                    $ip = $key;
                    if (is_array($entry)) {
                        $detail = isset($entry['detail']) ? $entry['detail'] : '';
                        $ts = $entry['timestamp'] ?? $entry['created_at'] ?? '';
                        $date = $ts ? gmdate('Y-m-d H:i:s', $ts) : '';
                    }
                } 
                // Method 2: IP is inside the array (Hypothetical/Migrated)
                elseif (is_array($entry) && isset($entry['ip'])) {
                    $ip = $entry['ip'];
                    $detail = isset($entry['detail']) ? $entry['detail'] : '';
                    $ts = $entry['timestamp'] ?? $entry['created_at'] ?? '';
                    $date = $ts ? gmdate('Y-m-d H:i:s', $ts) : '';
                } 
                // Method 3: Simple String (Legacy)
                elseif (is_string($entry)) {
                    $ip = $entry;
                }

                if (!empty($ip)) {
                    $detail_csv = '"' . str_replace('"', '""', $detail) . '"';
                    $export_data .= "{$ip},{$detail_csv},{$date}\n";
                }
            }
            $filename = 'aib-whitelist-export-' . gmdate('Y-m-d') . '.csv';
            $content_type = 'text/csv';

        } else {
            // Simple text list (IP per line)
            foreach ($whitelist as $key => $entry) {
                $ip = '';
                if (filter_var($key, FILTER_VALIDATE_IP) || strpos($key, '/') !== false) {
                    $ip = $key;
                } elseif (is_array($entry) && isset($entry['ip'])) {
                    $ip = $entry['ip'];
                } elseif (is_string($entry)) {
                    $ip = $entry;
                }

                if (!empty($ip)) {
                    $export_data .= $ip . "\n";
                }
            }
            $filename = 'aib-whitelist-export-' . gmdate('Y-m-d') . '.txt';
            $content_type = 'text/plain';
        }

        // We return the data URL to be downloaded by JS
        $base64_data = base64_encode($export_data);
        $data_uri = 'data:' . $content_type . ';base64,' . $base64_data;

        wp_send_json_success(['file_url' => $data_uri, 'filename' => $filename]);
    }

    /**
     * AJAX callback for Bulk Import of Blocked IPs.
     */
    public function ajax_bulk_import_blocked_ips() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Permission denied.', 'advanced-ip-blocker')]);
        }
        check_ajax_referer('advaipbl_bulk_import_blocked_ips_nonce', 'nonce');

        $raw_data = isset($_POST['ip_list']) ? sanitize_textarea_field(wp_unslash($_POST['ip_list'])) : '';
        $duration_minutes = isset($_POST['duration']) ? intval($_POST['duration']) : 0;
        
        // El motivo es siempre 'Bulk Import'
        $hardcoded_reason = __('Bulk Import', 'advanced-ip-blocker');

        if (empty($raw_data)) {
            wp_send_json_error(['message' => __('No data provided.', 'advanced-ip-blocker')]);
        }

        $current_time = time();

        // Calculate default expiration timestamp from modal
        $expires_at = 0; // Permanent by default
        if ($duration_minutes > 0) {
            $expires_at = $current_time + ($duration_minutes * 60);
        }

        // Split by new lines
        $lines = preg_split('/\r\n|\r|\n/', $raw_data);
        $imported_count = 0;
        $skipped_count = 0;
        $invalid_count = 0;

        global $wpdb;
        $table_name = $wpdb->prefix . 'advaipbl_blocked_ips';

        foreach ($lines as $line) {
            $line = trim($line);
            if (empty($line)) continue;
            
            // Try to parse as CSV line
            $parsed = str_getcsv($line);
            $ip_or_range = isset($parsed[0]) ? trim($parsed[0]) : '';
            
            // Skip empty IPs or CSV Header
            if (empty($ip_or_range) || strtolower($ip_or_range) === 'ip/cidr') continue;

            if (!$this->plugin->is_valid_ip_or_range($ip_or_range)) {
                $invalid_count++;
                continue;
            }

            // Ignoramos la razón del CSV, forzamos siempre la hardcodeada.
            $item_reason = $hardcoded_reason;

            // Determine Expiration
            $item_expires_at = $expires_at; // fallback to modal calculated expires_at
            if (isset($parsed[2]) && trim($parsed[2]) !== '') {
                $csv_exp = trim($parsed[2]);
                if (strtolower($csv_exp) === 'permanent' || $csv_exp == '0') {
                    $item_expires_at = 0;
                } else {
                    $parsed_time = strtotime($csv_exp);
                    if ($parsed_time !== false) {
                         // Si es una fecha absoluta (e.g. 2024-01-01)
                         // Solo la aceptamos si está en el futuro
                         if ($parsed_time > $current_time) {
                             $item_expires_at = $parsed_time;
                         } else {
                             $item_expires_at = 0; // Ya expiró en el pasado, la tomamos como permanente "rota" o 0
                         }
                    } elseif (is_numeric($csv_exp) && $csv_exp > 0) {
                         // Si es un delta en segundos desde ahora en base a la línea del texto, asumiéndolo igual.
                         // Nosotros sabemos que viene como epoch expirado en la DB
                         // Realmente, en el CSV exportamos "Permanent" o fecha "Y-m-d H:i:s".
                        $item_expires_at = intval($csv_exp);
                    }
                }
            }

            // Check if already in whitelist
            if ($this->plugin->is_whitelisted($ip_or_range)) {
                $skipped_count++;
                continue;
            }

            // Check if actively blocked (expires_at is 0 OR expires_at > current_time)
            $query = "SELECT COUNT(*) FROM {$table_name} WHERE ip_range = %s AND (expires_at = 0 OR expires_at > %d)";
            // phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $exists = $wpdb->get_var($wpdb->prepare($query, $ip_or_range, $current_time));
            // phpcs:enable
            
            if ($exists) {
                $skipped_count++;
                continue;
            }

            // Insert new block
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
            $inserted = $wpdb->insert(
                $table_name,
                [
                    'ip_range' => $ip_or_range,
                    'block_type' => 'bulk_import', // NUEVO TIPO
                    'timestamp' => $current_time,
                    'expires_at' => $item_expires_at,
                    'reason' => $item_reason
                ],
                ['%s', '%s', '%d', '%d', '%s']
            );

            if ($inserted) {
                $imported_count++;
            } else {
                $skipped_count++;
            }
        }

        if ($imported_count > 0 && !empty($this->plugin->options['enable_htaccess_ip_blocking'])) {
            $this->plugin->htaccess_manager->update_htaccess();
        }

        if ($imported_count > 0) {
            $this->plugin->purge_all_page_caches();
        }

        // Si Cloudflare está habilitado, desencadenamos una sincronización asíncrona casi inmediata.
        // Hacemos esto porque sincronizar miles de IPs de forma síncrona aquí podría agotar el tiempo de espera PHP.
        if ($imported_count > 0 && !empty($this->plugin->options['enable_cloudflare'])) {
            if (!wp_next_scheduled('advaipbl_cloudflare_sync_event')) {
                 wp_schedule_single_event(time(), 'advaipbl_cloudflare_sync_event');
            }
        }

        $message = sprintf(
            /* translators: 1: Number of imported IPs, 2: Number of skipped/invalid/duplicate IPs. */
            __('Import complete. Imported: %1$d. Skipped/Invalid/Duplicate: %2$d.', 'advanced-ip-blocker'),
            $imported_count,
            $skipped_count + $invalid_count
        );

        wp_send_json_success(['message' => $message, 'imported' => $imported_count, 'skipped' => $skipped_count, 'invalid' => $invalid_count]);
    }

    /**
     * AJAX callback for Bulk Export of Blocked IPs.
     */
    public function ajax_bulk_export_blocked_ips() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Permission denied.', 'advanced-ip-blocker')]);
        }
        check_ajax_referer('advaipbl_bulk_export_blocked_ips_nonce', 'nonce');

        global $wpdb;
        $table_name = $wpdb->prefix . 'advaipbl_blocked_ips';
        $current_time = time();
        
        // Fetch ALL actively blocked IPs (permanent or not expired)
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $results = $wpdb->get_results($wpdb->prepare("SELECT ip_range, reason, expires_at, block_type FROM {$table_name} WHERE expires_at = 0 OR expires_at > %d", $current_time), ARRAY_A);

        if (empty($results)) {
            wp_send_json_error(['message' => __('No active blocked IPs found to export.', 'advanced-ip-blocker')]);
        }

        $export_data = "IP/CIDR,Reason,Expiration,Type\n";
        
        foreach ($results as $row) {
            $reason_csv = '"' . str_replace('"', '""', $row['reason']) . '"';
            $expiration = ($row['expires_at'] == 0) ? 'Permanent' : gmdate('Y-m-d H:i:s', $row['expires_at']);
            
            $export_data .= "{$row['ip_range']},{$reason_csv},{$expiration},{$row['block_type']}\n";
        }
        
        $filename = 'aib-blocked-ips-export-' . gmdate('Y-m-d') . '.csv';
        $content_type = 'text/csv';

        $base64_data = base64_encode($export_data);
        $data_uri = 'data:' . $content_type . ';base64,' . $base64_data;

        wp_send_json_success(['file_url' => $data_uri, 'filename' => $filename]);
    }

}