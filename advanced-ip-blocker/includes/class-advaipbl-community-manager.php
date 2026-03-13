<?php

if ( ! defined( 'ABSPATH' ) ) exit;

class ADVAIPBL_Community_Manager {

    private $plugin;
    private $feed_url_v2 = 'https://advaipbl.com/wp-content/uploads/advaipbl-feed/blocklist.json';
    private $feed_url_v3 = 'https://advaipbl.com/wp-json/aib-api/v3/community-blocklist';
    private $last_update_option = 'advaipbl_community_last_update';

    public function __construct(ADVAIPBL_Main $plugin_instance) {
        $this->plugin = $plugin_instance;
    }

    /**
     * Descarga y actualiza la lista comunitaria en la TABLA DEDICADA.
     *
     * @return int|false Número de IPs importadas o false si falló.
     */
    public function update_list() {
        $feed_data = false; // Initialize feed_data to store the raw JSON body
        $api_token = $this->plugin->options['api_token_v3'] ?? '';

        // VÍA V3 (Prioritaria si hay token)
        $use_v3 = false;
        if (!empty($api_token)) {
            $response = wp_remote_get($this->feed_url_v3, [
                'headers' => [
                    'Authorization' => 'Bearer ' . $api_token,
                    'Accept'        => 'application/json'
                ],
                'timeout' => 30
            ]);

            $status_code = wp_remote_retrieve_response_code($response);
            if (!is_wp_error($response) && $status_code === 200) {
                $feed_data = wp_remote_retrieve_body($response);
                $use_v3 = true;
            } else {
                $error_msg = is_wp_error($response) ? $response->get_error_message() : 'HTTP ' . $status_code;
                $this->plugin->log_event('AIB Network Sync: V3 failed (' . $error_msg . '), falling back to V2.', 'warning');
            }
        }

        // FALLBACK V2 (Si no hay token o falló V3)
        if (!$use_v3) {
            $response = wp_remote_get($this->feed_url_v2, [
                'timeout' => 30
            ]);

            if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
                $error_msg = is_wp_error($response) ? $response->get_error_message() : 'HTTP ' . wp_remote_retrieve_response_code($response);
                $this->plugin->log_event('AIB Network list download failed completely. Reason: ' . $error_msg, 'error');
                
                // Actualizar timestamp para no reintentar de inmediato
                update_option(ADVAIPBL_Main::OPTION_COMMUNITY_SYNC_TIME, time());
                return false;
            }
            $feed_data = wp_remote_retrieve_body($response);
        }

        // Process the downloaded data
        if (!$feed_data) {
            $this->plugin->log_event('AIB Network list download failed: No data received from V3 or V2.', 'error');
            return false;
        }

        $data = json_decode($feed_data, true);
        
        if (!$data || !isset($data['ips']) || !is_array($data['ips'])) {
            $this->plugin->log_event('AIB Network list download failed: Invalid data format.', 'error');
            return false;
        }
        
        global $wpdb;
        $table_name = $wpdb->prefix . 'advaipbl_community_ips';

        // 1. Vaciar la tabla (Truncate es más rápido que Delete)
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->query("TRUNCATE TABLE {$table_name}");

        // 2. Insertar por lotes (Batch Insert) para rendimiento
        $ips = array_unique($data['ips']);

        // [USER-REQUEST] Excluir IPs que estén en la Whitelist del usuario
        // para evitar bloquear tráfico legítimo o denegar acceso propio si la IP cae en la lista comunitaria.
        $raw_whitelist = get_option('advaipbl_ips_whitelist', []);
        $whitelisted_ips_flat = [];

        // Detectar formato: ¿Es asociativo (IP => Data) o indexado?
        // En v8.7+, se usa formato asociativo IP => array('timestamp'..., 'detail'...)
        // Verificamos si la primera clave es string (IP) o si es un array mixto.
        // La forma más segura es recorrerlo.
        if (is_array($raw_whitelist)) {
             foreach ($raw_whitelist as $key => $val) {
                 // Si la clave parece una IP, la usamos. Si el valor es una IP (formato antiguo o simples strings), lo usamos.
                 if (filter_var($key, FILTER_VALIDATE_IP)) {
                     $whitelisted_ips_flat[] = (string)$key;
                 } elseif (is_string($val) && filter_var($val, FILTER_VALIDATE_IP)) {
                     $whitelisted_ips_flat[] = $val;
                 }
             }
        }

        // Add Server IP and Localhost to the exclusion list
        $server_ip = $this->plugin->get_server_ip();
        if ($server_ip) {
            $whitelisted_ips_flat[] = $server_ip;
        }
        $whitelisted_ips_flat[] = '127.0.0.1';
        $whitelisted_ips_flat[] = '::1';

        $whitelisted_ips_flat = array_unique($whitelisted_ips_flat);

        if (!empty($whitelisted_ips_flat)) {
            // Normalizar arrays para asegurar comparación correcta
            $ips = array_diff($ips, $whitelisted_ips_flat);
        }

        $batch_size = 1000;
        $total_ips = count($ips);
        $chunks = array_chunk($ips, $batch_size);

        foreach ($chunks as $chunk) {
            $placeholders = [];
            $values = [];
            foreach ($chunk as $ip) {
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    $placeholders[] = "(%s)";
                    $values[] = $ip;
                }
            }
            
            if (!empty($placeholders)) {
                $query = "INSERT IGNORE INTO {$table_name} (ip) VALUES " . implode(', ', $placeholders);
				// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                $wpdb->query($wpdb->prepare($query, $values));
            }
        }

        // Actualizar timestamp y limpiar opción legacy si existe
        update_option($this->last_update_option, time());
        delete_option('advaipbl_community_blocklist'); // Limpieza legacy
        
        return $total_ips;
    }

    /**
     * Comprueba si una IP está en la tabla comunitaria.
     * Consulta SQL directa de alto rendimiento (O(1) gracias a Primary Key).
     *
     * @param string $ip La IP a verificar.
     * @return bool True si está bloqueada.
     */
    public function is_ip_blocked($ip) {
        global $wpdb;
        $table_name = $wpdb->prefix . 'advaipbl_community_ips';
        
        // Usamos una consulta preparada muy ligera
        // Al ser Primary Key, MySQL responde instantáneamente
        $exists = $wpdb->get_var($wpdb->prepare(

            // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            "SELECT 1 FROM {$table_name} WHERE ip = %s LIMIT 1",
            $ip
        ));
        
        return (bool) $exists;
    }
    
    public function get_stats() {
        global $wpdb;
        $table_name = $wpdb->prefix . 'advaipbl_community_ips';
        
        // Usamos get_var con COUNT rápido
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $count = $wpdb->get_var("SELECT COUNT(*) FROM {$table_name}");

        return [
            'count' => (int) $count,
            'last_update' => get_option($this->last_update_option, 0)
        ];
    }

    /**
     * Registers the site with the Central Server and gets a V3 API Token.
     * Can be called manually via AJAX or automatically during upgrades.
     * 
     * @return array|WP_Error Returns an array with 'api_token' on success, or WP_Error on failure.
     */
    public function register_site() {
        $site_url = home_url();

        $response = wp_remote_post('https://advaipbl.com/wp-json/aib-api/v3/register', [
            'headers' => [
                'Content-Type' => 'application/json',
                'Accept'       => 'application/json'
            ],
            'body' => wp_json_encode(['site_url' => $site_url]),
            'timeout' => 15
        ]);

        if (is_wp_error($response)) {
            $this->plugin->log_event('Community Network Registration failed: ' . $response->get_error_message(), 'error');
            return new WP_Error('registration_failed', $response->get_error_message());
        }

        $status_code = wp_remote_retrieve_response_code($response);
        $body = json_decode(wp_remote_retrieve_body($response), true);

        // Permitir continuar (o al menos loguear info útil) si hay rate-limit o ya registrado
        if ($status_code !== 200) {
            $error_msg = $body['message'] ?? __('Unknown error during registration.', 'advanced-ip-blocker');
            $this->plugin->log_event("Community Network Registration failed (HTTP {$status_code}): {$error_msg}", 'error');
            
            // If the key was already registered or there are too many requests, we don't abort the entire plugin,
            // we just inform. Ideally, for a test environment, the admin should generate
            // from their account or wait.
            if ($status_code === 429 || (isset($body['code']) && $body['code'] === 'site_already_registered')) {
                // For these specific cases, we might not return an error, but rather indicate it's handled.
                // However, the function signature expects WP_Error on failure, so we'll return an error.
                return new WP_Error('registration_failed_handled', $error_msg, ['status' => $status_code]);
            }
            return new WP_Error('registration_failed', $error_msg, ['status' => $status_code]);
        }

        if (isset($body['status']) && $body['status'] === 'success' && !empty($body['api_token'])) {
            $options = $this->plugin->options; // Get current options
            $options['api_token_v3'] = sanitize_text_field($body['api_token']);
            update_option(ADVAIPBL_Main::OPTION_SETTINGS, $options);
            $this->plugin->options = $options; // Update memory cache
            
            return [
                'api_token' => $body['api_token']
            ];
        }

        $error_msg = $body['message'] ?? __('Failed to generate API Key.', 'advanced-ip-blocker');
        return new WP_Error('registration_failed', $error_msg);
    }
}