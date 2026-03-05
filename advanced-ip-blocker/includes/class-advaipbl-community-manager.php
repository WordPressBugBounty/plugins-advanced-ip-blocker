<?php

if ( ! defined( 'ABSPATH' ) ) exit;

class ADVAIPBL_Community_Manager {

    private $plugin;
    private $feed_url = 'https://advaipbl.com/wp-content/uploads/advaipbl-feed/blocklist.json';
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
        $response = wp_remote_get($this->feed_url, ['timeout' => 15]);
        
        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
            return false;
        }
        
        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);
        
        if (!$data || !isset($data['ips']) || !is_array($data['ips'])) {
            return false;
        }
        
        global $wpdb;
        $table_name = $wpdb->prefix . 'advaipbl_community_ips';

        // 1. Vaciar la tabla (Truncate es más rápido que Delete)
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
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
}