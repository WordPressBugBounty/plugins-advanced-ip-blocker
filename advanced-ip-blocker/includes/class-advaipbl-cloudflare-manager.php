<?php

if ( ! defined( 'ABSPATH' ) ) exit;

class ADVAIPBL_Cloudflare_Manager {

    private $plugin;
    private $api_endpoint = 'https://api.cloudflare.com/client/v4/';

    public function __construct( ADVAIPBL_Main $plugin_instance ) {
        $this->plugin = $plugin_instance;
    }

    /**
     * Realiza una petición a la API de Cloudflare.
     *
     * @param string $method Método HTTP (GET, POST, DELETE).
     * @param string $endpoint Endpoint relativo (ej: 'zones/xxx/firewall/access_rules/rules').
     * @param array  $data Datos para el cuerpo de la petición (opcional).
     * @param string|null $token Token específico para probar (opcional). Si es null, usa el de las opciones.
     * @return array|WP_Error Respuesta decodificada o error.
     */
    private function make_api_request( $method, $endpoint, $data = [], $token = null ) {
        $api_token = $token ?? ($this->plugin->options['cf_api_token'] ?? '');
        
        if ( empty( $api_token ) ) {
            return new WP_Error( 'cf_no_token', __( 'Cloudflare API Token is missing.', 'advanced-ip-blocker' ) );
        }

        $url = $this->api_endpoint . $endpoint;
        
        $args = [
            'method'    => $method,
            'headers'   => [
                'Authorization' => 'Bearer ' . $api_token,
                'Content-Type'  => 'application/json',
            ],
            'timeout'   => 10,
        ];

        if ( ! empty( $data ) && in_array( $method, ['POST', 'PUT', 'PATCH'] ) ) {
            $args['body'] = wp_json_encode( $data );
        }

        $response = wp_remote_request( $url, $args );

        if ( is_wp_error( $response ) ) {
            return $response;
        }

        $body = wp_remote_retrieve_body( $response );
        $result = json_decode( $body, true );

        if ( json_last_error() !== JSON_ERROR_NONE ) {
            return new WP_Error( 'cf_invalid_json', __( 'Invalid JSON response from Cloudflare.', 'advanced-ip-blocker' ) );
        }

        if ( isset( $result['success'] ) && $result['success'] === false ) {
            $error_msg = $result['errors'][0]['message'] ?? __( 'Unknown Cloudflare API error.', 'advanced-ip-blocker' );
            return new WP_Error( 'cf_api_error', 'Cloudflare Error: ' . $error_msg );
        }

        return $result;
    }

    /**
     * Verifica las credenciales conectando con la API y validando el Token.
     *
     * @param string $token El API Token a probar.
     * @return bool|WP_Error True si es válido, Error si falla.
     */
    public function verify_token( $token ) {
        // Endpoint especial para verificar tokens
        $result = $this->make_api_request( 'GET', 'user/tokens/verify', [], $token );

        if ( is_wp_error( $result ) ) {
            return $result;
        }

        if ( isset( $result['result']['status'] ) && $result['result']['status'] === 'active' ) {
            return true;
        }

        return new WP_Error( 'cf_token_inactive', __( 'The API Token is valid but not active.', 'advanced-ip-blocker' ) );
    }

    /**
     * Añade una IP a las reglas de acceso de Cloudflare (Firewall).
     *
     * @param string $ip La IP o rango CIDR a bloquear.
     * @param string $note Nota para identificar el bloqueo (opcional).
     * @return bool|WP_Error True si éxito.
     */
    public function block_ip( $ip, $note = 'Blocked by Advanced IP Blocker' ) {
        $zone_id = $this->plugin->options['cf_zone_id'] ?? '';
        
        if ( empty( $zone_id ) ) {
            return new WP_Error( 'cf_no_zone', __( 'Cloudflare Zone ID is missing.', 'advanced-ip-blocker' ) );
        }

        // Preparar datos para "IP Access Rules"
        // Documentación: https://developers.cloudflare.com/api/operations/ip-access-rules-for-a-zone-create-an-ip-access-rule
        $payload = [
            'mode'          => 'block', // Opciones: block, challenge, js_challenge, managed_challenge
            'configuration' => [
                'target' => 'ip',
                'value'  => $ip,
            ],
            'notes'         => substr( $note, 0, 50 ) . ' [AIB]', // Cloudflare tiene límite de caracteres en notas
        ];

        // Detectar si es un rango CIDR
        if ( strpos( $ip, '/' ) !== false ) {
            $payload['configuration']['target'] = 'ip_range';
        }

        $endpoint = "zones/{$zone_id}/firewall/access_rules/rules";
        $result = $this->make_api_request( 'POST', $endpoint, $payload );

        if ( is_wp_error( $result ) ) {
            // Si el error es "The rule already exists" (código 10009 approx) o "duplicate_of_existing", lo consideramos éxito.
            $err_msg = $result->get_error_message();
            if ( strpos( $err_msg, 'already exists' ) !== false || strpos( $err_msg, 'duplicate_of_existing' ) !== false ) {
                return true;
            }
            $this->plugin->log_event( 'Cloudflare Block Failed for ' . $ip . ': ' . $result->get_error_message(), 'error' );
            return $result;
        }

        return true;
    }

    /**
     * Elimina una IP de Cloudflare.
     * NOTA: Cloudflare requiere el ID de la regla para borrarla, no la IP.
     * Primero tenemos que buscar la IP para obtener su ID.
     *
     * @param string $ip La IP a desbloquear.
     * @return bool|WP_Error
     */
    public function unblock_ip( $ip ) {
        $zone_id = $this->plugin->options['cf_zone_id'] ?? '';
        if ( empty( $zone_id ) ) return false;

        // 1. Buscar el ID de la regla para esta IP
        $endpoint_search = "zones/{$zone_id}/firewall/access_rules/rules?configuration.value=" . urlencode($ip);
        $search_result = $this->make_api_request( 'GET', $endpoint_search );

        if ( is_wp_error( $search_result ) ) {
            return $search_result;
        }

        if ( empty( $search_result['result'] ) ) {
            // La IP no estaba en Cloudflare, así que "ya está desbloqueada".
            return true;
        }

        // 2. Borrar todas las reglas que coincidan con esa IP (por si hay duplicados)
        foreach ( $search_result['result'] as $rule ) {
            $rule_id = $rule['id'];
            $endpoint_delete = "zones/{$zone_id}/firewall/access_rules/rules/{$rule_id}";
            $this->make_api_request( 'DELETE', $endpoint_delete );
        }

        return true;
    }

    /**
     * Elimina todas las reglas creadas por el plugin (etiquetadas con [AIB]).
     * Utiliza un enfoque de dos pasos (recopilar -> eliminar) para evitar problemas de paginación.
     *
     * @return int|WP_Error Número de reglas eliminadas o error.
     */
    public function clear_all_aib_rules() {
        $zone_id = $this->plugin->options['cf_zone_id'] ?? '';
        if ( empty( $zone_id ) ) return new WP_Error( 'cf_no_zone', __('Cloudflare Zone ID is missing.', 'advanced-ip-blocker') );

        $page = 1;
        $ids_to_delete = [];
        $has_more = true;

        // Paso 1: Recopilar todos los IDs a eliminar
        while ( $has_more ) {
            $endpoint = "zones/{$zone_id}/firewall/access_rules/rules?per_page=100&page={$page}";
            $result = $this->make_api_request( 'GET', $endpoint );

            if ( is_wp_error( $result ) ) {
                return $result;
            }

            $rules = $result['result'] ?? [];
            if ( empty( $rules ) ) {
                $has_more = false;
                break;
            }

            foreach ( $rules as $rule ) {
                // Verificamos si la nota contiene [AIB]
                if ( isset( $rule['notes'] ) && strpos( $rule['notes'], '[AIB]' ) !== false ) {
                    $ids_to_delete[] = $rule['id'];
                }
            }
            
            // Info de paginación
            $total_pages = $result['result_info']['total_pages'] ?? 1;
            
            if ( $page >= $total_pages ) {
                $has_more = false;
            } else {
                $page++;
            }
        }

        // Paso 2: Eliminar los IDs recopilados
        $deleted_count = 0;
        foreach ( $ids_to_delete as $rule_id ) {
            $delete_endpoint = "zones/{$zone_id}/firewall/access_rules/rules/{$rule_id}";
            $del_res = $this->make_api_request( 'DELETE', $delete_endpoint );
            
            if ( ! is_wp_error( $del_res ) ) {
                $deleted_count++;
            }
        }

        return $deleted_count;
    }

    public function sync_blocked_ips() {
        if (empty($this->plugin->options['enable_cloudflare']) || '1' !== $this->plugin->options['enable_cloudflare']) {
            return;
        }

        $zone_id = $this->plugin->options['cf_zone_id'] ?? '';
        if ( empty( $zone_id ) ) {
            return; // No se puede sincronizar sin Zone ID
        }

        global $wpdb;
        $table_name = $wpdb->prefix . 'advaipbl_blocked_ips';
        
        // 1. Obtener IPs locales
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $local_ips = $wpdb->get_col("SELECT ip_range FROM $table_name");

        if (empty($local_ips)) {
            return;
        }

        // 2. Obtener IPs actualmente bloqueadas en Cloudflare (Paso de Reconciliación)
        $cf_ips = [];
        $page = 1;
        $has_more = true;

        while ( $has_more ) {
            $endpoint = "zones/{$zone_id}/firewall/access_rules/rules?per_page=100&page={$page}";
            $result = $this->make_api_request( 'GET', $endpoint );

            if ( is_wp_error( $result ) ) {
                // Si falla la petición de lectura, abortamos para no duplicar reglas ciegamente
                $this->plugin->log_event( 'Cloudflare Sync Aborted: Could not fetch current rules. ' . $result->get_error_message(), 'error' );
                return;
            }

            $rules = $result['result'] ?? [];
            if ( empty( $rules ) ) {
                $has_more = false;
                break;
            }

            foreach ( $rules as $rule ) {
                // Consideramos reglas que tengan el valor de IP y que estén bloqueadas
                if ( isset( $rule['configuration']['value'] ) && isset($rule['mode']) && $rule['mode'] === 'block' ) {
                    $cf_ips[] = $rule['configuration']['value'];
                }
            }
            
            $total_pages = $result['result_info']['total_pages'] ?? 1;
            if ( $page >= $total_pages ) {
                $has_more = false;
            } else {
                $page++;
            }
        }

        // 3. Calcular Delta: ¿Qué IPs locales NO están todavía en Cloudflare?
        $ips_to_sync = array_diff($local_ips, $cf_ips);

        // Si todas las IPs ya existen, el proceso termina en milisegundos sin estrangular la API.
        if (empty($ips_to_sync)) {
            /* translators: 1: The number of IPs synced, 2: The number of errors encountered. */
            $this->plugin->log_event(sprintf(__('Cloudflare Sync Complete. Up to date. Synced: %1$d, Errors: 0', 'advanced-ip-blocker'), count($local_ips)), 'info');
            return;
        }

        $count = 0;
        $errors = 0;

        // 4. Sincronizar solo el delta
        foreach ($ips_to_sync as $ip) {
            $result = $this->block_ip($ip, 'Synced from Advanced IP Blocker');
            
            if (is_wp_error($result)) {
                $errors++;
            } else {
                $count++;
            }
            
            // Pausa sutil (50ms) entre IPs faltantes.  
            usleep(50000); 
        }

        /* translators: 1: The number of IPs synced, 2: The number of errors encountered. */
        $this->plugin->log_event(sprintf(__('Cloudflare Sync Complete. Newly Synced: %1$d, Errors: %2$d', 'advanced-ip-blocker'), $count, $errors), 'info');
    }
}