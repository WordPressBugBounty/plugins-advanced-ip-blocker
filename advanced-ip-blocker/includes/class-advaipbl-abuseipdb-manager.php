<?php
// En: includes/class-advaipbl-abuseipdb-manager.php

if ( ! defined( 'ABSPATH' ) ) exit;

class ADVAIPBL_AbuseIPDB_Manager {

    /**
     * Instancia de la clase principal del plugin.
     * @var ADVAIPBL_Main
     */
    private $plugin;
    private $api_key = '';
    private $api_base_url = 'https://api.abuseipdb.com/api/v2/check';

    /**
     * Constructor.
     * @param ADVAIPBL_Main $plugin_instance
     */
    public function __construct(ADVAIPBL_Main $plugin_instance) {
        $this->plugin = $plugin_instance;
        $this->api_key = $this->plugin->options['abuseipdb_api_key'] ?? '';
    }

/**
 * Comprueba una dirección IP contra la API de AbuseIPDB.
 * Utiliza un transient para cachear los resultados y un "disyuntor" para no agotar la cuota de la API.
 *
 * @param string $ip La IP a comprobar.
 * @return array|false Un array con ['score' => int, 'is_whitelisted' => bool] o false en caso de error/pausa.
 */
public function check_ip($ip) {
    if (empty($this->api_key) || !filter_var($ip, FILTER_VALIDATE_IP)) {
        return false;
    }

    if (get_transient('advaipbl_abuseipdb_paused')) {
        return false;
    }

    $transient_key = 'advaipbl_abuseipdb_' . md5($ip);
    $cached_result = get_transient($transient_key);
    if ($cached_result !== false) {
        return $cached_result;
    }

    $args = [
        'method'    => 'GET',
        'timeout'   => 10,
        'headers'   => [
            'Accept' => 'application/json',
            'Key'    => $this->api_key,
        ],
    ];
    $query_params = http_build_query(['ipAddress' => $ip, 'maxAgeInDays' => '90']);
    $response = wp_remote_get($this->api_base_url . '?' . $query_params, $args);
    $http_code = wp_remote_retrieve_response_code($response);

    if (is_wp_error($response) || $http_code >= 400) {
        $error_message = is_wp_error($response) ? $response->get_error_message() : 'HTTP ' . $http_code;
        
        $pause_duration = 5 * MINUTE_IN_SECONDS; // Pausa corta por defecto para errores genéricos
        $log_message_prefix = 'AbuseIPDB API request failed. Pausing checks for 5 minutes.';

        if ($http_code === 429) {
            // Obtenemos las cabeceras de la respuesta
            $headers = wp_remote_retrieve_headers($response);
            
            // Usamos la cabecera 'Retry-After' que nos da los segundos exactos a esperar
            $retry_after_seconds = isset($headers['retry-after']) ? (int) $headers['retry-after'] : HOUR_IN_SECONDS;
            $pause_duration = max($retry_after_seconds, 60); // Aseguramos un mínimo de 60s
            
            $log_message_prefix = sprintf(
                'AbuseIPDB API rate limit exceeded. Pausing checks for %s.',
                human_time_diff(time() + $pause_duration)
            );

            // Verificamos si ya hemos enviado una notificación hoy
            if (!get_transient('advaipbl_abuseipdb_notif_sent')) {
                // LOCK FIRST: Establecemos el transient antes de realizar la acción lenta (enviar email) para evitar condiciones de carrera
                set_transient('advaipbl_abuseipdb_notif_sent', true, 24 * HOUR_IN_SECONDS);
                if (isset($this->plugin->notification_manager)) {
                    $this->plugin->notification_manager->send_abuseipdb_limit_email();
                }
            }
        }

        set_transient('advaipbl_abuseipdb_paused', true, $pause_duration);
        $this->plugin->log_event($log_message_prefix . ' ' . $error_message, 'error');

        return false;
    }
    
    $body = wp_remote_retrieve_body($response);
    $data = json_decode($body, true);

    if (json_last_error() !== JSON_ERROR_NONE || !isset($data['data'])) {
        $this->plugin->log_event('AbuseIPDB API returned invalid data. Response: ' . $body, 'error');
        return false;
    }
    
    $result = [
        'score' => (int) ($data['data']['abuseConfidenceScore'] ?? 0),
        'is_whitelisted' => (bool) ($data['data']['isWhitelisted'] ?? false),
    ];

    $cache_duration = 6 * HOUR_IN_SECONDS;
    set_transient($transient_key, $result, $cache_duration);

    return $result;
}

    /**
     * Verifica la validez de una clave API de AbuseIPDB.
     *
     * @param string $api_key La clave a verificar.
     * @return array Un array con ['success' => bool, 'message' => string].
     */
    public function verify_api_key($api_key) {
        if (empty($api_key)) {
            return ['success' => false, 'message' => __('API Key is empty.', 'advanced-ip-blocker')];
        }

        $args = [ 'headers' => [ 'Accept' => 'application/json', 'Key' => $api_key ] ];
        $test_ip = '8.8.8.8'; // IP de Google, sabemos que es "limpia"
        $query_params = http_build_query(['ipAddress' => $test_ip]);
        
        $response = wp_remote_get($this->api_base_url . '?' . $query_params, $args);

        if (is_wp_error($response)) {
            return ['success' => false, 'message' => $response->get_error_message()];
        }

        $http_code = wp_remote_retrieve_response_code($response);
        $body = json_decode(wp_remote_retrieve_body($response), true);

        if ($http_code === 200 && isset($body['data'])) {
            return ['success' => true, 'message' => __('API Key is valid!', 'advanced-ip-blocker')];
        }

        if ($http_code === 401) {
            return ['success' => false, 'message' => __('Authentication failed. The API Key is incorrect.', 'advanced-ip-blocker')];
        }

        $error_message = $body['errors'][0]['detail'] ?? 'An unknown error occurred.';
        return ['success' => false, 'message' => sprintf('Error %d: %s', $http_code, $error_message)];
    }
}