<?php

if (! defined('ABSPATH')) {
    exit;
}

class ADVAIPBL_AbuseIPDB_Manager
{
    /**
     * Main plugin class instance.
     * @var ADVAIPBL_Main
     */
    private $plugin;

    private $api_key = '';

    private $api_base_url = 'https://api.abuseipdb.com/api/v2/check';

    /**
     * Constructor.
     * @param ADVAIPBL_Main $plugin_instance
     */
    public function __construct(ADVAIPBL_Main $plugin_instance)
    {
        $this->plugin = $plugin_instance;
        $this->api_key = $this->plugin->options['abuseipdb_api_key'] ?? '';
    }

    /**
     * Checks an IP address against the AbuseIPDB API.
     * Uses a transient to cache results and a "circuit breaker" to avoid exhausting the API quota.
     *
     * @param string $ip The IP to check.
     * @return array|false An array with ['score' => int, 'is_whitelisted' => bool] or false on error/pause.
     */
    public function check_ip($ip)
    {
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

            $pause_duration = 5 * MINUTE_IN_SECONDS;
            $log_message_prefix = 'AbuseIPDB API request failed. Pausing checks for 5 minutes.';

            if ($http_code === 429) {
                $headers = wp_remote_retrieve_headers($response);

                $retry_after_seconds = isset($headers['retry-after']) ? (int) $headers['retry-after'] : HOUR_IN_SECONDS;
                $pause_duration = max($retry_after_seconds, 60);

                $log_message_prefix = sprintf(
                    'AbuseIPDB API rate limit exceeded. Pausing checks for %s.',
                    human_time_diff(time() + $pause_duration)
                );

                if (!get_transient('advaipbl_abuseipdb_notif_sent')) {
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
     * Verifies the validity of an AbuseIPDB API key.
     *
     * @param string $api_key The key to verify.
     * @return array An array with ['success' => bool, 'message' => string].
     */
    public function verify_api_key($api_key)
    {
        if (empty($api_key)) {
            return ['success' => false, 'message' => __('API Key is empty.', 'advanced-ip-blocker')];
        }

        $args = [ 'headers' => [ 'Accept' => 'application/json', 'Key' => $api_key ] ];
        $test_ip = '8.8.8.8';
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
