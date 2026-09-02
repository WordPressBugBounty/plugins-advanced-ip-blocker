<?php

if (! defined('ABSPATH')) {
    exit;
}

class ADVAIPBL_Community_Manager
{
    private $plugin;

    private $feed_url_v2 = 'https://advaipbl.com/wp-content/uploads/advaipbl-feed/blocklist.json';

    private $feed_url_v3 = 'https://advaipbl.com/wp-json/aib-api/v3/community-blocklist';

    private $last_update_option = 'advaipbl_community_last_update';

    public function __construct(ADVAIPBL_Main $plugin_instance)
    {
        $this->plugin = $plugin_instance;
    }

    /**
     * Downloads and updates the community list in the DEDICATED TABLE.
     *
     * @return int|false Number of imported IPs or false if failed.
     */
    public function update_list()
    {
        $feed_data = false;
        $api_token = $this->plugin->options['api_token_v3'] ?? '';

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
                if (!get_transient('advaipbl_community_api_error_cooldown_v3')) {
                    $this->plugin->log_event('AIB Network Sync: V3 failed (' . $error_msg . '), falling back to V2.', 'warning');
                    set_transient('advaipbl_community_api_error_cooldown_v3', true, HOUR_IN_SECONDS);
                }
            }
        }

        if (!$use_v3) {
            $response = wp_remote_get($this->feed_url_v2, [
                'timeout' => 30
            ]);

            if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
                $error_msg = is_wp_error($response) ? $response->get_error_message() : 'HTTP ' . wp_remote_retrieve_response_code($response);
                if (!get_transient('advaipbl_community_api_error_cooldown_v2')) {
                    $this->plugin->log_event('AIB Network list download failed completely. Reason: ' . $error_msg, 'error');
                    set_transient('advaipbl_community_api_error_cooldown_v2', true, HOUR_IN_SECONDS);
                }

                update_option(ADVAIPBL_Main::OPTION_COMMUNITY_SYNC_TIME, time());

                return false;
            }
            $feed_data = wp_remote_retrieve_body($response);
        }

        if (!$feed_data) {
            if (!get_transient('advaipbl_community_api_error_cooldown_nodata')) {
                $this->plugin->log_event('AIB Network list download failed: No data received from V3 or V2.', 'error');
                set_transient('advaipbl_community_api_error_cooldown_nodata', true, HOUR_IN_SECONDS);
            }

            return false;
        }

        $data = json_decode($feed_data, true);

        if (!$data || !isset($data['ips']) || !is_array($data['ips'])) {
            $this->plugin->log_event('AIB Network list download failed: Invalid data format.', 'error');

            return false;
        }

        if (isset($data['status']) && $data['status'] === 'degraded') {
            update_option('advaipbl_network_degraded', true);
        } else {
            delete_option('advaipbl_network_degraded');
        }

        global $wpdb;
        $table_name = $wpdb->prefix . 'advaipbl_community_ips';

        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->query("TRUNCATE TABLE {$table_name}");

        $raw_ips = $data['ips'];

        $min_score = (int) ($this->plugin->options['community_min_score'] ?? 1);
        if ($min_score > 1 && isset($data['scores']) && is_array($data['scores'])) {
            $filtered_ips = [];
            foreach ($raw_ips as $ip) {
                $score = $data['scores'][$ip] ?? 0;
                if ($score >= $min_score) {
                    $filtered_ips[] = $ip;
                }
            }
            $ips = array_unique($filtered_ips);
        } else {
            $ips = array_unique($raw_ips);
        }

        $raw_whitelist = get_option('advaipbl_ips_whitelist', []);
        $whitelisted_ips_flat = [];

        if (is_array($raw_whitelist)) {
            foreach ($raw_whitelist as $key => $val) {
                if (filter_var($key, FILTER_VALIDATE_IP)) {
                    $whitelisted_ips_flat[] = (string)$key;
                } elseif (is_string($val) && filter_var($val, FILTER_VALIDATE_IP)) {
                    $whitelisted_ips_flat[] = $val;
                }
            }
        }

        $server_ip = $this->plugin->get_server_ip();
        if ($server_ip) {
            $whitelisted_ips_flat[] = $server_ip;
        }
        $whitelisted_ips_flat[] = '127.0.0.1';
        $whitelisted_ips_flat[] = '::1';

        $whitelisted_ips_flat = array_unique($whitelisted_ips_flat);

        if (!empty($whitelisted_ips_flat)) {
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

        update_option($this->last_update_option, time());
        delete_transient('advaipbl_community_ips_count');
        delete_option('advaipbl_community_blocklist');

        return $total_ips;
    }

    /**
     * Checks if an IP is in the community table.
     * Direct high-performance SQL query (O(1) thanks to Primary Key).
     *
     * @param string $ip The IP to check.
     * @return bool True if blocked.
     */
    public function is_ip_blocked($ip)
    {
        global $wpdb;
        $table_name = $wpdb->prefix . 'advaipbl_community_ips';

        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $exists = $wpdb->get_var($wpdb->prepare("SELECT 1 FROM {$table_name} WHERE ip = %s LIMIT 1", $ip));

        return (bool) $exists;
    }

    public function get_stats()
    {
        global $wpdb;
        $table_name = $wpdb->prefix . 'advaipbl_community_ips';

        $count = get_transient('advaipbl_community_ips_count');
        if (false === $count) {
            // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $count = $wpdb->get_var("SELECT COUNT(*) FROM {$table_name}");
            set_transient('advaipbl_community_ips_count', $count, 24 * HOUR_IN_SECONDS);
        }

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
    public function register_site()
    {
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

        if ($status_code !== 200) {
            $error_msg = $body['message'] ?? __('Unknown error during registration.', 'advanced-ip-blocker');
            $this->plugin->log_event("Community Network Registration failed (HTTP {$status_code}): {$error_msg}", 'error');

            if ($status_code === 429 || (isset($body['code']) && $body['code'] === 'site_already_registered')) {
                return new WP_Error('registration_failed_handled', $error_msg, ['status' => $status_code]);
            }

            return new WP_Error('registration_failed', $error_msg, ['status' => $status_code]);
        }

        if (isset($body['status']) && $body['status'] === 'success' && !empty($body['api_token'])) {
            $options = $this->plugin->options;
            $options['api_token_v3'] = sanitize_text_field($body['api_token']);
            update_option(ADVAIPBL_Main::OPTION_SETTINGS, $options);
            $this->plugin->options = $options;

            return [
                'api_token' => $body['api_token']
            ];
        }

        $error_msg = $body['message'] ?? __('Failed to generate API Key.', 'advanced-ip-blocker');

        return new WP_Error('registration_failed', $error_msg);
    }
}
