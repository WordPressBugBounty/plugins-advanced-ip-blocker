<?php

if (! defined('ABSPATH')) {
    exit;
}

class ADVAIPBL_Cloudflare_Manager
{
    private $plugin;

    private $api_endpoint = 'https://api.cloudflare.com/client/v4/';

    public function __construct(ADVAIPBL_Main $plugin_instance)
    {
        $this->plugin = $plugin_instance;
    }

    /**
     * Makes a request to the Cloudflare API.
     *
     * @param string $method HTTP method (GET, POST, DELETE).
     * @param string $endpoint Relative endpoint (e.g. 'zones/xxx/firewall/access_rules/rules').
     * @param array  $data Data for request body (optional).
     * @param string|null $token Specific token to test (optional). If null, uses the one from options.
     * @return array|WP_Error Decoded response or error.
     */
    private function make_api_request($method, $endpoint, $data = [], $token = null)
    {
        $api_token = $token ?? ($this->plugin->options['cf_api_token'] ?? '');

        if (empty($api_token)) {
            return new WP_Error('cf_no_token', __('Cloudflare API Token is missing.', 'advanced-ip-blocker'));
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

        if (! empty($data) && in_array($method, ['POST', 'PUT', 'PATCH'])) {
            $args['body'] = wp_json_encode($data);
        }

        $response = wp_remote_request($url, $args);

        if (is_wp_error($response)) {
            return $response;
        }

        $body = wp_remote_retrieve_body($response);
        $result = json_decode($body, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            return new WP_Error('cf_invalid_json', __('Invalid JSON response from Cloudflare.', 'advanced-ip-blocker'));
        }

        if (isset($result['success']) && $result['success'] === false) {
            $error_msg = $result['errors'][0]['message'] ?? __('Unknown Cloudflare API error.', 'advanced-ip-blocker');

            return new WP_Error('cf_api_error', 'Cloudflare Error: ' . $error_msg);
        }

        return $result;
    }

    /**
     * Verifies credentials by connecting to the API and validating the Token.
     *
     * @param string $token The API Token to test.
     * @return bool|WP_Error True if valid, Error if failed.
     */
    public function verify_token($token)
    {
        $result = $this->make_api_request('GET', 'user/tokens/verify', [], $token);

        if (is_wp_error($result)) {
            return $result;
        }

        if (isset($result['result']['status']) && $result['result']['status'] === 'active') {
            return true;
        }

        return new WP_Error('cf_token_inactive', __('The API Token is valid but not active.', 'advanced-ip-blocker'));
    }

    /**
     * Adds an IP to Cloudflare access rules (Firewall).
     *
     * @param string $ip The IP or CIDR range to block.
     * @param string $note Note to identify the block (optional).
     * @return bool|WP_Error True if successful.
     */
    public function block_ip($ip, $note = 'Blocked by Advanced IP Blocker')
    {
        $zone_id = $this->plugin->options['cf_zone_id'] ?? '';

        if (empty($zone_id)) {
            return new WP_Error('cf_no_zone', __('Cloudflare Zone ID is missing.', 'advanced-ip-blocker'));
        }

        $payload = [
            'mode'          => 'block',
            'configuration' => [
                'target' => 'ip',
                'value'  => $ip,
            ],
            'notes'         => substr($note, 0, 50) . ' [AIB]',
        ];

        if (strpos($ip, '/') !== false) {
            $payload['configuration']['target'] = 'ip_range';
        }

        $endpoint = "zones/{$zone_id}/firewall/access_rules/rules";
        $result = $this->make_api_request('POST', $endpoint, $payload);

        if (is_wp_error($result)) {
            $err_msg = $result->get_error_message();
            if (strpos($err_msg, 'already exists') !== false || strpos($err_msg, 'duplicate_of_existing') !== false) {
                return true;
            }
            $this->plugin->log_event('Cloudflare Block Failed for ' . $ip . ': ' . $result->get_error_message(), 'error');

            return $result;
        }

        return true;
    }

    /**
     * Removes an IP from Cloudflare.
     * NOTE: Cloudflare requires the rule ID to delete it, not the IP.
     * First we must search for the IP to get its ID.
     *
     * @param string $ip The IP to unblock.
     * @return bool|WP_Error
     */
    public function unblock_ip($ip)
    {
        $zone_id = $this->plugin->options['cf_zone_id'] ?? '';
        if (empty($zone_id)) {
            return false;
        }

        $endpoint_search = "zones/{$zone_id}/firewall/access_rules/rules?configuration.value=" . urlencode($ip);
        $search_result = $this->make_api_request('GET', $endpoint_search);

        if (is_wp_error($search_result)) {
            return $search_result;
        }

        if (empty($search_result['result'])) {
            return true;
        }

        foreach ($search_result['result'] as $rule) {
            $rule_id = $rule['id'];
            $endpoint_delete = "zones/{$zone_id}/firewall/access_rules/rules/{$rule_id}";
            $this->make_api_request('DELETE', $endpoint_delete);
        }

        return true;
    }

    /**
     * Deletes all rules created by the plugin (tagged with [AIB]).
     * Uses a two-step approach (collect -> delete) to avoid pagination issues.
     *
     * @return int|WP_Error Number of deleted rules or error.
     */
    public function clear_all_aib_rules()
    {
        $zone_id = $this->plugin->options['cf_zone_id'] ?? '';
        if (empty($zone_id)) {
            return new WP_Error('cf_no_zone', __('Cloudflare Zone ID is missing.', 'advanced-ip-blocker'));
        }

        $page = 1;
        $ids_to_delete = [];
        $has_more = true;

        // Paso 1: Recopilar todos los IDs a eliminar
        while ($has_more) {
            $endpoint = "zones/{$zone_id}/firewall/access_rules/rules?per_page=100&page={$page}";
            $result = $this->make_api_request('GET', $endpoint);

            if (is_wp_error($result)) {
                return $result;
            }

            $rules = $result['result'] ?? [];
            if (empty($rules)) {
                $has_more = false;
                break;
            }

            foreach ($rules as $rule) {
                if (isset($rule['notes']) && strpos($rule['notes'], '[AIB]') !== false) {
                    $ids_to_delete[] = $rule['id'];
                }
            }

            $total_pages = $result['result_info']['total_pages'] ?? 1;

            if ($page >= $total_pages) {
                $has_more = false;
            } else {
                $page++;
            }
        }

        $deleted_count = 0;
        foreach ($ids_to_delete as $rule_id) {
            $delete_endpoint = "zones/{$zone_id}/firewall/access_rules/rules/{$rule_id}";
            $del_res = $this->make_api_request('DELETE', $delete_endpoint);

            if (! is_wp_error($del_res)) {
                $deleted_count++;
            }
        }

        return $deleted_count;
    }

    public function sync_blocked_ips()
    {
        if (empty($this->plugin->options['enable_cloudflare']) || '1' !== $this->plugin->options['enable_cloudflare']) {
            return;
        }

        $zone_id = $this->plugin->options['cf_zone_id'] ?? '';
        if (empty($zone_id)) {
            return;
        }

        global $wpdb;
        $table_name = $wpdb->prefix . 'advaipbl_blocked_ips';

        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $local_ips = $wpdb->get_col("SELECT ip_range FROM $table_name");

        if (empty($local_ips)) {
            return;
        }

        $cf_ips = [];
        $page = 1;
        $has_more = true;

        while ($has_more) {
            $endpoint = "zones/{$zone_id}/firewall/access_rules/rules?per_page=100&page={$page}";
            $result = $this->make_api_request('GET', $endpoint);

            if (is_wp_error($result)) {
                $this->plugin->log_event('Cloudflare Sync Aborted: Could not fetch current rules. ' . $result->get_error_message(), 'error');

                return;
            }

            $rules = $result['result'] ?? [];
            if (empty($rules)) {
                $has_more = false;
                break;
            }

            foreach ($rules as $rule) {
                if (isset($rule['configuration']['value']) && isset($rule['mode']) && $rule['mode'] === 'block') {
                    $cf_ips[] = $rule['configuration']['value'];
                }
            }

            $total_pages = $result['result_info']['total_pages'] ?? 1;
            if ($page >= $total_pages) {
                $has_more = false;
            } else {
                $page++;
            }
        }

        $ips_to_sync = array_diff($local_ips, $cf_ips);

        if (empty($ips_to_sync)) {
            /* translators: %s is a placeholder */
            $this->plugin->log_event(sprintf(__('Cloudflare Sync Complete. Up to date. Synced: %1$d, Errors: 0', 'advanced-ip-blocker'), count($local_ips)), 'info');

            return;
        }

        $count = 0;
        $errors = 0;

        foreach ($ips_to_sync as $ip) {
            $result = $this->block_ip($ip, 'Synced from Advanced IP Blocker');

            if (is_wp_error($result)) {
                $errors++;
            } else {
                $count++;
            }

            usleep(50000);
        }

        /* translators: %s is a placeholder */
        $this->plugin->log_event(sprintf(__('Cloudflare Sync Complete. Newly Synced: %1$d, Errors: %2$d', 'advanced-ip-blocker'), $count, $errors), 'info');
    }
}
