<?php

if (! defined('ABSPATH')) {
    exit;
}

class ADVAIPBL_Reporter_Manager
{
    private $plugin;

    private $allowed_types = [
        'abuseipdb',
        'asn',
        'waf',
        'login',
        '404',
        '403',
        'honeypot',
        'user_agent',
        'xmlrpc_block',
        'threat_score',
        'rate_limit',
        'aib_network',
        'impersonation',
        'ghost_ip',
        'advanced_rule',
    ];

    public function __construct(ADVAIPBL_Main $plugin_instance)
    {
        $this->plugin = $plugin_instance;
    }

    /**
     * Adds an event to the pending report queue.
     *
     * @param string $ip The attacking IP.
     * @param string $type The block type.
     * @param array $extra_data Context data (UA, URI, Score, etc).
     */
    public function queue_report($ip, $type, $extra_data = [])
    {
        if (! in_array($type, $this->allowed_types, true)) {
            return;
        }

        if (! filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            return;
        }

        if ($type === 'asn' && isset($extra_data['source']) && $extra_data['source'] === 'Manual List') {
            return;
        }

        if ($type === 'advanced_rule') {
            $rule_id = $extra_data['rule_id'] ?? '';
            if (strpos($rule_id, 'ar_zd_') !== 0) {
                return;
            }
        }

        $critical_ips = ['1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4', '9.9.9.9', '149.112.112.112', '208.67.222.222', '208.67.220.220'];
        if (in_array($ip, $critical_ips, true)) {
            return;
        }

        if (isset($this->plugin->geoip_manager) && method_exists($this->plugin->geoip_manager, 'lookup_ip')) {
            $geo_info = $this->plugin->geoip_manager->lookup_ip($ip);
            if ($geo_info && !empty($geo_info['as'])) {
                $asn_code = strtoupper(strtok($geo_info['as'], ' '));
                $critical_asns = ['AS13335', 'AS209242', 'AS15169', 'AS396982', 'AS30036', 'AS16509', 'AS394562', 'AS17012'];
                if (in_array($asn_code, $critical_asns, true)) {
                    return;
                }
            }
        }

        global $wpdb;
        $table_name = $wpdb->prefix . 'advaipbl_pending_reports';

        $context = [
            'ua' => $this->plugin->get_user_agent(),
            'uri' => $extra_data['uri'] ?? '',
            'method' => $this->plugin->get_request_method(),
            'score' => $extra_data['abuse_score'] ?? 0,
            'rule' => $extra_data['rule'] ?? '',
        ];

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
        $wpdb->insert(
            $table_name,
            [
                'ip' => $ip,
                'report_type' => $type,
                'timestamp' => time(),
                'context' => wp_json_encode($context)
            ]
        );
    }

    /**
     * Gets the batch of reports to send and clears the table.
     * Called via Cron.
     *
     * @param int $limit Maximum reports per batch.
     * @return array Data ready to send to the API.
     */
    public function get_batch_for_api($limit = 50)
    {
        global $wpdb;
        $table_name = $wpdb->prefix . 'advaipbl_pending_reports';

        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $rows = $wpdb->get_results($wpdb->prepare("SELECT * FROM {$table_name} ORDER BY timestamp ASC LIMIT %d", $limit), ARRAY_A);

        if (empty($rows)) {
            return [];
        }

        $ids_to_delete = wp_list_pluck($rows, 'id');
        if (! empty($ids_to_delete)) {
            $ids_string = implode(',', array_map('absint', $ids_to_delete));
            // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $wpdb->query("DELETE FROM {$table_name} WHERE id IN ($ids_string)");
        }

        $payload = [
            'site_hash' => hash('sha256', home_url()),
            'version' => ADVAIPBL_VERSION,
            'reports' => []
        ];

        foreach ($rows as $row) {
            $payload['reports'][] = [
                'ip' => $row['ip'],
                'type' => $row['report_type'],
                'ts' => $row['timestamp'],
                'meta' => json_decode($row['context'], true)
            ];
        }

        return $payload;
    }
}
