<?php

if (!defined('ABSPATH')) {
    exit;
}

class ADVAIPBL_Dashboard_Manager
{
    private $main_class;

    private $session_manager;

    /**
     * Modified constructor to accept the main class and session manager.
     * @param ADVAIPBL_Main $main_class
     * @param ADVAIPBL_User_Session_Manager $session_manager
     */
    public function __construct(ADVAIPBL_Main $main_class, ADVAIPBL_User_Session_Manager $session_manager)
    {
        $this->main_class = $main_class;
        $this->session_manager = $session_manager;
    }

    /**
     * Collects all dashboard statistics into a single array.
     * @return array
     */
    public function get_dashboard_stats()
    {
        $this->main_class->limpiar_ips_expiradas();

        $days = 7;
        $date_after = gmdate('Y-m-d H:i:s', strtotime("-{$days} days"));

        $live_attacks_data = $this->get_recent_attacks_for_map();

        $raw_rules_metrics = isset($this->main_class->rules_metrics) ? $this->main_class->rules_metrics->get_metrics() : [];
        $advanced_rules = $this->main_class->rules_engine->get_rules();
        $processed_rules_metrics = [];

        foreach ($raw_rules_metrics as $rule_id => $metrics) {
            $rule_name = 'Unknown Rule';
            foreach ($advanced_rules as $rule) {
                if ($rule['id'] === $rule_id) {
                    $rule_name = $rule['name'];
                    break;
                }
            }
            $processed_rules_metrics[] = [
                'id' => $rule_id,
                'name' => $rule_name,
                'hits' => $metrics['hits'] ?? 0,
                'passed' => $metrics['passed'] ?? 0
            ];
        }

        usort($processed_rules_metrics, function ($a, $b) {
            return $b['hits'] <=> $a['hits'];
        });

        return [
            'summary'            => $this->get_summary_stats($date_after),
            'timeline'           => $this->get_timeline_stats($days, $date_after),
            'top_ips'            => $this->get_top_attackers($date_after),
            'top_countries'      => $this->get_top_countries($date_after),
            'system_status'      => $this->get_system_status(),
            'live_attacks'       => $live_attacks_data,
            'blocked_ips_count'  => count($live_attacks_data),
            'challenge_stats'    => isset($this->main_class->challenge_metrics) ? $this->main_class->challenge_metrics->get_historical_stats() : [],
            'advanced_rules_stats' => array_slice($processed_rules_metrics, 0, 5),
        ];
    }

    /**
     * Gets summary statistics: total blocks and breakdown by type.
     * @param string $date_after Date from which to count (Y-m-d H:i:s format).
     * @return array
     */
    private function get_summary_stats($date_after)
    {
        global $wpdb;
        $table_name = $wpdb->prefix . 'advaipbl_logs';

        // phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $results = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT log_type, COUNT(*) as count
                 FROM {$table_name}
                 WHERE level IN ('critical', 'warning') AND log_type != 'general' AND timestamp >= %s
                 GROUP BY log_type
                 ORDER BY count DESC",
                $date_after
            ),
            ARRAY_A
        );

        $stats = ['total' => 0, 'by_type' => []];
        if ($results) {
            foreach ($results as $row) {
                $stats['total'] += $row['count'];
                $stats['by_type'][$row['log_type']] = $row['count'];
            }
        }

        return $stats;
    }

    /**
     * Gets data for the timeline chart.
     * @param int    $days Number of days back to query.
     * @param string $date_after Date from which to count.
     * @return array
     */
    private function get_timeline_stats($days, $date_after)
    {
        global $wpdb;
        $table_name = $wpdb->prefix . 'advaipbl_logs';

        // phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $results = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT DATE(timestamp) as day, COUNT(*) as count
                 FROM {$table_name}
                 WHERE level IN ('critical', 'warning') AND log_type != 'general' AND timestamp >= %s
                 GROUP BY day
                 ORDER BY day ASC",
                $date_after
            ),
            ARRAY_A
        );

        $timeline = [];
        for ($i = ($days - 1); $i >= 0; $i--) {
            $day_key = gmdate('Y-m-d', strtotime("-{$i} days"));
            $timeline[$day_key] = 0;
        }

        if ($results) {
            foreach ($results as $row) {
                if (isset($timeline[$row['day']])) {
                    $timeline[$row['day']] = (int) $row['count'];
                }
            }
        }

        return $timeline;
    }

    /**
     * Gets the 8 top attacking IPs.
     * @param string $date_after Date from which to count.
     * @return array
     */
    private function get_top_attackers($date_after)
    {
        global $wpdb;
        $table_name = $wpdb->prefix . 'advaipbl_logs';

        // phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $results = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT ip, COUNT(*) as count
                 FROM {$table_name}
                 WHERE level IN ('critical', 'warning') AND log_type != 'general' AND ip NOT IN ('127.0.0.1', '::1') AND timestamp >= %s
                 GROUP BY ip
                 ORDER BY count DESC
                 LIMIT 8",
                $date_after
            ),
            ARRAY_A
        );

        return $results;
    }

    /**
     * Gets the top 8 blocked countries across ALL block types.
     * @param string $date_after Date from which to count.
     * @return array
     */
    private function get_top_countries($date_after)
    {
        global $wpdb;
        $table_name = $wpdb->prefix . 'advaipbl_logs';

        // phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $results = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT JSON_UNQUOTE(JSON_EXTRACT(details, '$.country')) as country, 
                        JSON_UNQUOTE(JSON_EXTRACT(details, '$.country_code')) as country_code, 
                        COUNT(*) as count
                 FROM {$table_name}
                 WHERE level IN ('critical', 'warning')
                   AND log_type != 'general'
                   AND timestamp >= %s 
                   AND JSON_UNQUOTE(JSON_EXTRACT(details, '$.country_code')) IS NOT NULL
                 GROUP BY country_code, country
                 ORDER BY count DESC
                 LIMIT 8",
                $date_after
            ),
            ARRAY_A
        );

        return $results;
    }

    /**
     * Gets specific statistics for Spamhaus protection.
     * @return array
     */
    public function get_spamhaus_stats()
    {
        global $wpdb;
        $table_name = $wpdb->prefix . 'advaipbl_logs';
        $date_after = gmdate('Y-m-d H:i:s', strtotime("-7 days"));

        $spamhaus_asns = get_option('advaipbl_spamhaus_asn_list', []);

        // phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $blocked_count = $wpdb->get_var(
            $wpdb->prepare(
                "SELECT COUNT(DISTINCT ip)
                 FROM {$table_name}
                 WHERE log_type = 'asn'
                   AND details LIKE %s
                   AND timestamp >= %s",
                '%"source":"Spamhaus"%',
                $date_after
            )
        );

        return [
            'list_count'    => count($spamhaus_asns),
            'blocked_count' => (int) $blocked_count,
        ];
    }

    /**
     * Returns the status of each protection module.
     * @return array
     */
    public function get_system_status()
    {
        $options = $this->main_class->options;

        return [
            'cloudflare_sync'    => !empty($options['enable_cloudflare']),
            'htaccess_firewall'  => !empty($options['enable_htaccess_write']),
            'community_network'  => !empty($options['enable_community_blocking']),

            'bot_verification'   => !empty($options['enable_bot_verification']),
            'ai_bot_verification' => isset($options['enable_ai_bot_verification']) ? !empty($options['enable_ai_bot_verification']) : true,
            'monitoring_bot_verification' => isset($options['enable_monitoring_bot_verification']) ? !empty($options['enable_monitoring_bot_verification']) : true,

            'advanced_rule'      => !empty($this->main_class->rules_engine->get_rules()),
            'cloud_advanced_rules' => !empty($options['enable_cloud_advanced_rules']),

            'under_attack_mode'  => (!empty($options['under_attack_mode']) && $options['under_attack_mode'] !== 'off'),
            'block_ghost_ips'    => !empty($options['block_ghost_ips']),
            'xmlrpc_lockdown'    => !empty($options['enable_xmlrpc_lockdown']),
            'login_lockdown'     => !empty($options['enable_login_lockdown']),
            'signature_logging'  => !empty($options['enable_signature_engine']),
            'signature_analysis' => !empty($options['enable_signature_analysis']),
            'signature_blocking' => !empty($options['enable_signature_blocking']),
            'geo_challenge'      => !empty($options['enable_geo_challenge']),
            'rate_limit'         => !empty($options['rate_limiting_enable']),

            'honeypot'           => !empty($options['enable_honeypot_blocking']),
            'waf'                => !empty($options['enable_waf']),
            'intelligent_waf'    => !empty($options['enable_intelligent_waf']),
            'geoblock'           => !empty($options['enable_geoblocking']),
            'user_agent'         => !empty($options['enable_user_agent_blocking']),
            'spamhaus_asn'       => !empty($options['enable_spamhaus_asn']),
            'manual_asn'         => !empty($options['enable_manual_asn']),
            '404_blocking'       => true,
            '403_blocking'       => true,
            'login_blocking'     => true,
            '404_lockdown'       => !empty($options['enable_404_lockdown']),
            '403_lockdown'       => !empty($options['enable_403_lockdown']),
            'xmlrpc_mode'        => $options['xmlrpc_protection_mode'] ?? 'smart',
            'enable_2fa'         => !empty($options['enable_2fa']),

            'abuseipdb'          => !empty($options['enable_abuseipdb']),
            'threat_scoring'     => !empty($options['enable_threat_scoring']),
            'activity_audit'     => !empty($options['enable_audit_log']),

            'disable_imagick'        => !empty($options['disable_imagick']),
            'hide_wp_version'        => !empty($options['hide_wp_version']),
            'disable_app_passwords'  => !empty($options['disable_app_passwords']),
            'disable_file_editor'    => !empty($options['disable_file_editor']),
            'block_php_uploads'      => !empty($options['block_php_uploads']),
            'remove_x_powered_by'    => !empty($options['remove_x_powered_by']),
            'restricted_admins'      => !empty($options['allowed_admin_users']),
        ];
    }

    /**
     * Gets geolocation data and block details (type, duration)
     * of currently blocked IPs for the map.
     *
     * @return array An array of attacks with all data needed for the popup.
     */
    public function get_recent_attacks_for_map()
    {
        $all_blocked_entries = $this->main_class->get_all_blocked_entries();

        if (empty($all_blocked_entries)) {
            return [];
        }

        $ips_to_locate = [];
        foreach ($all_blocked_entries as $entry) {
            $ip = $entry['ip'];
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                $ips_to_locate[] = $ip;
            }
        }
        $ips_to_locate = array_unique($ips_to_locate);

        if (empty($ips_to_locate)) {
            return [];
        }

        $locations = $this->session_manager->get_cached_locations($ips_to_locate);

        $attacks_for_map = [];
        $options = $this->main_class->options;

        $entry_map = [];
        foreach ($all_blocked_entries as $entry) {
            if (filter_var($entry['ip'], FILTER_VALIDATE_IP)) {
                $entry_map[$entry['ip']] = $entry;
            }
        }

        foreach ($locations as $ip => $location_data) {
            if (isset($location_data['lat']) && isset($location_data['lon']) && isset($entry_map[$ip])) {
                $entry = $entry_map[$ip];
                $type = $entry['type'];
                $type_display = ($type === 'threat_score') ? $entry['detail'] : $entry['type_label'];

                $duration_minutes = (int) ($options['duration_' . $type] ?? 1440);
                $duration_text = '';
                if ($type === 'manual' || $duration_minutes <= 0) {
                    $duration_text = __('Permanent', 'advanced-ip-blocker');
                } else {
                    /* translators: %s is a placeholder */
                    $duration_text = sprintf(__('%d minutes', 'advanced-ip-blocker'), $duration_minutes);
                }

                $attacks_for_map[] = [
                    'ip'            => $ip,
                    'lat'           => $location_data['lat'],
                    'lon'           => $location_data['lon'],
                    'country'       => $location_data['country'] ?? 'Unknown',
                    'city'          => $location_data['city'] ?? 'Unknown',
                    'type_label'    => $entry['type_label'],
                    'type_display'  => $type_display,
                    'duration_text' => $duration_text,
                ];
            }
        }

        $limit = 200;

        return array_slice($attacks_for_map, 0, $limit);
    }
}
