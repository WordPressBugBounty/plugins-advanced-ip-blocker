<?php

if (!defined('ABSPATH')) {
    exit;
}

class ADVAIPBL_Asn_Manager
{
    private $main_class;

    private $geolocation_manager;

    /**
     * Constructor.
     * @param ADVAIPBL_Main        $main_class  The main class instance.
     * @param ADVAIPBL_geolocation_manager $geolocation_manager The API manager instance.
     */
    public function __construct(ADVAIPBL_Main $main_class, ADVAIPBL_Geolocation_Manager $geolocation_manager)
    {
        $this->main_class  = $main_class;
        $this->geolocation_manager = $geolocation_manager;
    }

    /**
    * Checks an IP's ASN and, if on a blacklist, returns block details.
    * @param string $ip The visitor's IP.
    * @return array|false An array with block details or false if no match.
    */
    public function check_asn_block($ip)
    {
        $enable_manual_list = !empty($this->main_class->options['enable_manual_asn']);
        $enable_spamhaus_list = !empty($this->main_class->options['enable_spamhaus_asn']);

        if (!$enable_manual_list && !$enable_spamhaus_list) {
            return false;
        }

        $location_data = $this->geolocation_manager->fetch_location($ip);
        $visitor_asn = $this->extract_asn_from_data($location_data);

        if (!$visitor_asn) {
            return false;
        }

        $in_asn_list = function ($asn, $raw_list) {
            if (empty($raw_list)) {
                return false;
            }
            foreach ($raw_list as $entry) {
                $parts = explode('#', $entry);
                if (strtoupper(trim($parts[0])) === strtoupper($asn)) {
                    return true;
                }
            }

            return false;
        };

        $whitelisted_asns = get_option(ADVAIPBL_Main::OPTION_WHITELISTED_ASNS, []);
        if ($in_asn_list($visitor_asn, $whitelisted_asns)) {
            return false;
        }

        $is_blocked = false;
        $block_source = '';

        if ($enable_manual_list) {
            $blocked_asns_manual = get_option(ADVAIPBL_Main::OPTION_BLOCKED_ASNS, []);
            if ($in_asn_list($visitor_asn, $blocked_asns_manual)) {
                $is_blocked = true;
                $block_source = 'Manual List';
            }
        }

        if (!$is_blocked && $enable_spamhaus_list) {
            $blocked_asns_spamhaus = get_option('advaipbl_spamhaus_asn_list', []);
            if (!empty($blocked_asns_spamhaus) && in_array($visitor_asn, $blocked_asns_spamhaus, true)) {
                $is_blocked = true;
                $block_source = 'Spamhaus';
            }
        }

        if ($is_blocked) {
            $asn_name = $location_data['as'] ?? ($location_data['asn']['name'] ?? '');

            /* translators: %s is a placeholder */
            $reason = sprintf(__('Blocked ASN: %1$s (%2$s) - Source: %3$s', 'advanced-ip-blocker'), $visitor_asn, $asn_name, $block_source);
            $log_data = [
                'asn_number' => $visitor_asn,
                'asn_name'   => $asn_name,
                'source'     => $block_source,
                'uri'        => $this->main_class->get_current_request_uri(),
            ];

            return ['reason_message' => $reason, 'log_data' => $log_data];
        }

        return false;
    }

    /**
     * Extracts the ASN number (e.g. "AS15169") from API data.
     * Compatible with ip-api.com and ipinfo.io formats.
     * @param array|null $data The API data.
     * @return string|false The ASN number or false if not found.
     */
    public function extract_asn_from_data($data)
    {
        if (empty($data) || !is_array($data)) {
            return false;
        }

        if (isset($data['asn']['asn']) && preg_match('/^AS\d+$/i', $data['asn']['asn'])) {
            return strtoupper($data['asn']['asn']);
        }

        if (isset($data['as'])) {
            preg_match('/(AS\d+)/i', $data['as'], $matches);
            if (!empty($matches[1])) {
                return strtoupper($matches[1]);
            }
        }

        return false;
    }

    /**
     * Gets the log details (event history) for a specific IP.
     *
     * @param string $ip The IP address to query.
     * @return array|false An array with the event history or false if not found.
     */
    public function get_log_details($ip)
    {
        global $wpdb;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $log_json = $wpdb->get_var($wpdb->prepare(
            // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
            "SELECT log_details FROM {$this->table_name} WHERE ip = %s",
            $ip
        ));

        if ($log_json === null) {
            return false;
        }

        $log_details = json_decode($log_json, true);

        return is_array($log_details) ? $log_details : [];
    }
}
