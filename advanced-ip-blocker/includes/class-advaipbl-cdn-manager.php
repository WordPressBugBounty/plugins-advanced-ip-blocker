<?php

/**
 * Advanced IP Blocker - CDN & Proxy Manager
 *
 * This class handles the presets and lists of trusted proxies (CDNs, WAFs).
 * Future implementation can include fetching updated IP lists directly from provider APIs.
 *
 * @package AdvancedIPBlocker
 */

if (! defined('ABSPATH')) {
    exit;
}

class ADVAIPBL_CDN_Manager
{
    /**
     * @var ADVAIPBL_Main The main plugin instance.
     */
    private $plugin;

    /**
     * Constructor.
     *
     * @param ADVAIPBL_Main $plugin The main plugin instance.
     */
    public function __construct($plugin)
    {
        $this->plugin = $plugin;
    }

    /**
     * Returns official Cloudflare IPv4 and IPv6 CIDR ranges.
     *
     * @return array
     */
    public static function get_cloudflare_cidrs()
    {
        return [
            '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
            '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
            '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
            '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',

            '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
            '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
        ];
    }

    /**
     * Returns the default Trusted Proxies configuration string.
     *
     * @return string
     */
    public static function get_default_trusted_proxies()
    {
        return "# Cloudflare\n" . implode("\n", self::get_cloudflare_cidrs()) . "\n# Fastly\nAS54113\n# Local Nginx/Varnish Proxy\n127.0.0.1\n::1";
    }

    /**
     * Get the list of CDN presets for the settings dropdown.
     *
     * This provides the predefined blocks of text (CIDRs or ASNs) that users
     * can easily inject into their Trusted Proxies configuration.
     *
     * @return array Array of CDN presets. Key is the text to inject, value is the display name.
     */
    public function get_presets()
    {
        return [
            '' => __('Select a CDN/Proxy to add...', 'advanced-ip-blocker'),
            "# Cloudflare\n" . implode("\n", self::get_cloudflare_cidrs()) => 'Cloudflare',
            "# Fastly\nAS54113" => 'Fastly',
            "# QUIC.cloud / LiteSpeed\nAS398367\nAS26116" => 'QUIC.cloud',
            "# Sucuri\nAS30148" => 'Sucuri',
            "# Bunny.net (BunnyCDN)\nAS200325" => 'Bunny.net',
            "# KeyCDN\nAS44239" => 'KeyCDN',
        ];
    }

    /**
     * Fetches official IP/CIDR ranges from supported CDN providers.
     *
     * @param string $provider The CDN provider identifier ('cloudflare', 'fastly', 'quiccloud').
     * @return array|false Validated list of IPs/CIDR ranges on success, false otherwise.
     */
    public function fetch_provider_ips($provider)
    {
        $provider = strtolower(trim((string) $provider));
        $raw_entries = [];

        if ($provider === 'cloudflare') {
            $response = wp_remote_get('https://api.cloudflare.com/client/v4/ips', ['timeout' => 10]);
            if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
                return false;
            }
            $data = json_decode(wp_remote_retrieve_body($response), true);
            if (!is_array($data) || empty($data['result']) || !is_array($data['result'])) {
                return false;
            }
            $raw_entries = array_merge($data['result']['ipv4_cidrs'] ?? [], $data['result']['ipv6_cidrs'] ?? []);
        } elseif ($provider === 'fastly') {
            $response = wp_remote_get('https://api.fastly.com/public-ip-list', ['timeout' => 10]);
            if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
                return false;
            }
            $data = json_decode(wp_remote_retrieve_body($response), true);
            if (!is_array($data)) {
                return false;
            }
            $raw_entries = array_merge($data['addresses'] ?? [], $data['ipv6_addresses'] ?? []);
        } elseif ($provider === 'quiccloud') {
            $response = wp_remote_get('https://quic.cloud/ips', ['timeout' => 10]);
            if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
                return false;
            }
            $lines = preg_split('/\r\n|\r|\n/', trim(wp_remote_retrieve_body($response)));
            if (is_array($lines)) {
                $raw_entries = $lines;
            }
        } else {
            return false;
        }

        $validated = [];
        foreach ($raw_entries as $entry) {
            $entry = trim((string) $entry);
            if ($entry === '') {
                continue;
            }
            if (filter_var($entry, FILTER_VALIDATE_IP)) {
                $validated[] = $entry;
                continue;
            }
            if (strpos($entry, '/') !== false) {
                list($ip_part, $prefix_part) = explode('/', $entry, 2);
                if (filter_var($ip_part, FILTER_VALIDATE_IP) && ctype_digit($prefix_part)) {
                    $max_prefix = strpos($ip_part, ':') !== false ? 128 : 32;
                    $prefix_int = (int) $prefix_part;
                    if ($prefix_int >= 0 && $prefix_int <= $max_prefix) {
                        $validated[] = $ip_part . '/' . $prefix_int;
                    }
                }
            }
        }

        return !empty($validated) ? array_values(array_unique($validated)) : false;
    }
}
