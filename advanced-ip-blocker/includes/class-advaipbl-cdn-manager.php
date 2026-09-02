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
     * Get the list of CDN presets for the settings dropdown.
     *
     * This provides the predefined blocks of text (ASNs or IPs) that users
     * can easily inject into their Trusted Proxies configuration.
     *
     * @return array Array of CDN presets. Key is the text to inject, value is the display name.
     */
    public function get_presets()
    {
        return [
            '' => __('Select a CDN/Proxy to add...', 'advanced-ip-blocker'),
            "# Cloudflare\nAS13335\nAS209242\nAS132892\nAS394536\nAS395747" => 'Cloudflare',
            "# Fastly\nAS54113" => 'Fastly',
            "# QUIC.cloud / LiteSpeed\nAS398367\nAS26116" => 'QUIC.cloud',
            "# Sucuri\nAS30148" => 'Sucuri',
            "# Bunny.net (BunnyCDN)\nAS200325" => 'Bunny.net',
            "# KeyCDN\nAS44239" => 'KeyCDN',
            "# StackPath / MaxCDN\nAS33438\nAS12989" => 'StackPath (MaxCDN)'
        ];
    }

    /**
     * Placeholder for future dynamic IP fetching.
     *
     * @param string $provider The CDN provider identifier.
     * @return array|false The list of IPs/ranges if successful, false otherwise.
     */
    public function fetch_provider_ips($provider)
    {
        return false;
    }
}
