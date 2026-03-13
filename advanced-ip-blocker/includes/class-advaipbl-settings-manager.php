<?php

if ( ! defined( 'ABSPATH' ) ) exit;

class ADVAIPBL_Settings_Manager {

    /**
     * Instancia de la clase principal del plugin.
     * @var ADVAIPBL_Main
     */
    private $plugin;

    /**
     * Instancia de la clase de páginas de administración.
     * @var ADVAIPBL_Admin_Pages
     */
    private $admin_pages;

    /**
     * Constructor.
     * @param ADVAIPBL_Main $plugin_instance
     * @param ADVAIPBL_Admin_Pages $admin_pages_instance
     */
    public function __construct(ADVAIPBL_Main $plugin_instance, ADVAIPBL_Admin_Pages $admin_pages_instance) {
        $this->plugin = $plugin_instance;
        $this->admin_pages = $admin_pages_instance;
    }

    public function register_settings() {
        $page = 'advaipbl_settings_page';

        register_setting('advaipbl_settings_group', ADVAIPBL_Main::OPTION_SETTINGS, [$this, 'sanitize_settings']);
        register_setting('advaipbl_waf_rules_group', ADVAIPBL_Main::OPTION_WAF_RULES, ['sanitize_callback' => [$this, 'sanitize_waf_rules']]);
    
    add_settings_section('advaipbl_general_settings_section', null, null, $page);
    add_settings_field('advaipbl_enable_logging', __('Enable Logging', 'advanced-ip-blocker'), [$this, 'switch_field_callback'], $page, 'advaipbl_general_settings_section', ['name' => 'enable_logging', 'label' => __('Enable logging of events to the database.', 'advanced-ip-blocker')]);
    add_settings_field('advaipbl_log_retention_days', __('Log Retention (days)', 'advanced-ip-blocker'), [$this, 'text_field_callback'], $page, 'advaipbl_general_settings_section', ['name' => 'log_retention_days', 'default' => 30, 'description' => __('Number of days to keep logs in the DB. 0 to disable automatic purging.', 'advanced-ip-blocker')]);
    add_settings_field('advaipbl_log_timezone', __('Timezone for Logs', 'advanced-ip-blocker'), [$this, 'timezone_select_callback'], $page, 'advaipbl_general_settings_section');
    add_settings_field('advaipbl_custom_block_message', __('Block Message', 'advanced-ip-blocker'), [$this, 'textarea_field_callback'], $page, 'advaipbl_general_settings_section', ['name' => 'custom_block_message', 'label' => __('Message for blocked users. Leave blank for default messages.', 'advanced-ip-blocker')]);
    add_settings_field('advaipbl_excluded_error_urls', __('Global URL Exclusions', 'advanced-ip-blocker'), [$this, 'textarea_field_callback'], $page, 'advaipbl_general_settings_section', ['name' => 'excluded_error_urls', 'label' => __('Add one URL path or fragment per line. Requests containing these strings will bypass 404/403 error logging and all JavaScript challenges (Signature, Geo, and Endpoint).', 'advanced-ip-blocker')]);
    add_settings_field('advaipbl_show_admin_bar_menu', __( 'Admin Bar Menu', 'advanced-ip-blocker' ), [$this, 'switch_field_callback'], $page, 'advaipbl_general_settings_section', ['name'  => 'show_admin_bar_menu', 'label' => __( 'Show security menu in the WordPress admin bar', 'advanced-ip-blocker' )]);
    


	add_settings_section('advaipbl_general_settings_section', null, null, $page);
 add_settings_field(
        'advaipbl_allow_telemetry', 
        __('Usage Tracking', 'advanced-ip-blocker'), 
        [$this, 'switch_field_callback'], 
        $page, 
        'advaipbl_general_settings_section', 
        [
            'name' => 'allow_telemetry', 
            'id'   => 'advaipbl_allow_telemetry',
            'label' => __('Share anonymous usage data to help us improve the plugin.', 'advanced-ip-blocker'), 
            'description' => __('<a href="https://advaipbl.com/privacy-policy/" target="_blank">Learn More</a> about what we collect.', 'advanced-ip-blocker')
        ]
    );    
    add_settings_section('advaipbl_email_notifications_section', null, null, $page);
    add_settings_field('advaipbl_enable_email_notifications', __('Enable Email Notifications', 'advanced-ip-blocker'), [$this, 'switch_field_callback'], $page, 'advaipbl_email_notifications_section', ['name' => 'enable_email_notifications', 'label' => __('Send an email when an IP is blocked.', 'advanced-ip-blocker')]);
    add_settings_field('advaipbl_notification_frequency', __('Notification Frequency', 'advanced-ip-blocker'), [$this, 'notification_frequency_callback'], $page, 'advaipbl_email_notifications_section');
    add_settings_field('advaipbl_notification_email', __('Notification Email', 'advanced-ip-blocker'), [$this, 'email_field_callback'], $page, 'advaipbl_email_notifications_section', ['name' => 'notification_email', 'label' => __('Leave empty to use the admin email.', 'advanced-ip-blocker')]);
    add_settings_field( 'advaipbl_send_test_email_button', __( 'Send Test Email', 'advanced-ip-blocker' ), [ $this, 'send_test_email_button_callback' ], $page, 'advaipbl_email_notifications_section' );
    
     // Sub-sección para Push
    add_settings_section('advaipbl_push_notifications_section', null, null, $page);
    add_settings_field('advaipbl_enable_push_notifications', __('Enable Push Notifications', 'advanced-ip-blocker'), [$this, 'switch_field_callback'], $page, 'advaipbl_push_notifications_section', ['name' => 'enable_push_notifications', 'label' => __('Send real-time alerts via webhooks.', 'advanced-ip-blocker')]);
    // Este usará el 'large-text' por defecto, que es correcto para URLs.
    add_settings_field('advaipbl_push_webhook_urls', __('Push Webhook URLs', 'advanced-ip-blocker'), [$this, 'textarea_field_callback'], $page, 'advaipbl_push_notifications_section', ['name' => 'push_webhook_urls', 'description' => __('One URL per line.', 'advanced-ip-blocker')]);
    // A este le especificamos que use 'regular-text'.
    add_settings_field('advaipbl_push_mentions', __('Mentions to Trigger Push', 'advanced-ip-blocker'), [$this, 'textarea_field_callback'], $page, 'advaipbl_push_notifications_section', ['name' => 'push_mentions', 'rows' => 3, 'class' => 'regular-text', 'description' => __('Optional. To force a push notification on Slack/Discord, add a mention like <code>@here</code>, <code>@channel</code>, or a specific <code>@username</code>. Add one per line if needed.', 'advanced-ip-blocker')]);
    add_settings_field('advaipbl_push_critical_only', __('Send Critical Alerts Only', 'advanced-ip-blocker'), [$this, 'switch_field_callback'], $page, 'advaipbl_push_notifications_section', ['name' => 'push_critical_only', 'label' => __('Only send alerts for instant blocks (WAF, Honeypot, etc.), not for threshold-based blocks (404, Login).', 'advanced-ip-blocker')]);
    add_settings_field( 'advaipbl_send_test_push_button', __( 'Send Test Notification', 'advanced-ip-blocker' ), [ $this, 'send_test_push_button_callback' ], $page, 'advaipbl_push_notifications_section' );
	
	// --- Site Scanner Automation Settings ---
        add_settings_section('advaipbl_scanner_settings_section', __('Site Scanner Automation', 'advanced-ip-blocker'), null, $page);

        add_settings_field(
            'advaipbl_enable_scheduled_scans',
            __('Enable Scheduled Scans', 'advanced-ip-blocker'),
            [$this, 'switch_field_callback'],
            $page,
            'advaipbl_scanner_settings_section',
            [
                'name' => 'enable_scheduled_scans',
                'label' => __('Automatically run Deep Scans and email the report.', 'advanced-ip-blocker')
            ]
        );

        add_settings_field(
            'advaipbl_scan_frequency',
            __('Scan Frequency', 'advanced-ip-blocker'),
            [$this, 'scan_frequency_callback'],
            $page,
            'advaipbl_scanner_settings_section'
        );

        add_settings_field(
            'advaipbl_scan_notification_email',
            __('Notification Email', 'advanced-ip-blocker'),
            [$this, 'email_field_callback'],
            $page,
            'advaipbl_scanner_settings_section',
            [
                'name' => 'scan_notification_email',
                'label' => __('Where to send the scan reports (leave blank for admin email).', 'advanced-ip-blocker')
            ]
        );

        add_settings_field(
            'advaipbl_send_test_scan_button',
            __('Run Manual Scan & Email', 'advanced-ip-blocker'),
            [$this, 'send_test_scan_button_callback'], 
            $page,
            'advaipbl_scanner_settings_section'
        );


        // Granular Scan Checks
        add_settings_field('advaipbl_scan_check_ssl', __('Check SSL Certificate', 'advanced-ip-blocker'), [$this, 'switch_field_callback'], $page, 'advaipbl_scanner_settings_section', ['name' => 'scan_check_ssl', 'default' => '1', 'label' => __('Enable SSL/TLS certificate validation.', 'advanced-ip-blocker')]);
        add_settings_field('advaipbl_scan_check_updates', __('Check Updates', 'advanced-ip-blocker'), [$this, 'switch_field_callback'], $page, 'advaipbl_scanner_settings_section', ['name' => 'scan_check_updates', 'default' => '1', 'label' => __('Enable core, plugin, and theme update checks.', 'advanced-ip-blocker')]);
        add_settings_field('advaipbl_scan_check_php', __('Check PHP Version', 'advanced-ip-blocker'), [$this, 'switch_field_callback'], $page, 'advaipbl_scanner_settings_section', ['name' => 'scan_check_php', 'default' => '1', 'label' => __('Enable PHP version compatibility checks.', 'advanced-ip-blocker')]);
        add_settings_field('advaipbl_scan_check_wp', __('Check WordPress Version', 'advanced-ip-blocker'), [$this, 'switch_field_callback'], $page, 'advaipbl_scanner_settings_section', ['name' => 'scan_check_wp', 'default' => '1', 'label' => __('Enable WordPress core version checks.', 'advanced-ip-blocker')]);
        add_settings_field('advaipbl_scan_check_debug', __('Check Debug Mode', 'advanced-ip-blocker'), [$this, 'switch_field_callback'], $page, 'advaipbl_scanner_settings_section', ['name' => 'scan_check_debug', 'default' => '1', 'label' => __('Enable WP_DEBUG status checks.', 'advanced-ip-blocker')]);

	add_settings_section(
        'advaipbl_ip_detection_section',
        null,
        null,
        $page
    );

    add_settings_field(
        'advaipbl_trusted_proxies',
        __('Trusted Proxies', 'advanced-ip-blocker'),
        [$this, 'textarea_field_callback'],
        $page,
        'advaipbl_ip_detection_section',
        [
            'name' => 'trusted_proxies',
            'rows' => 10,
            'label' => __('Define which proxy servers you trust to provide the real visitor IP address. The plugin will only trust headers like <code>X-Forwarded-For</code> if the request comes from one of these IPs, preventing IP spoofing.', 'advanced-ip-blocker'),
            'description' => __('Enter one IP, CIDR range, or ASN per line. Use # for comments. <strong>Example:</strong><br><code># Cloudflare<br>AS13335<br># Varnish Server<br>192.168.0.1<br># Nginx Proxy<br>127.0.0.1</code>', 'advanced-ip-blocker'),
			'help_url' => 'https://advaipbl.com/ip-detection-trusted-proxies-guide/'
        ]
    );
	
        // Sección Geolocation.      
        add_settings_section(
            'advaipbl_geolocation_section', 
            null, 
            null, 
            $page
        );

        add_settings_field(
            'advaipbl_geolocation_method',
            __( 'Geolocation Method', 'advanced-ip-blocker' ),
            [$this, 'geolocation_method_callback'],
            $page,
            'advaipbl_geolocation_section' 
        );
		
		// --- AbuseIPDB Section ---
add_settings_section('advaipbl_abuseipdb_section', null, null, $page);

add_settings_field(
    'advaipbl_enable_abuseipdb',
    __('Enable AbuseIPDB Protection', 'advanced-ip-blocker'),
    [$this, 'switch_field_callback'],
    $page,
    'advaipbl_abuseipdb_section',
    [
        'name' => 'enable_abuseipdb',
        'label' => __('Activate real-time IP reputation checking.', 'advanced-ip-blocker'),
		'help_url' => 'https://advaipbl.com/abuseipdb-integration-guide/'
    ]
);

add_settings_field(
    'advaipbl_abuseipdb_api_key',
    __('AbuseIPDB API Key', 'advanced-ip-blocker'),
    [$this, 'text_field_callback'],
    $page,
    'advaipbl_abuseipdb_section',
    [
        'name' => 'abuseipdb_api_key',
        'class' => 'regular-text',
        'data_provider' => 'abuseipdb' // Usado por JS para el botón de verificar
    ]
);

add_settings_field(
    'advaipbl_abuseipdb_threshold',
    __('Blocking Confidence Score', 'advanced-ip-blocker'),
    [$this, 'text_field_callback'],
    $page,
    'advaipbl_abuseipdb_section',
    [
        'name' => 'abuseipdb_threshold',
        'default' => 90,
        'description' => __('Block IPs with an abuse confidence score of this value or higher (0-100). Recommended: 90 or 100.', 'advanced-ip-blocker')
    ]
);

add_settings_field(
            'advaipbl_abuseipdb_action',
            __('Action on High Score', 'advanced-ip-blocker'),
            [$this, 'action_select_callback'],
            $page,
            'advaipbl_abuseipdb_section',
            [
                'name' => 'abuseipdb_action',
                'description' => __('Choose whether to block high-risk IPs immediately or to present them with a JavaScript challenge.', 'advanced-ip-blocker')
            ]
        );

add_settings_field(
    'advaipbl_duration_abuseipdb',
    __('Block Duration (minutes)', 'advanced-ip-blocker'),
    [$this, 'text_field_callback'],
    $page,
    'advaipbl_abuseipdb_section',
    [
        'name' => 'duration_abuseipdb',
        'default' => 1440, // 24 horas
        'description' => __('How long to block an IP flagged by AbuseIPDB. Set to 0 for a permanent block.', 'advanced-ip-blocker')
    ]
);

// --- AIB COMMUNITY NETWORK SECTION ---
        add_settings_section('advaipbl_community_network_section', null, null, $page);

        // --- V3 API Connection ---
        add_settings_field(
            'advaipbl_api_connection_status',
            __('AIB Account Connection', 'advanced-ip-blocker'),
            [$this, 'api_connection_status_callback'],
            $page,
            'advaipbl_community_network_section'
        );

        add_settings_field(
            'advaipbl_api_token_v3', 
            __('API Token', 'advanced-ip-blocker'), 
            [$this, 'api_token_field_callback'], 
            $page, 
            'advaipbl_community_network_section', 
            [
                'name' => 'api_token_v3',
                'description' => __('Connecting to the Advanced IP Blocker cloud network gives you access to the community blocklist and deep site scanning.', 'advanced-ip-blocker'),
            ]
        );

        add_settings_field(
            'advaipbl_enable_community_network', 
            __('Join Community Defense Network', 'advanced-ip-blocker'), 
            [$this, 'switch_field_callback'], 
            $page, 
            'advaipbl_community_network_section', 
            [
                'name' => 'enable_community_network', 
                'label' => __('Enable Community Defense', 'advanced-ip-blocker'),
                'description' => __('Participate in the global defense network. Your plugin will share anonymized attack data (Verified IPs) to help build the <strong>AIB Community Blocklist</strong>.', 'advanced-ip-blocker'),
				'help_url' => 'https://advaipbl.com/aib-community-defense-network/'
            ]
        );
        
        add_settings_field(
            'advaipbl_enable_community_blocking', 
            __('Enable Community Blocking', 'advanced-ip-blocker'), 
            [$this, 'switch_field_callback'], 
            $page, 
            'advaipbl_community_network_section', 
            [
                'name' => 'enable_community_blocking', 
                'label' => __('Block visitors found in the global AIB Community Blocklist.', 'advanced-ip-blocker')
            ]
        );
        
        add_settings_field(
            'advaipbl_community_blocking_action', 
            __('Action', 'advanced-ip-blocker'), 
            [$this, 'action_select_callback'], // Usamos el nuevo callback genérico
            $page, 
            'advaipbl_community_network_section',
            [
                'name' => 'community_blocking_action',
                'description' => __('Decide how to handle IPs listed in the community database.', 'advanced-ip-blocker')
            ]
        );
		
		add_settings_field(
            'advaipbl_duration_aib_network', 
            __('Block Duration (minutes)', 'advanced-ip-blocker'), 
            [$this, 'text_field_callback'], 
            $page, 
            'advaipbl_community_network_section', 
            [
                'name' => 'duration_aib_network', 
                'default' => 1440, 
                'description' => __('How long to block an IP listed in the community database. Set to 0 for a permanent block.', 'advanced-ip-blocker')
            ]
        );
		
		    // --- Geo-Challenge Section ---
    add_settings_section('advaipbl_geochallenge_settings_section', null, null, $page );
    add_settings_field(
        'advaipbl_enable_geo_challenge', 
        __('Enable Geo-Challenge', 'advanced-ip-blocker'), 
        [$this, 'switch_field_callback'], 
        $page, 
        'advaipbl_geochallenge_settings_section', 
        [
            'name' => 'enable_geo_challenge', 
            'label' => __('Activate country-based JavaScript challenge.', 'advanced-ip-blocker'),
            'description' => __('Instead of a hard block, this presents a quick, invisible JavaScript challenge... <br><strong>Note:</strong> If you use a page caching plugin (e.g., WP Rocket, WP Fastest Cache), you may need to exclude the challenge cookie <code>advaipbl_js_verified</code> from being cached to prevent issues.', 'advanced-ip-blocker')
        ]
    );
    add_settings_field(
        'advaipbl_geo_challenge_countries', 
        __( 'Challenged Countries', 'advanced-ip-blocker' ), 
        [ $this, 'geoblock_countries_callback' ], 
        $page, 
        'advaipbl_geochallenge_settings_section',
        ['type' => 'geo_challenge']
    );
    add_settings_field(
        'advaipbl_geo_challenge_cookie_duration', 
        __( 'Access Duration (Hours)', 'advanced-ip-blocker' ), 
        [ $this, 'text_field_callback' ], 
        $page, 
        'advaipbl_geochallenge_settings_section', 
        [
            'name' => 'geo_challenge_cookie_duration', 
            'default' => 24, 
            'description' => __( 'How long a visitor can access the site after passing the challenge. Set to 0 for the browser session only.', 'advanced-ip-blocker' )
        ]
    );
        

        
        // API PROVIDER (solo para el método 'api')
        add_settings_field(
            'advaipbl_geolocation_provider', 
            __( 'API Provider', 'advanced-ip-blocker' ), 
            [$this, 'geolocation_provider_callback'], 
            $page, 
            'advaipbl_geolocation_section', 
            ['class' => 'advaipbl-geolocation-api-option'] // Clase para JS
        );
        
        // API KEYS (solo para el método 'api')
        add_settings_field('advaipbl_api_key_ip_apicom', 'ip-api.com ' . __('API Key', 'advanced-ip-blocker'), [$this, 'text_field_callback'], $page, 'advaipbl_geolocation_section', ['name' => 'api_key_ip_apicom', 'description' => __('Optional key for HTTPS access.', 'advanced-ip-blocker'), 'class' => 'api-key-field advaipbl-geolocation-api-option', 'data_provider' => 'ip-api.com']);
        add_settings_field('advaipbl_api_key_ipinfocom', 'ipinfo.io ' . __('API Key', 'advanced-ip-blocker'), [$this, 'text_field_callback'], $page, 'advaipbl_geolocation_section', ['name' => 'api_key_ipinfocom', 'description' => __('API key is recommended for higher limits.', 'advanced-ip-blocker'), 'class' => 'api-key-field advaipbl-geolocation-api-option', 'data_provider' => 'ipinfo.io']);
        add_settings_field('advaipbl_api_key_ipapicom', 'ipapi.com ' . __('API Key', 'advanced-ip-blocker'), [$this, 'text_field_callback'], $page, 'advaipbl_geolocation_section', ['name' => 'api_key_ipapicom', 'description' => __('API Key is required.', 'advanced-ip-blocker'), 'class' => 'api-key-field advaipbl-geolocation-api-option', 'data_provider' => 'ipapi.com']);
        add_settings_field('advaipbl_api_key_ipstackcom', 'ipstack.com ' . __('API Key', 'advanced-ip-blocker'), [$this, 'text_field_callback'], $page, 'advaipbl_geolocation_section', ['name' => 'api_key_ipstackcom', 'description' => __('API Key is required.', 'advanced-ip-blocker'), 'class' => 'api-key-field advaipbl-geolocation-api-option', 'data_provider' => 'ipstack.com']);

        // MAXMIND (solo para el método 'local_db')
        add_settings_field('advaipbl_maxmind_license_key', __( 'MaxMind License Key', 'advanced-ip-blocker' ), [$this, 'text_field_callback'], $page, 'advaipbl_geolocation_section', ['name' => 'maxmind_license_key', 'class' => 'advaipbl-geolocation-db-option', 'description' => sprintf( wp_kses( /* translators: $s: Maxmind website URL */ __( 'Required for the Local Database method. Get a free key from the <a href="%s" target="_blank">MaxMind website</a>.', 'advanced-ip-blocker' ), ['a' => ['href' => [], 'target' => []]] ), 'https://www.maxmind.com/en/geolite2/signup' )]);
        add_settings_field('advaipbl_geoip_db_status', __( 'Local Database Status', 'advanced-ip-blocker' ), [$this, 'geoip_db_status_callback'], $page, 'advaipbl_geolocation_section', ['class' => 'advaipbl-geolocation-db-option']);
        
        // CACHE (siempre visible)
        add_settings_field('advaipbl_clear_location_cache_button', __('Geolocation Cache', 'advanced-ip-blocker'), [$this, 'clear_cache_button_callback'], $page, 'advaipbl_geolocation_section');

    add_settings_section('advaipbl_geoblocking_settings_section', null, null, $page );
    add_settings_field('advaipbl_enable_geoblocking', __('Enable Geoblocking', 'advanced-ip-blocker'), [$this, 'switch_field_callback'], $page, 'advaipbl_geoblocking_settings_section', ['name' => 'enable_geoblocking', 'label' => __('Activate country-based blocking.', 'advanced-ip-blocker'), 'description' => sprintf(__('Block access from entire countries. This feature requires a working Geolocation Provider to be configured above.', 'advanced-ip-blocker'))]);
    add_settings_field('advaipbl_geoblock_countries', __( 'Blocked Countries', 'advanced-ip-blocker' ), [ $this, 'geoblock_countries_callback' ], $page, 'advaipbl_geoblocking_settings_section' );
    add_settings_field('advaipbl_duration_geoblock', __( 'Geoblock Duration (min)', 'advanced-ip-blocker' ), [ $this, 'text_field_callback' ], $page, 'advaipbl_geoblocking_settings_section', ['name' => 'duration_geoblock', 'default' => 1440, 'description' => __( 'How long an IP from a blocked country will be blocked. Set to 0 for a permanent block.', 'advanced-ip-blocker' )]);
    
    add_settings_section('advaipbl_honeypot_settings_section', null, null, $page);
    add_settings_field(
            'advaipbl_enable_honeypot_blocking', 
            __('Enable Honeypot Blocking', 'advanced-ip-blocker'), 
            [$this, 'switch_field_callback'], 
            $page, 
            'advaipbl_honeypot_settings_section', 
            [
                'name' => 'enable_honeypot_blocking', 
                'label' => __('Activate Honeypot trap protection.', 'advanced-ip-blocker'), 
                'description' => sprintf(/* translators: $s: Honeypot blocking rules URL */__('Manage Honeypot URLs in the <a href="%s">Blocking Rules</a> tab.', 'advanced-ip-blocker'), admin_url('admin.php?page=advaipbl_settings_page&tab=rules&sub-tab=honeypot')),
                'help_url' => 'https://advaipbl.com/honeypot-guide/'
            ]
        );
    add_settings_field('advaipbl_duration_honeypot', __('Honeypot Duration (min)', 'advanced-ip-blocker'), [$this, 'text_field_callback'], $page, 'advaipbl_honeypot_settings_section', ['name' => 'duration_honeypot', 'default' => 1440, 'description' => __('Block duration for IPs that fall into a honeypot URL. Set to 0 for a permanent block.', 'advanced-ip-blocker')]);
    
    add_settings_section('advaipbl_user_agent_settings_section', null, null, $page);
    add_settings_field('advaipbl_enable_user_agent_blocking', __('Enable User-Agent Blocking', 'advanced-ip-blocker'), [$this, 'switch_field_callback'], $page, 'advaipbl_user_agent_settings_section', ['name' => 'enable_user_agent_blocking', 'label' => __('Activate User-Agent based blocking.', 'advanced-ip-blocker'), 'description' => sprintf(/* translators: $s: User-Agent blocking rules URL */__('Manage User-Agent lists in the <a href="%s">Blocking Rules</a> tab.', 'advanced-ip-blocker'), admin_url('admin.php?page=advaipbl_settings_page&tab=rules&sub-tab=user_agents'))]);
    add_settings_field('advaipbl_duration_user_agent', __('User-Agent Duration (min)', 'advanced-ip-blocker'), [$this, 'text_field_callback'], $page, 'advaipbl_user_agent_settings_section', ['name' => 'duration_user_agent', 'default' => 1440, 'description' => __('Block duration for IPs with a malicious User-Agent. Set to 0 for a permanent block.', 'advanced-ip-blocker')]);
    add_settings_field(
    'advaipbl_enable_bot_verification',
    __('Verify Known Bots', 'advanced-ip-blocker'),
    [$this, 'switch_field_callback'],
    $page,
    'advaipbl_user_agent_settings_section',
    [
        'name' => 'enable_bot_verification',
        'label' => __('Enable reverse DNS verification for known crawlers (e.g., Googlebot, Bingbot).', 'advanced-ip-blocker'),
        'description' => __('This prevents attackers from bypassing rules by faking their User-Agent. If an IP claims to be Googlebot but fails verification, it will be treated as a threat.', 'advanced-ip-blocker')
    ]
);

    add_settings_section('advaipbl_asn_protection_section', __('ASN Protection', 'advanced-ip-blocker'), null, $page);
    add_settings_field(
            'advaipbl_enable_spamhaus_asn', 
            __('Spamhaus ASN Protection', 'advanced-ip-blocker'), 
            [$this, 'switch_field_callback'], 
            $page, 
            'advaipbl_asn_protection_section', 
            [
                'name' => 'enable_spamhaus_asn', 
                'label' => __('Enable automatic blocking using the Spamhaus ASN DROP list.', 'advanced-ip-blocker'), 
                'description' => __('Provides a powerful, auto-updating layer of protection against the worst networks on the internet. The list is refreshed daily.', 'advanced-ip-blocker'),
                'help_url' => 'https://advaipbl.com/asn-blocking-guide/'
            ]
        );
    add_settings_field('advaipbl_enable_manual_asn', __('Manual ASN Protection', 'advanced-ip-blocker'), [$this, 'switch_field_callback'], $page, 'advaipbl_asn_protection_section', ['name' => 'enable_manual_asn', 'label' => __('Enable blocking based on your custom Manual ASN Blocklist.', 'advanced-ip-blocker'), 'description' => sprintf(/* translators: $s: ASN blocklist rules URL */__('Manage your custom list in the <a href="%s">Blocking Rules</a> tab.', 'advanced-ip-blocker'), admin_url('admin.php?page=advaipbl_settings_page&tab=rules&sub-tab=asn_blocking'))]);
    add_settings_field('advaipbl_duration_asn', __('ASN Block Duration (min)', 'advanced-ip-blocker'), [$this, 'text_field_callback'], $page, 'advaipbl_asn_protection_section', ['name' => 'duration_asn', 'default' => 1440, 'description' => __('Duration to block IPs from both manual and automated ASN lists. Set to <strong>0</strong> for a permanent block.', 'advanced-ip-blocker')]);

    add_settings_section('advaipbl_waf_settings_section', null, null, $page);
    add_settings_field(
            'advaipbl_enable_waf', 
            __('Enable WAF', 'advanced-ip-blocker'), 
            [$this, 'switch_field_callback'], 
            $page, 
            'advaipbl_waf_settings_section', 
            [
                'name' => 'enable_waf', 
                'label' => __('Activate the WAF to scan requests against your custom rules.', 'advanced-ip-blocker'),
                'description' => sprintf(/* translators: $s: WAF blocking rules URL */__('Manage WAF rules in the <a href="%s">Blocking Rules</a> tab.', 'advanced-ip-blocker'), admin_url('admin.php?page=advaipbl_settings_page&tab=rules&sub-tab=waf')),
                'help_url' => 'https://advaipbl.com/waf-rules-guide/'
            ]
        );
    add_settings_field('advaipbl_duration_waf', __('WAF Block Duration (min)', 'advanced-ip-blocker'), [$this, 'text_field_callback'], $page, 'advaipbl_waf_settings_section', ['name' => 'duration_waf', 'default' => 1440, 'description' => __('Duration to block IPs that trigger a WAF rule. Set to 0 for a permanent block.', 'advanced-ip-blocker')]);
    add_settings_field('advaipbl_waf_excluded_urls', __('Excluded URLs for WAF', 'advanced-ip-blocker'), [$this, 'textarea_field_callback'], $page, 'advaipbl_waf_settings_section', ['name' => 'waf_excluded_urls', 'label' => __('Add one URL fragment per line. Requests to URLs containing these strings will not be scanned by the WAF. Use this for payment gateway webhooks or problematic AJAX actions.', 'advanced-ip-blocker')]);
    
    add_settings_section('advaipbl_404_settings_section', null, null, $page);

    // --- 404 Distributed Lockdown Settings ---
    add_settings_field('advaipbl_enable_404_lockdown', __('Enable 404 Lockdown Mode', 'advanced-ip-blocker'), [$this, 'switch_field_callback'], $page, 'advaipbl_404_settings_section', ['name' => 'enable_404_lockdown', 'label' => __('Activate Distributed Attack Protection', 'advanced-ip-blocker'), 'description' => __('If enabled, a global "Lockdown" will be triggered when too many 404 errors occur from multiple IPs. During lockdown, ALL 404 visitors must solve a JS Challenge.', 'advanced-ip-blocker')]);
    
    add_settings_field('advaipbl_lockdown_404_event_threshold', __('Lockdown Trigger: Max Errors', 'advanced-ip-blocker'), [$this, 'text_field_callback'], $page, 'advaipbl_404_settings_section', ['name' => 'lockdown_404_event_threshold', 'default' => 50, 'description' => __('Total 404 errors allowed across the entire site...', 'advanced-ip-blocker')]); 
    add_settings_field('advaipbl_lockdown_404_ip_threshold', __('Lockdown Trigger: Min Unique IPs', 'advanced-ip-blocker'), [$this, 'text_field_callback'], $page, 'advaipbl_404_settings_section', ['name' => 'lockdown_404_ip_threshold', 'default' => 5, 'description' => __('...originating from at least this many unique IPs...', 'advanced-ip-blocker')]);
    add_settings_field('advaipbl_lockdown_404_window', __('Lockdown Trigger: Time Window', 'advanced-ip-blocker'), [$this, 'text_field_callback'], $page, 'advaipbl_404_settings_section', ['name' => 'lockdown_404_window', 'default' => 10, 'description' => __('...within this many minutes.', 'advanced-ip-blocker')]);
    add_settings_field('advaipbl_lockdown_404_duration', __('Lockdown Duration (min)', 'advanced-ip-blocker'), [$this, 'text_field_callback'], $page, 'advaipbl_404_settings_section', ['name' => 'lockdown_404_duration', 'default' => 60, 'description' => __('How long the Lockdown Mode stays active.', 'advanced-ip-blocker')]);
    
    // Separator
    add_settings_field('advaipbl_404_separator', '', [$this, 'separator_callback'], $page, 'advaipbl_404_settings_section');

    // --- Existing Single IP Settings ---
    add_settings_field('advaipbl_threshold_404', __('Single IP: Block Threshold', 'advanced-ip-blocker'), [$this, 'text_field_callback'], $page, 'advaipbl_404_settings_section', ['name' => 'threshold_404', 'default' => 10, 'description' => __('Block a specific IP if it generates this many 404 errors.', 'advanced-ip-blocker')]);
    add_settings_field('advaipbl_transient_expiration_404', __('404 Time Window (min)', 'advanced-ip-blocker'), [$this, 'text_field_callback'], $page, 'advaipbl_404_settings_section', ['name' => 'transient_expiration_404', 'default' => 60, 'description' => __('Time period in which the error count must be reached.', 'advanced-ip-blocker')]);
    add_settings_field('advaipbl_duration_404', __('404 Duration (min)', 'advanced-ip-blocker'), [$this, 'text_field_callback'], $page, 'advaipbl_404_settings_section', ['name' => 'duration_404', 'default' => 120, 'description' => __('How long the IP will be blocked.', 'advanced-ip-blocker')]);
    
    add_settings_section('advaipbl_403_settings_section', null, null, $page);

    // --- 403 Distributed Lockdown Settings ---
    add_settings_field('advaipbl_enable_403_lockdown', __('Enable 403 Lockdown Mode', 'advanced-ip-blocker'), [$this, 'switch_field_callback'], $page, 'advaipbl_403_settings_section', ['name' => 'enable_403_lockdown', 'label' => __('Activate Distributed Attack Protection', 'advanced-ip-blocker'), 'description' => __('If enabled, a global "Lockdown" will be triggered when too many 403 errors occur. During lockdown, ALL 403 visitors must solve a JS Challenge.', 'advanced-ip-blocker')]);
    
    add_settings_field('advaipbl_lockdown_403_event_threshold', __('Lockdown Trigger: Max Errors', 'advanced-ip-blocker'), [$this, 'text_field_callback'], $page, 'advaipbl_403_settings_section', ['name' => 'lockdown_403_event_threshold', 'default' => 50, 'description' => __('Total 403 errors allowed across the entire site...', 'advanced-ip-blocker')]); 
    add_settings_field('advaipbl_lockdown_403_ip_threshold', __('Lockdown Trigger: Min Unique IPs', 'advanced-ip-blocker'), [$this, 'text_field_callback'], $page, 'advaipbl_403_settings_section', ['name' => 'lockdown_403_ip_threshold', 'default' => 5, 'description' => __('...originating from at least this many unique IPs...', 'advanced-ip-blocker')]);
    add_settings_field('advaipbl_lockdown_403_window', __('Lockdown Trigger: Time Window', 'advanced-ip-blocker'), [$this, 'text_field_callback'], $page, 'advaipbl_403_settings_section', ['name' => 'lockdown_403_window', 'default' => 10, 'description' => __('...within this many minutes.', 'advanced-ip-blocker')]);
    add_settings_field('advaipbl_lockdown_403_duration', __('Lockdown Duration (min)', 'advanced-ip-blocker'), [$this, 'text_field_callback'], $page, 'advaipbl_403_settings_section', ['name' => 'lockdown_403_duration', 'default' => 60, 'description' => __('How long the Lockdown Mode stays active.', 'advanced-ip-blocker')]);

    // Separator
    add_settings_field('advaipbl_403_separator', '', [$this, 'separator_callback'], $page, 'advaipbl_403_settings_section');

    add_settings_field('advaipbl_threshold_403', __('Single IP: Block Threshold', 'advanced-ip-blocker'), [$this, 'text_field_callback'], $page, 'advaipbl_403_settings_section', ['name' => 'threshold_403', 'default' => 5, 'description' => __('Block a specific IP if it generates this many 403 errors.', 'advanced-ip-blocker')]);
    add_settings_field('advaipbl_transient_expiration_403', __('403 Time Window (min)', 'advanced-ip-blocker'), [$this, 'text_field_callback'], $page, 'advaipbl_403_settings_section', ['name' => 'transient_expiration_403', 'default' => 30, 'description' => __('Time period in which the error count must be reached.', 'advanced-ip-blocker')]);
    add_settings_field('advaipbl_duration_403', __('403 Duration (min)', 'advanced-ip-blocker'), [$this, 'text_field_callback'], $page, 'advaipbl_403_settings_section', ['name' => 'duration_403', 'default' => 60, 'description' => __('How long the IP will be blocked.', 'advanced-ip-blocker')]);
    
    add_settings_section('advaipbl_rate_limiting_section', null, null, $page);
    add_settings_field('advaipbl_rate_limiting_enable', __('Enable Rate Limiting', 'advanced-ip-blocker'), [$this, 'switch_field_callback'], $page, 'advaipbl_rate_limiting_section', ['name' => 'rate_limiting_enable', 'label' => __('Temporarily block IPs that make too many requests.', 'advanced-ip-blocker')]);
    add_settings_field('advaipbl_rate_limiting_limit', __('Request Limit', 'advanced-ip-blocker'), [$this, 'text_field_callback'], $page, 'advaipbl_rate_limiting_section', ['name' => 'rate_limiting_limit', 'default' => 120, 'description' => __('Number of requests to allow within the time window.', 'advanced-ip-blocker')]);
    add_settings_field('advaipbl_rate_limiting_window', __('Time Window (seconds)', 'advanced-ip-blocker'), [$this, 'text_field_callback'], $page, 'advaipbl_rate_limiting_section', ['name' => 'rate_limiting_window', 'default' => 60, 'description' => __('The time period in which the request count is measured.', 'advanced-ip-blocker')]);	
    add_settings_field('advaipbl_duration_rate_limit', __('Block Duration (minutes)', 'advanced-ip-blocker'), [$this, 'text_field_callback'], $page, 'advaipbl_rate_limiting_section', ['name' => 'duration_rate_limit', 'default' => 5, 'description' => __('How long the IP will be blocked after reaching the limit.', 'advanced-ip-blocker')]);	
    
    add_settings_section('advaipbl_login_settings_section', null, null, $page);
    add_settings_field('advaipbl_threshold_login', __('Login Failure Threshold', 'advanced-ip-blocker'), [$this, 'text_field_callback'], $page, 'advaipbl_login_settings_section', ['name' => 'threshold_login', 'default' => 5, 'description' => __('Number of failed logins to trigger a block.', 'advanced-ip-blocker')]);
    add_settings_field('advaipbl_transient_expiration_login', __('Login Time Window (min)', 'advanced-ip-blocker'), [$this, 'text_field_callback'], $page, 'advaipbl_login_settings_section', ['name' => 'transient_expiration_login', 'default' => 60, 'description' => __('Time period in which the failure count must be reached.', 'advanced-ip-blocker')]);
    add_settings_field('advaipbl_duration_login', __('Login Duration (min)', 'advanced-ip-blocker'), [$this, 'text_field_callback'], $page, 'advaipbl_login_settings_section', ['name' => 'duration_login', 'default' => 120, 'description' => __('How long the IP will be blocked.', 'advanced-ip-blocker')]);   
   
    add_settings_section('advaipbl_advanced_login_section', null, null, $page);
    add_settings_field('advaipbl_auto_whitelist_admin', __('Auto-Whitelist Admins', 'advanced-ip-blocker'), [$this, 'switch_field_callback'], $page, 'advaipbl_advanced_login_section', ['name' => 'auto_whitelist_admin', 'label' => __('Automatically add administrator IPs to the whitelist on successful login.', 'advanced-ip-blocker'), 'description' => __('Ideal for admins who travel or have dynamic IP addresses.', 'advanced-ip-blocker')]);
	add_settings_field('advaipbl_disable_user_enumeration', __( 'REST API User Protection', 'advanced-ip-blocker' ), [$this, 'switch_field_callback'], $page, 'advaipbl_advanced_login_section', ['name'  => 'disable_user_enumeration', 'label' => __( 'Disable User Enumeration via REST API', 'advanced-ip-blocker' )]);
    add_settings_field('advaipbl_prevent_author_scanning', __( 'Author Scan Protection', 'advanced-ip-blocker' ), [$this, 'switch_field_callback'], $page, 'advaipbl_advanced_login_section', ['name'  => 'prevent_author_scanning', 'label' => __( 'Prevent user enumeration via author scans', 'advanced-ip-blocker' )]);
    add_settings_field(
        'advaipbl_prevent_login_hinting',
        __( 'Prevent Login Hinting', 'advanced-ip-blocker' ),
        [$this, 'switch_field_callback'],
        $page,
        'advaipbl_advanced_login_section',
        [
            'name'  => 'prevent_login_hinting',
            'label' => __( 'Prevent WordPress from revealing whether a username or email exists on login failure.', 'advanced-ip-blocker' ),
            'description' => __( 'Shows a generic error message for all login and "lost password" failures to prevent user enumeration.', 'advanced-ip-blocker' )
        ]
    );
	add_settings_field('advaipbl_restrict_login_page', __( 'Whitelist Login Access', 'advanced-ip-blocker' ), [ $this, 'restrict_login_page_callback' ], $page, 'advaipbl_advanced_login_section');
		
	add_settings_field('advaipbl_login_restrict_countries', __( 'Whitelist Login Countries', 'advanced-ip-blocker' ), [ $this, 'geoblock_countries_callback' ], $page, 'advaipbl_advanced_login_section', [
        'type' => 'login_restrict',
        'description' => __('Select one or more countries that are allowed to access wp-login.php. If empty, all countries are allowed.', 'advanced-ip-blocker')
    ]);
	
    add_settings_section('advaipbl_advanced_xmlrpc_section', null, null, $page);	
	add_settings_field('advaipbl_xmlrpc_protection_mode', __('XML-RPC Protection Mode', 'advanced-ip-blocker'), [$this, 'xmlrpc_protection_mode_callback'], $page, 'advaipbl_advanced_xmlrpc_section');
	add_settings_field('advaipbl_duration_xmlrpc_block', __('XML-RPC Block Duration (min)', 'advanced-ip-blocker'), [$this, 'text_field_callback'], $page, 'advaipbl_advanced_xmlrpc_section', ['name' => 'duration_xmlrpc_block', 'default' => 1440, 'description' => __('How long to block IPs that make suspicious XML-RPC requests. Set to 0 for a permanent block.', 'advanced-ip-blocker')]);
	
	    // --- Campos para el nuevo Endpoint Lockdown ---advaipbl_advanced_xmlrpc_protection_section
	add_settings_section('advaipbl_advanced_xmlrpc_protection_section', null, null, $page);	
    add_settings_field(
        'advaipbl_enable_xmlrpc_lockdown',
        __( 'XML-RPC Lockdown Mode (Beta)', 'advanced-ip-blocker' ),
        [$this, 'switch_field_callback'],
        $page,
        'advaipbl_advanced_xmlrpc_protection_section',
        [
            'name'  => 'enable_xmlrpc_lockdown',
            'label' => __( 'Enable automated protection against distributed XML-RPC attacks.', 'advanced-ip-blocker' ),
            'description' => sprintf(/* translators: $s: Blocked Endpoints tab link. */__( 'When a sustained attack is detected, this mode will temporarily challenge all non-whitelisted traffic to <code>xmlrpc.php</code> with a JavaScript verifier, stopping the attack without flooding your block list. Manage endpoints that are currently in "Lockdown Mode" in the <a href="%s">Blocked Endpoints</a> tab.', 'advanced-ip-blocker' ), admin_url('admin.php?page=advaipbl_settings_page&tab=ip_management&sub-tab=blocked_endpoints'))
        ]
    );
    add_settings_field(
        'advaipbl_xmlrpc_lockdown_threshold',
        __( 'Lockdown Threshold', 'advanced-ip-blocker' ),
        [$this, 'text_field_callback'],
        $page,
        'advaipbl_advanced_xmlrpc_protection_section',
        [
            'name'  => 'xmlrpc_lockdown_threshold',
            'default' => 10,
            'description' => __( 'Number of unique IP blocks on <code>xmlrpc.php</code> needed to trigger the lockdown.', 'advanced-ip-blocker' )
        ]
    );
    add_settings_field(
        'advaipbl_xmlrpc_lockdown_window',
        __( 'Lockdown Detection Window (min)', 'advanced-ip-blocker' ),
        [$this, 'text_field_callback'],
        $page,
        'advaipbl_advanced_xmlrpc_protection_section',
        [
            'name'  => 'xmlrpc_lockdown_window',
            'default' => 15,
            'description' => __( 'The time frame (in minutes) in which the threshold must be reached.', 'advanced-ip-blocker' )
        ]
    );
    add_settings_field(
        'advaipbl_xmlrpc_lockdown_duration',
        __( 'Lockdown Duration (min)', 'advanced-ip-blocker' ),
        [$this, 'text_field_callback'],
        $page,
        'advaipbl_advanced_xmlrpc_protection_section',
        [
            'name'  => 'xmlrpc_lockdown_duration',
            'default' => 60,
            'description' => __( 'How long the lockdown mode will remain active (in minutes).', 'advanced-ip-blocker' )
        ]
    );
	add_settings_section('advaipbl_login_lockdown_section', null, null, $page);
	add_settings_field(
            'advaipbl_enable_login_lockdown',
            __( 'Login Page Lockdown Mode (Beta)', 'advanced-ip-blocker' ),
            [$this, 'switch_field_callback'],
            $page,
            'advaipbl_login_lockdown_section',
            [
                'name'  => 'enable_login_lockdown',
                'label' => __( 'Enable automated protection against distributed brute-force attacks.', 'advanced-ip-blocker' ),
                'description' => sprintf(/* translators: $s: Blocked Endpoints tab link. */__( 'When a sustained brute-force attack is detected, this mode will temporarily challenge all non-whitelisted traffic to <code>wp-login.php</code> with a JavaScript verifier.Manage endpoints that are currently in "Lockdown Mode" in the <a href="%s">Blocked Endpoints</a> tab.', 'advanced-ip-blocker' ), admin_url('admin.php?page=advaipbl_settings_page&tab=ip_management&sub-tab=blocked_endpoints'))
        ]
    );
        add_settings_field(
            'advaipbl_login_lockdown_event_threshold',
            __( 'Lockdown Event Threshold', 'advanced-ip-blocker' ),
            [$this, 'text_field_callback'],
            $page,
            'advaipbl_login_lockdown_section',
            [
                'name'  => 'login_lockdown_event_threshold',
                'default' => 50,
                'description' => __( 'Total number of failed login attempts needed to trigger the lockdown.', 'advanced-ip-blocker' )
            ]
        );
        add_settings_field(
            'advaipbl_login_lockdown_ip_threshold',
            __( 'Lockdown Unique IP Threshold', 'advanced-ip-blocker' ),
            [$this, 'text_field_callback'],
            $page,
            'advaipbl_login_lockdown_section',
            [
                'name'  => 'login_lockdown_ip_threshold',
                'default' => 10,
                'description' => __( 'Minimum number of unique IPs that must contribute to the failed logins.', 'advanced-ip-blocker' )
            ]
        );
        add_settings_field(
            'advaipbl_login_lockdown_window',
            __( 'Lockdown Detection Window (min)', 'advanced-ip-blocker' ),
            [$this, 'text_field_callback'],
            $page,
            'advaipbl_login_lockdown_section',
            [
                'name'  => 'login_lockdown_window',
                'default' => 5,
                'description' => __( 'The time frame (in minutes) in which the thresholds must be reached.', 'advanced-ip-blocker' )
            ]
        );
        add_settings_field(
            'advaipbl_login_lockdown_duration',
            __( 'Lockdown Duration (min)', 'advanced-ip-blocker' ),
            [$this, 'text_field_callback'],
            $page,
            'advaipbl_login_lockdown_section',
            [
                'name'  => 'login_lockdown_duration',
                'default' => 60,
                'description' => __( 'How long the lockdown mode will remain active (in minutes).', 'advanced-ip-blocker' )
            ]
        );
    add_settings_section('advaipbl_recaptcha_section', null, null, $page);
    add_settings_field('advaipbl_recaptcha_enable', __('Enable reCAPTCHA', 'advanced-ip-blocker'), [$this, 'recaptcha_enable_callback'], $page, 'advaipbl_recaptcha_section', ['help_url' => 'https://advaipbl.com/setup-google-recaptcha-protection/']);
    add_settings_field('advaipbl_recaptcha_version', __('reCAPTCHA Version', 'advanced-ip-blocker'), [$this, 'recaptcha_version_callback'], $page, 'advaipbl_recaptcha_section');
    add_settings_field('advaipbl_recaptcha_site_key', __('Site Key', 'advanced-ip-blocker'), [$this, 'recaptcha_site_key_callback'], $page, 'advaipbl_recaptcha_section');
    add_settings_field('advaipbl_recaptcha_secret_key', __('Secret Key', 'advanced-ip-blocker'), [$this, 'recaptcha_secret_key_callback'], $page, 'advaipbl_recaptcha_section');
    add_settings_field('advaipbl_recaptcha_score_threshold', __('v3 Score Threshold', 'advanced-ip-blocker'), [$this, 'recaptcha_score_callback'], $page, 'advaipbl_recaptcha_section');
    
	// SECCIÓN DE 2FA
        add_settings_section(
            'advaipbl_2fa_settings_section',
            null, // El título ya está en el HTML de la pestaña
            null,
            $page
        );

        add_settings_field(
            'advaipbl_enable_2fa',
            __( 'Enable Two-Factor Authentication', 'advanced-ip-blocker' ),
            [$this, 'switch_field_callback'],
            $page,
            'advaipbl_2fa_settings_section',
            [
                'name' => 'enable_2fa',
                'label' => __( 'Enable the 2FA feature for all users on this site.', 'advanced-ip-blocker' ),
				'description' => sprintf(/* translators: $s: User profile URL */__('When enabled, users will see the 2FA setup section in their  <a href="%s">Profile</a>.', 'advanced-ip-blocker'), admin_url('profile.php'))
            ]
        );

        add_settings_field(
            'advaipbl_tfa_force_roles',
            __( 'Force 2FA for Roles', 'advanced-ip-blocker' ),
            [$this, 'tfa_force_roles_callback'],
            $page,
            'advaipbl_2fa_settings_section'
        );
	
	// --- HTACCESS FIREWALL SECTION (INTEGRATED) ---
        // Creamos una nueva sección que se mostrará en el Settings Page principal
        add_settings_section('advaipbl_htaccess_settings_section', null, null, $page);
        
        add_settings_field(
            'advaipbl_enable_htaccess_write', 
            __('Enable Htaccess Writer', 'advanced-ip-blocker'), 
            [$this, 'switch_field_callback'], 
            $page, 
            'advaipbl_htaccess_settings_section',
            [
                'name' => 'enable_htaccess_write', 
                'label' => __('Allow the plugin to modify the .htaccess file.', 'advanced-ip-blocker'),
                'description' => __('This is required for all server-level blocking features. The plugin creates a backup before every write operation.', 'advanced-ip-blocker'),
                'help_url' => 'https://advaipbl.com/high-performance-server-level-firewall-htaccess/'
			]
        );
        
		add_settings_field(
            'advaipbl_enable_htaccess_ip_blocking', 
            __('Sync Blocked IPs', 'advanced-ip-blocker'), 
            [$this, 'checkbox_field_callback'], 
            $page, 
            'advaipbl_htaccess_settings_section',
            [
                'name' => 'enable_htaccess_ip_blocking', 
                'label' => __('Automatically write "Manually Blocked" and "Permanent" IPs to the .htaccess file.', 'advanced-ip-blocker')
            ]
        );
		
		add_settings_field(
            'advaipbl_enable_htaccess_all_ips', 
            __('Include Temporary Blocks', 'advanced-ip-blocker'), 
            [$this, 'checkbox_field_callback'], 
            $page, 
            'advaipbl_htaccess_settings_section', 
            [
                'name' => 'enable_htaccess_all_ips', 
                'label' => __('Write ALL blocked IPs (including temporary ones like 404/Login) to .htaccess.', 'advanced-ip-blocker'),
                'description' => __('<strong>Advanced Performance:</strong> Offloads temporary blocks to the server. The file updates automatically when IPs expire. Requires "Sync Blocked IPs" to be enabled.', 'advanced-ip-blocker')
            ]
        );
		
        add_settings_field(
            'advaipbl_htaccess_protect_system_files', 
            __('Block System Files', 'advanced-ip-blocker'), 
            [$this, 'checkbox_field_callback'], 
            $page, 
            'advaipbl_htaccess_settings_section', 
            [
                'name' => 'htaccess_protect_system_files', 
                'label' => __('Block access to sensitive files (.git, .svn, .log, .sql, backups, etc.)', 'advanced-ip-blocker')
            ]
        );

        add_settings_field(
            'advaipbl_htaccess_protect_wp_config', 
            __('Block wp-config.php', 'advanced-ip-blocker'), 
            [$this, 'checkbox_field_callback'], 
            $page, 
            'advaipbl_htaccess_settings_section', 
            [
                'name' => 'htaccess_protect_wp_config', 
                'label' => __('Block direct access to wp-config.php and wp-config-sample.php', 'advanced-ip-blocker')
            ]
        );

        add_settings_field(
            'advaipbl_htaccess_protect_readme', 
            __('Block Readme Files', 'advanced-ip-blocker'), 
            [$this, 'checkbox_field_callback'], 
            $page, 
            'advaipbl_htaccess_settings_section', 
            [
                'name' => 'htaccess_protect_readme', 
                'label' => __('Block access to readme.html and license.txt (prevents version enumeration)', 'advanced-ip-blocker')
            ]
        );

        add_settings_section('advaipbl_cloudflare_section', null, null, $page);

        add_settings_field(
            'advaipbl_enable_cloudflare',
            __('Enable Cloudflare Integration', 'advanced-ip-blocker'),
            [$this, 'switch_field_callback'],
            $page,
            'advaipbl_cloudflare_section',
            [
                'name' => 'enable_cloudflare',
                'label' => __('Activate synchronization with Cloudflare Firewall.', 'advanced-ip-blocker'),
				'help_url' => 'https://advaipbl.com/cloud-edge-defense-setup/'
            ]
        );

        add_settings_field(
            'advaipbl_cf_api_token',
            __('Cloudflare API Token', 'advanced-ip-blocker'),
            [$this, 'text_field_callback'],
            $page,
            'advaipbl_cloudflare_section',
            [
                'name' => 'cf_api_token',
                'class' => 'regular-text',
                'description' => __('Create a token with <strong>Zone > Firewall > Edit</strong> permissions. <a href="https://dash.cloudflare.com/profile/api-tokens" target="_blank">Get Token</a>', 'advanced-ip-blocker'),
                // Añadimos un atributo data para el JS de validación
                'data_provider' => 'cloudflare' 
            ]
        );

        add_settings_field(
            'advaipbl_cf_zone_id',
            __('Zone ID', 'advanced-ip-blocker'),
            [$this, 'text_field_callback'],
            $page,
            'advaipbl_cloudflare_section',
            [
                'name' => 'cf_zone_id',
                'class' => 'regular-text',
                'description' => __('Found on the "Overview" page of your domain in Cloudflare (bottom right).', 'advanced-ip-blocker')
            ]
        );

        add_settings_field(
            'advaipbl_cf_sync_manual',
            __('Sync Manual Blocks', 'advanced-ip-blocker'),
            [$this, 'checkbox_field_callback'],
            $page,
            'advaipbl_cloudflare_section',
            [
                'name' => 'cf_sync_manual',
                'label' => __('Push "Manually Blocked" IPs to Cloudflare.', 'advanced-ip-blocker')
            ]
        );
        
        add_settings_field(
            'advaipbl_cf_sync_temporary',
            __('Sync Temporary Blocks', 'advanced-ip-blocker'),
            [$this, 'checkbox_field_callback'],
            $page,
            'advaipbl_cloudflare_section',
            [
                'name' => 'cf_sync_temporary',
                'label' => __('Push temporary blocks (WAF, Login attempts, etc.) to Cloudflare.', 'advanced-ip-blocker'),
                'description' => __('<strong>Recommended for High Security.</strong> Offload all bad traffic to the cloud.', 'advanced-ip-blocker')
            ]
        );
	
    add_settings_section('advaipbl_uninstall_section', null, null, $page);
    add_settings_field('advaipbl_delete_data_on_uninstall', __('Delete Data on Uninstall', 'advanced-ip-blocker'), [$this, 'switch_field_callback'], $page, 'advaipbl_uninstall_section', ['name' => 'delete_data_on_uninstall', 'label' => __('Check to delete all data from this plugin when it is deleted.', 'advanced-ip-blocker')]);
    
    add_settings_section('advaipbl_threat_scoring_section', null, null, $page);
    add_settings_field(
            'advaipbl_enable_threat_scoring', 
            __('Enable Threat Scoring System', 'advanced-ip-blocker'), 
            [$this, 'switch_field_callback'], 
            $page, 
            'advaipbl_threat_scoring_section', 
            [
                'name' => 'enable_threat_scoring',
                'label' => __('Activate the dynamic IP threat scoring system.', 'advanced-ip-blocker'),
                'description' => __('When enabled, the plugin will assign threat points to IPs for malicious actions instead of using simple thresholds. An IP will be blocked only when its total score reaches the configured threshold.', 'advanced-ip-blocker'),
                'help_url' => 'https://advaipbl.com/threat-scoring-system-guide/'
            ]
        );

    add_settings_field('advaipbl_threat_score_threshold', __('Blocking Threshold', 'advanced-ip-blocker'), [$this, 'text_field_callback'], $page, 'advaipbl_threat_scoring_section', [
        'name' => 'threat_score_threshold',
        'default' => 100,
        'description' => __('An IP will be blocked when its threat score reaches or exceeds this value.', 'advanced-ip-blocker')
    ]);

    add_settings_field('advaipbl_duration_threat_score', __('Block Duration (minutes)', 'advanced-ip-blocker'), [$this, 'text_field_callback'], $page, 'advaipbl_threat_scoring_section', [
        'name' => 'duration_threat_score',
        'default' => 360,
        'description' => __('How long an IP will be blocked after reaching the threshold. Set to 0 for a permanent block.', 'advanced-ip-blocker')
    ]);

    add_settings_field('advaipbl_threat_scores', __('Threat Event Points', 'advanced-ip-blocker'), [$this, 'threat_scores_callback'], $page, 'advaipbl_threat_scoring_section');
    
    add_settings_field('advaipbl_score_decay_points', __('Score Decay Rate', 'advanced-ip-blocker'), [$this, 'text_field_callback'], $page, 'advaipbl_threat_scoring_section', [
        'name' => 'score_decay_points',
        'default' => 1,
        'description' => __('Number of points to subtract from an inactive IP\'s score during each decay cycle.', 'advanced-ip-blocker')
    ]);

    add_settings_field('advaipbl_score_decay_frequency', __('Score Decay Frequency (Hours)', 'advanced-ip-blocker'), [$this, 'text_field_callback'], $page, 'advaipbl_threat_scoring_section', [
        'name' => 'score_decay_frequency',
        'default' => 1,
        'description' => __('How often (in hours) to run the decay process. The score of an IP will only decay if it has been inactive for at least this period.', 'advanced-ip-blocker')
    ]);
	
	add_settings_section('advaipbl_signature_engine_section', null, null, $page);

    add_settings_field(
            'advaipbl_enable_signature_engine', 
            __('Enable Signature Logging', 'advanced-ip-blocker'), 
            [$this, 'switch_field_callback'], 
            $page, 
            'advaipbl_signature_engine_section', 
            [
                'name' => 'enable_signature_engine',
                'label' => __('Activate the experimental request fingerprinting engine.', 'advanced-ip-blocker'),
                'description' => __('<strong>Warning:</strong> This is an advanced feature for data collection. Activating it will log details of incoming requests to a new database table. Use only if you are aware of the potential performance impact on high-traffic sites.', 'advanced-ip-blocker'),
                'help_url' => 'https://advaipbl.com/beyond-the-blocklist-introducing-the-intelligent-ip-trust-attack-signature-engines/'
            ]
        );

    add_settings_field('advaipbl_enable_signature_analysis', __('Enable Signature Analysis', 'advanced-ip-blocker'), [$this, 'switch_field_callback'], $page, 'advaipbl_signature_engine_section', [
        'name' => 'enable_signature_analysis',
        'label' => __('Activate automatic analysis of request signatures.', 'advanced-ip-blocker'),
        'description' => __('When enabled, a background process will analyze the collected logs to find patterns of a distributed attack.', 'advanced-ip-blocker')
    ]);

    add_settings_field('advaipbl_enable_signature_blocking', __('Enable Signature Blocking', 'advanced-ip-blocker'), [$this, 'switch_field_callback'], $page, 'advaipbl_signature_engine_section', [
        'name' => 'enable_signature_blocking',
        'label' => __('Activate blocking based on malicious signatures.', 'advanced-ip-blocker'),
        'description' => __('<strong>Enable this to activate protection.</strong> When a request matches a known malicious signature, the plugin will present a JavaScript challenge to filter out bots. <br><strong>Note:</strong> If you use a page caching plugin, you may need to exclude the <code>advaipbl_js_verified</code> cookie from being cached.', 'advanced-ip-blocker')
    ]);

    add_settings_field('advaipbl_signature_ip_threshold', __('Signature IP Threshold', 'advanced-ip-blocker'), [$this, 'text_field_callback'], $page, 'advaipbl_signature_engine_section', [
        'name' => 'signature_ip_threshold',
        'default' => 5,
        'description' => __('The minimum number of different IPs that must use the same attack signature to be flagged as malicious.', 'advanced-ip-blocker')
    ]);

    add_settings_field('advaipbl_signature_analysis_window', __('Analysis Window (Hours)', 'advanced-ip-blocker'), [$this, 'text_field_callback'], $page, 'advaipbl_signature_engine_section', [
        'name' => 'signature_analysis_window',
        'default' => 1,
        'description' => __('How far back (in hours) the analysis process should look for patterns.', 'advanced-ip-blocker')
    ]);

    add_settings_field('advaipbl_signature_rule_ttl', __('Signature Rule Lifetime (Hours)', 'advanced-ip-blocker'), [$this, 'text_field_callback'], $page, 'advaipbl_signature_engine_section', [
        'name' => 'signature_rule_ttl',
        'default' => 24,
        'description' => __('How long a malicious signature will remain active before it expires.', 'advanced-ip-blocker')
    ]);

    add_settings_field('advaipbl_signature_notification_frequency', __('Notification Frequency', 'advanced-ip-blocker'), [$this, 'signature_notification_frequency_callback'], $page, 'advaipbl_signature_engine_section', [
        'name' => 'signature_notification_frequency',
        'label' => __('How often to send alerts for detected signatures.', 'advanced-ip-blocker')
    ]);

    add_settings_field('advaipbl_signature_notification_recipient', __('Notification Recipient', 'advanced-ip-blocker'), [$this, 'signature_notification_recipient_callback'], $page, 'advaipbl_signature_engine_section', [
        'name' => 'signature_notification_recipient',
        'label' => __('Who should receive these specific alerts.', 'advanced-ip-blocker')
    ]);

    add_settings_field('advaipbl_signature_notification_custom_email', __('Custom Recipient Email', 'advanced-ip-blocker'), [$this, 'text_field_callback'], $page, 'advaipbl_signature_engine_section', [
        'name' => 'signature_notification_custom_email',
        'class' => 'regular-text',
        'description' => __('Required if "Custom Email" is selected above.', 'advanced-ip-blocker')
    ]);
	add_settings_section('advaipbl_trusted_signatures_section', __('Trusted Signatures (Whitelist)', 'advanced-ip-blocker'), [$this, 'trusted_signatures_section_callback'], $page);

    add_settings_field('advaipbl_trusted_signature_hashes', __('Trusted Signature Hashes', 'advanced-ip-blocker'), [$this, 'textarea_field_callback'], $page, 'advaipbl_trusted_signatures_section', [
        'name' => 'trusted_signature_hashes',
        'label' => __('Add known legitimate signature hashes here (one per line). Requests matching these exact fingerprints will always be allowed and never logged by the Signature Engine. Use this for services like Googlebot, Facebook Crawler, etc., to prevent false positives. Find hashes in the "Blocked Signatures" page by clicking "View Details".', 'advanced-ip-blocker')
    ]);

    // --- INTERNAL SECURITY & FORENSICS (v8.7.1) ---
    add_settings_section('advaipbl_internal_security_section', __('Internal Security & Forensics', 'advanced-ip-blocker'), null, $page);

    add_settings_field(
        'advaipbl_enable_audit_log',
        __('Enable Activity Audit Log', 'advanced-ip-blocker'),
        [$this, 'switch_field_callback'],
        $page,
        'advaipbl_internal_security_section',
        [
            'name' => 'enable_audit_log',
            'label' => __('Record critical administrative actions.', 'advanced-ip-blocker'),
            'description' => __('Logs plugin rule changes, setting updates, and other critical admin events to a separate audit table.', 'advanced-ip-blocker')
        ]
    );

    add_settings_field(
        'advaipbl_enable_fim',
        __('Enable File Integrity Monitor', 'advanced-ip-blocker'),
        [$this, 'switch_field_callback'],
        $page,
        'advaipbl_internal_security_section',
        [
            'name' => 'enable_fim',
            'label' => __('Monitor critical WordPress files for unauthorized changes.', 'advanced-ip-blocker'),
            'description' => __('Automatically scans core files (wp-config.php, .htaccess, index.php) daily for modifications.', 'advanced-ip-blocker')
        ]
    );

    add_settings_field(
        'advaipbl_fim_alert_email', 
        __('FIM Alert Email', 'advanced-ip-blocker'), 
        [$this, 'email_field_callback'], 
        $page, 
        'advaipbl_internal_security_section', 
        [
            'name' => 'fim_alert_email', 
            'label' => __('Where to send critical file change alerts (leave blank for admin email).', 'advanced-ip-blocker')
        ]
    );

    add_settings_field(
        'advaipbl_fim_manual_scan_button',
        __('Manual Scan', 'advanced-ip-blocker'),
        [$this, 'fim_manual_scan_button_callback'], // Use a new callback
        $page,
        'advaipbl_internal_security_section'
    );
}

    public function sanitize_settings($input) {
        // Empezamos con las opciones antiguas como base.
        $new_input = get_option(ADVAIPBL_Main::OPTION_SETTINGS, []);
        
        $defaults = $this->plugin->get_default_settings();
        
        $numeric_fields = [
            'duration_geoblock', 'duration_waf', 'duration_rate_limit', 'rate_limiting_limit', 'rate_limiting_window', 
            'duration_xmlrpc_block', 'duration_asn', 'log_retention_days', 'threshold_404', 'duration_404', 'transient_expiration_404',
            'threshold_403', 'duration_403', 'transient_expiration_403', 'threshold_login',
            'duration_login', 'transient_expiration_login', 'duration_honeypot', 'duration_user_agent',
            'threat_score_threshold', 'duration_threat_score', 'score_404', 'score_403', 'score_login',
            'score_user_agent', 'score_waf', 'score_honeypot', 'score_asn', 'score_impersonation',
            'score_decay_points', 'score_decay_frequency',
            'signature_ip_threshold', 'signature_analysis_window', 'signature_rule_ttl', 
            'xmlrpc_lockdown_threshold', 'xmlrpc_lockdown_window', 'xmlrpc_lockdown_duration',
            'login_lockdown_event_threshold', 'login_lockdown_ip_threshold', 'login_lockdown_window', 'login_lockdown_duration',
            'lockdown_404_event_threshold', 'lockdown_404_ip_threshold', 'lockdown_404_window', 'lockdown_404_duration',
            'lockdown_403_event_threshold', 'lockdown_403_ip_threshold', 'lockdown_403_window', 'lockdown_403_duration',
            'geo_challenge_cookie_duration', 'abuseipdb_threshold', 'duration_abuseipdb', 'duration_aib_network'
        ];
        foreach ($numeric_fields as $field) {
            // Si el campo existe en el input, lo actualizamos. Si no, el valor antiguo se mantiene.
            if (isset($input[$field])) {
                $new_input[$field] = absint($input[$field]);
            }
        }
        
        $checkbox_fields = [
            'prevent_author_scanning', 'disable_user_enumeration', 'restrict_login_page',
            'enable_logging', 'delete_data_on_uninstall', 'enable_email_notifications',			
            'enable_waf', 'enable_geoblocking', 'enable_honeypot_blocking',
            'enable_user_agent_blocking', 'rate_limiting_enable', 'show_admin_bar_menu',
            'enable_spamhaus_asn', 'enable_manual_asn', 
            'enable_push_notifications', 'push_critical_only', 'auto_whitelist_admin',
            'allow_telemetry',
            'enable_threat_scoring',
            'enable_signature_engine',
            'enable_signature_blocking',
            'enable_signature_analysis',
            'enable_2fa',
            'recaptcha_enable',
            'prevent_login_hinting',
            'enable_xmlrpc_lockdown',
            'enable_login_lockdown',
            'enable_404_lockdown',
            'enable_403_lockdown',
            'enable_geo_challenge',
			'enable_bot_verification',
			'enable_community_blocking',
			'enable_abuseipdb',
			'enable_community_network',
			'enable_htaccess_write',
			'enable_cloudflare', 'cf_sync_manual', 'cf_sync_temporary',
			'enable_htaccess_ip_blocking',
			'enable_htaccess_all_ips',
            'htaccess_protect_system_files',
            'htaccess_protect_wp_config',
            'htaccess_protect_readme',
            'htaccess_protect_readme',
            'enable_scheduled_scans',
            'enable_audit_log',
            'enable_fim',
            'scan_check_ssl', 'scan_check_updates', 'scan_check_php', 'scan_check_wp', 'scan_check_debug',			
        ];
        
        foreach ($checkbox_fields as $field) {
            // Para checkboxes, si existen en el input, es '1'. Si no, es '0'.
            $new_input[$field] = (isset($input[$field]) && $input[$field] === '1') ? '1' : '0';
        }
      
        // Campos de array y texto, que siempre deberían estar presentes en el formulario.
        if (isset($input['tfa_force_roles'])) {
            $new_input['tfa_force_roles'] = is_array($input['tfa_force_roles']) ? array_map('sanitize_key', $input['tfa_force_roles']) : [];
        } else {
            $new_input['tfa_force_roles'] = []; // Si no se envía nada, es un array vacío.
        }

        $text_fields = [
            'notification_frequency', 'custom_block_message', 'excluded_error_urls', 'waf_excluded_urls',
            'push_webhook_urls', 'push_mentions', 'trusted_signature_hashes', 'notification_email',
            'signature_notification_frequency', 'signature_notification_recipient', 'signature_notification_custom_email',
            'api_key_ipapicom', 'api_key_ipstackcom', 'api_key_ipinfocom', 'api_key_ip_apicom', 'maxmind_license_key',
            'geolocation_provider', 'log_timezone', 'recaptcha_version', 'recaptcha_site_key', 'recaptcha_secret_key',
            'xmlrpc_protection_mode', 'geolocation_method', 'trusted_proxies', 'abuseipdb_api_key', 'abuseipdb_action',
			'cf_api_token', 'cf_zone_id', 'community_blocking_action', 'scan_frequency', 'scan_notification_email',
            'fim_alert_email', 'api_token_v3'
        ];

        foreach ($text_fields as $field) {
            if (isset($input[$field])) {
    if ($field === 'custom_block_message') {
        // Permitimos h1 y br para el mensaje de bloqueo personalizado
        $allowed_html = [
            'h1' => [],
            'br' => [],
        ];
        $new_input[$field] = wp_kses($input[$field], $allowed_html);
    } elseif (strpos($field, 'email') !== false) {
         $new_input[$field] = sanitize_email($input[$field]);
    } elseif (strpos($field, 'urls') !== false || strpos($field, 'proxies') !== false || strpos($field, 'hashes') !== false || strpos($field, 'mentions') !== false) { // Quitamos 'message' de aquí
         $new_input[$field] = sanitize_textarea_field($input[$field]);
    } else {
         $new_input[$field] = sanitize_text_field($input[$field]);
    }
}
        }
        
        // V3 API Token Validation (only if changed manually)
        if (isset($new_input['api_token_v3']) && $new_input['api_token_v3'] !== ($this->plugin->options['api_token_v3'] ?? '')) {
            if (!empty($new_input['api_token_v3'])) {
                $response = wp_remote_get('https://advaipbl.com/wp-json/aib-api/v3/verify-token', [
                    'headers' => [
                        'Authorization' => 'Bearer ' . $new_input['api_token_v3'],
                        'Accept'        => 'application/json'
                    ],
                    'timeout' => 15
                ]);
                
                if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
                    add_settings_error('advaipbl_settings_messages', 'invalid_v3_token', __('Invalid AIB Cloud Network Token. Connection failed.', 'advanced-ip-blocker'), 'error');
                    $new_input['api_token_v3'] = $this->plugin->options['api_token_v3'] ?? ''; // Revert to previous or empty
                }
            }
        }

        if (isset($input['geoblock_countries'])) {
            $countries = (array) $input['geoblock_countries'];
            $all_country_codes = array_keys($this->plugin->get_country_list());
            $new_input['geoblock_countries'] = array_values(array_intersect($countries, $all_country_codes));
        } else {
            $new_input['geoblock_countries'] = [];
        }
		
		if (isset($input['geo_challenge_countries'])) {
			$countries = (array) $input['geo_challenge_countries'];
			$all_country_codes = array_keys($this->plugin->get_country_list());
			$new_input['geo_challenge_countries'] = array_values(array_intersect($countries, $all_country_codes));
		} else {
			$new_input['geo_challenge_countries'] = [];
		}

        if (isset($input['login_restrict_countries'])) {
            $countries = (array) $input['login_restrict_countries'];
            $all_country_codes = array_keys($this->plugin->get_country_list());
            $new_input['login_restrict_countries'] = array_values(array_intersect($countries, $all_country_codes));
        } else {
            $new_input['login_restrict_countries'] = [];
        }
        
        if (isset($input['recaptcha_score_threshold'])) {
            $new_input['recaptcha_score_threshold'] = $this->plugin->sanitize_score_threshold($input['recaptcha_score_threshold']);
        }
        
        // Purge page caches when security settings are updated
        $this->plugin->purge_all_page_caches();
        
        return $new_input;
    }

    public function text_field_callback($args){
        $value = $this->plugin->options[$args['name']] ?? $args['default'] ?? '';
        $class = $args['class'] ?? '';
        $data_attr = ! empty( $args['data_provider'] ) ? 'data-provider="' . esc_attr( $args['data_provider'] ) . '"' : '';

        if ( (isset($args['name']) && substr($args['name'], -8) === '_api_key') || !empty($args['data_provider']) ) {            			
            printf(
                '<input type="password" id="%1$s" name="%2$s" value="%3$s" class="regular-text %4$s" autocomplete="off" %5$s />
                 <button type="button" class="button button-secondary advaipbl-verify-api-key" data-provider="%6$s" data-key-id="%1$s">%7$s</button>
                 <span class="advaipbl-api-status"></span>',
                esc_attr( $args['name'] ),
                esc_attr( 'advaipbl_settings[' . $args['name'] . ']' ),
                esc_attr( $value ),
                esc_attr( $class ),
				// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
                $data_attr,
                esc_attr( $args['data_provider'] ),
                esc_html__( 'Verify', 'advanced-ip-blocker' )
            );
        } else {
            $is_numeric = false;
            if (isset($args['name']) && is_string($args['name'])) {
                $numeric_keywords = ['duration', 'threshold', 'retention', 'score', 'points', 'frequency', 'limit', 'window', 'expiration', 'ttl'];
                foreach ($numeric_keywords as $keyword) {
                    if (strpos($args['name'], $keyword) !== false) {
                        $is_numeric = true;
                        break;
                    }
                }
            }
            $type = $is_numeric ? 'number' : 'text';
            $min_attr = ( 'number' === $type ) ? 'min="0"' : '';            			
            
            printf(
                '<input type="%1$s" id="%2$s" name="%3$s" value="%4$s" %5$s class="regular-text %6$s" />',
                esc_attr($type),
                esc_attr($args['name']),
                esc_attr('advaipbl_settings[' . $args['name'] . ']'),
                esc_attr($value),
				// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
                $min_attr,
                esc_attr($class)
            );
        }

        // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
        echo $this->get_help_link_html($args);

        if ( isset($args['description']) ) {
            echo '<p class="description">' . wp_kses_post($args['description']) . '</p>';
        }
    }

        public function checkbox_field_callback($args){
        $checked = checked( '1', $this->plugin->options[$args['name']] ?? '0', false );
        $id_attr = isset($args['id']) ? 'id="' . esc_attr($args['id']) . '"' : '';

        // Generamos el HTML del checkbox y su label
        $html = sprintf(
            '<label><input type="checkbox" name="%s" value="1" %s %s/> %s</label>',
            esc_attr( 'advaipbl_settings[' . $args['name'] . ']' ),
            $checked,
            $id_attr,
            esc_html( $args['label'] )
        );
        
        // Añadimos el icono de ayuda al final del label
        $html .= $this->get_help_link_html($args); 
        
        // Imprimimos una sola vez
        // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
        echo $html;
        
        // Imprimimos la descripción si existe
        if ( ! empty( $args['description'] ) ) {
            echo '<p class="description">' . wp_kses_post( $args['description'] ) . '</p>';
        }
    }
	
	    /**
     * Muestra un campo de tipo interruptor (toggle/switch) para los ajustes.
     * Utiliza la estructura HTML necesaria para ser estilizado con CSS.
     */
    public function switch_field_callback($args){
        $default = $args['default'] ?? '0';
        $value = $this->plugin->options[$args['name']] ?? $default;
        $id_attr = isset($args['id']) ? 'id="' . esc_attr($args['id']) . '"' : 'advaipbl_switch_' . esc_attr($args['name']);
        
        $html = sprintf(
            '<label for="%s" class="advaipbl-switch">
                <input type="checkbox" name="%s" id="%s" value="1" %s />
                <span class="advaipbl-slider"></span>
            </label>',
            esc_attr( $id_attr ),
            esc_attr( 'advaipbl_settings[' . $args['name'] . ']' ),
            esc_attr( $id_attr ),
            checked( '1', $value, false )
        );
        
        // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
        echo $html;

        if ( ! empty( $args['description'] ) ) {
            echo '<p class="description" style="display: inline-block; margin-left: 10px; vertical-align: middle;">' . wp_kses_post( $args['description'] ) . '</p>';
        } elseif ( ! empty( $args['label'] ) ) {
            echo '<label for="' . esc_attr($id_attr) . '" style="display: inline-block; margin-left: 10px; vertical-align: middle;">' . esc_html($args['label']) . '</label>';
        }
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		 echo $this->get_help_link_html($args);
    }
	
        public function textarea_field_callback($args){
        $value = $this->plugin->options[$args['name']] ?? '';
        $rows = $args['rows'] ?? 5;
        $class = $args['class'] ?? 'large-text';
        
        // 1. Imprimir Textarea
        printf(
            '<textarea name="%1$s" rows="%2$d" class="%4$s">%3$s</textarea>',
            esc_attr( 'advaipbl_settings[' . $args['name'] . ']' ),
            esc_attr( $rows ),
            esc_textarea( $value ),
            esc_attr( $class )
        );

        // 2. Imprimir Icono de Ayuda (si hay URL)
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
        echo $this->get_help_link_html($args);

        // 3. Imprimir Descripción (o Label si no hay descripción explícita en este contexto)
        if ( isset($args['description']) ) {
            echo '<p class="description">' . wp_kses_post($args['description']) . '</p>';
        } elseif (isset($args['label'])) {
             echo '<p class="description">' . esc_html($args['label']) . '</p>';
        }
    }
	
    public function email_field_callback($args){
        $value = $this->plugin->options[$args['name']] ?? '';
        
        printf(
            '<input type="email" name="%1$s" value="%2$s" class="regular-text" placeholder="%3$s"/>',
            esc_attr( 'advaipbl_settings[' . $args['name'] . ']' ),
            esc_attr( $value ),
            esc_attr( get_option('admin_email') )
        );
        
        if ( isset($args['label']) ) {
            printf(
                '<p class="description">%s</p>',
                esc_html($args['label'])
            );
        }
    }
    public function timezone_select_callback() { $name_attr = 'advaipbl_settings[log_timezone]'; $current_timezone = $this->plugin->options['log_timezone'] ?? wp_timezone_string(); echo '<select id="log_timezone" name="' . esc_attr($name_attr) . '">'; echo wp_timezone_choice($current_timezone, get_user_locale()); echo '</select>'; echo '<p class="description">' . esc_html__('Select the timezone to display in the logs.', 'advanced-ip-blocker') . '</p>'; }
    public function notification_frequency_callback() {
        $value = $this->plugin->options['notification_frequency'] ?? 'disabled';
        $frequencies = [
            'disabled' => __('Disabled', 'advanced-ip-blocker'),
            'instant' => __('Instant', 'advanced-ip-blocker'),
            'daily' => __('Daily Summary', 'advanced-ip-blocker'),
            'weekly' => __('Weekly Summary', 'advanced-ip-blocker')
        ];
        
        echo '<select name="' . esc_attr( 'advaipbl_settings[notification_frequency]' ) . '">';
        foreach ( $frequencies as $key => $label ) {
            printf(
                '<option value="%1$s" %2$s>%3$s</option>',
                esc_attr( $key ),
                selected( $value, $key, false ),
                esc_html( $label )
            );
        }
        echo '</select>';
        
        echo '<p class="description">' . esc_html__('Choose how often you want to receive alert emails.', 'advanced-ip-blocker') . '</p>';
    }

    public function signature_notification_frequency_callback() {
        $value = $this->plugin->options['signature_notification_frequency'] ?? 'instant';
        $frequencies = [
            'instant' => __('Instant (Batch per hour)', 'advanced-ip-blocker'),
            'daily' => __('Daily Digest', 'advanced-ip-blocker'),
            'weekly' => __('Weekly Digest', 'advanced-ip-blocker'),
            'disabled' => __('Disabled', 'advanced-ip-blocker')
        ];
        
        echo '<select name="' . esc_attr( 'advaipbl_settings[signature_notification_frequency]' ) . '">';
        foreach ( $frequencies as $key => $label ) {
            printf(
                '<option value="%1$s" %2$s>%3$s</option>',
                esc_attr( $key ),
                selected( $value, $key, false ),
                esc_html( $label )
            );
        }
        echo '</select>';
        echo '<p class="description">' . esc_html__('Instant mode sends one email per detection cycle (hourly). Digests accumulate signatures.', 'advanced-ip-blocker') . '</p>';
    }

    public function signature_notification_recipient_callback() {
        $value = $this->plugin->options['signature_notification_recipient'] ?? 'default';
        $recipients = [
            'default' => __('Default (Use Plugin Recipient)', 'advanced-ip-blocker'),
            'admin' => __('Administrator Email', 'advanced-ip-blocker'),
            'custom' => __('Custom Email', 'advanced-ip-blocker')
        ];
        
        echo '<select name="' . esc_attr( 'advaipbl_settings[signature_notification_recipient]' ) . '">';
        foreach ( $recipients as $key => $label ) {
            printf(
                '<option value="%1$s" %2$s>%3$s</option>',
                esc_attr( $key ),
                selected( $value, $key, false ),
                esc_html( $label )
            );
        }
        echo '</select>';
    }

    public function scan_frequency_callback() {
        $value = $this->plugin->options['scan_frequency'] ?? 'weekly';
        $frequencies = [
            'daily' => __('Daily', 'advanced-ip-blocker'),
            'weekly' => __('Weekly', 'advanced-ip-blocker')
        ];
        
        echo '<select name="' . esc_attr( 'advaipbl_settings[scan_frequency]' ) . '">';
        foreach ( $frequencies as $key => $label ) {
            printf(
                '<option value="%1$s" %2$s>%3$s</option>',
                esc_attr( $key ),
                selected( $value, $key, false ),
                esc_html( $label )
            );
        }
        echo '</select>';
        echo '<p class="description">' . esc_html__('How often to run the automated security audit.', 'advanced-ip-blocker') . '</p>';
    }

    public function send_test_scan_button_callback() {
        $nonce_url = wp_nonce_url(
            admin_url('admin-post.php?action=advaipbl_run_manual_scan'),
            'advaipbl_run_manual_scan_nonce'
        );
        ?>
        <a href="<?php echo esc_url($nonce_url); ?>" class="button">
            <?php esc_html_e('Run Scan & Email Now', 'advanced-ip-blocker'); ?>
        </a>
        <p class="description">
            <?php esc_html_e('Triggers the scan immediately and sends the report to the configured email.', 'advanced-ip-blocker'); ?>
        </p>
        <?php
    }
	
	 /**
     * Muestra la descripción para la sección de Threat Scoring.
     */
       public function threat_scoring_section_callback() {
        // La descripción ahora está en el HTML, esta función puede estar vacía.
        // Opcionalmente, podemos dejar el <p> aquí, pero es más limpio en el HTML.
    }

    /**
     * Muestra la tabla de campos numéricos para configurar los puntos de cada evento de amenaza.
     */
    public function threat_scores_callback() {
        $events = [
            'score_404'        => ['label' => __('404 Error', 'advanced-ip-blocker'), 'default' => 5],
            'score_403'        => ['label' => __('403 Error', 'advanced-ip-blocker'), 'default' => 10],
            'score_login'      => ['label' => __('Failed Login', 'advanced-ip-blocker'), 'default' => 15],
            'score_user_agent' => ['label' => __('Blocked User-Agent', 'advanced-ip-blocker'), 'default' => 60],
            'score_waf'        => ['label' => __('WAF Rule Triggered', 'advanced-ip-blocker'), 'default' => 60],
			'score_impersonation' => ['label' => __('Bot Impersonation', 'advanced-ip-blocker'), 'default' => 75],
            'score_honeypot'   => ['label' => __('Honeypot Accessed', 'advanced-ip-blocker'), 'default' => 100],
            'score_asn'        => ['label' => __('Blocked ASN (Spamhaus)', 'advanced-ip-blocker'), 'default' => 100],
        ];
        ?>
        <div class="advaipbl-threat-scores-grid">
            <?php foreach ($events as $name => $details) : ?>
                <?php $value = $this->plugin->options[$name] ?? $details['default']; ?>
                <div class="advaipbl-threat-score-item">
                    <label for="<?php echo esc_attr($name); ?>"><?php echo esc_html($details['label']); ?></label>
                    <input type="number" id="<?php echo esc_attr($name); ?>" name="advaipbl_settings[<?php echo esc_attr($name); ?>]" value="<?php echo esc_attr($value); ?>" class="small-text" min="0">
                </div>
            <?php endforeach; ?>
        </div>
        <style>
            .advaipbl-threat-scores-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 15px; }
            .advaipbl-threat-score-item { display: flex; align-items: center; justify-content: space-between; }
        </style>
        <p class="description"><?php esc_html_e('Assign the number of threat points for each event. An event with 100 or more points will trigger an instant block, regardless of the threshold.', 'advanced-ip-blocker'); ?></p>
        <?php
    }
	
    public function geolocation_provider_callback() {
    $value = $this->plugin->options['geolocation_provider'] ?? 'ip-api.com';
    $providers = [
        'ip-api.com'      => __('ip-api.com (Default, no key for HTTP)', 'advanced-ip-blocker'),
        'geoiplookup.net' => __('geoiplookup.net (Free, no key)', 'advanced-ip-blocker'),
        'ipinfo.io'       => __('ipinfo.io (API Key recommended)', 'advanced-ip-blocker'),
        'ipapi.com'       => __('ipapi.com (API Key required)', 'advanced-ip-blocker'),
        'ipstack.com'     => __('ipstack.com (API Key required)', 'advanced-ip-blocker')
    ];
    
    // Añadimos un id único al select
    printf( '<select id="advaipbl_geolocation_provider_select" name="%s">', esc_attr( 'advaipbl_settings[geolocation_provider]' ) );
    foreach ( $providers as $key => $label ) {
        printf(
            '<option value="%s" %s>%s</option>',
            esc_attr( $key ),
            selected( $value, $key, false ),
            esc_html( $label )
        );
    }
    echo '</select>';
}
/**
     * Renders the checkbox for the Whitelist Login Access feature, including security checks.
     */
    public function restrict_login_page_callback() {
        $args = [
            'name'  => 'restrict_login_page',
            'label' => __( 'Restrict access to wp-login.php to whitelisted IPs only', 'advanced-ip-blocker' )
        ];

        $client_ip = $this->plugin->get_client_ip();
        $is_whitelisted = $this->plugin->is_whitelisted( $client_ip );

        // Llama al callback del checkbox normal
        $this->checkbox_field_callback($args);

        // Añadimos la advertencia de seguridad
        echo '<p class="description" style="color:#d63638; font-weight:bold;">' . esc_html__( 'WARNING: This is a highly restrictive feature. Only enable it if you have a static IP address and public user registration is disabled on your site.', 'advanced-ip-blocker' ) . '</p>';

        // Si la IP del admin no está en la whitelist, mostramos un aviso y un botón para añadirla
        if ( ! $is_whitelisted ) {
            echo '<div class="notice notice-error inline" style="margin-top:10px;"><p>';
            /* translators: %s: The admin's current IP address. */
            echo '<strong>' . sprintf( esc_html__( 'Your current IP address (%s) is NOT whitelisted.', 'advanced-ip-blocker' ), esc_html( $client_ip ) ) . '</strong> ' . esc_html__( 'You MUST add it to the whitelist before enabling this feature, or you will be locked out.', 'advanced-ip-blocker' );            echo '<button class="button button-secondary advaipbl-add-whitelist-ajax" style="margin-left: 10px;" data-ip="' . esc_attr( $client_ip ) . '" data-detail="' . esc_attr__( 'Admin IP (self-added for login restriction)', 'advanced-ip-blocker' ) . '">' . esc_html__( 'Whitelist My IP Now', 'advanced-ip-blocker' ) . '</button>';
            echo '</p></div>';
        }
    }

    /**
     * Callback para mostrar el estado de la conexión con la API V3.
     */
    public function api_connection_status_callback() {
        $token = $this->plugin->options['api_token_v3'] ?? '';
        
        if (empty($token)) {
            echo '<span class="dashicons dashicons-dismiss" style="color: #d63638;"></span> <strong style="color: #d63638;">' . esc_html__('Not Connected', 'advanced-ip-blocker') . '</strong>';
            echo '<p class="description">' . esc_html__('Get a Free API Key below to connect your site to the AIB Cloud Network.', 'advanced-ip-blocker') . '</p>';
        } else {
            echo '<div id="advaipbl-api-status-container">';
            echo '<span class="dashicons dashicons-yes-alt" style="color: #00a32a;"></span> <strong style="color: #00a32a;">' . esc_html__('Connected', 'advanced-ip-blocker') . '</strong>';
            
            // Si tuviéramos el tipo de plan guardado, lo mostraríamos aquí. Por ahora, asumimos conectado.
            echo ' <span class="advaipbl-badge advaipbl-badge-free" style="margin-left:5px;">' . esc_html__('AIB Cloud Network', 'advanced-ip-blocker') . '</span>';
            
            echo '<p class="description" style="margin-top:5px;">';
            echo '<button type="button" class="button button-secondary button-small" id="advaipbl-verify-api-token">' . esc_html__('Verify Connection', 'advanced-ip-blocker') . '</button>';
            echo '<span id="advaipbl-api-verification-result" style="margin-left: 8px;"></span>';
            echo '</p>';
            echo '</div>';
        }
    }

    /**
     * Callback específico para el campo del Token API con ofuscación.
     */
    public function api_token_field_callback($args) {
        $name = $args['name'];
        $value = isset($this->plugin->options[$name]) ? $this->plugin->options[$name] : '';
        
        // Ofuscar si existe
        $display_val = $value;
        if (!empty($value) && strlen($value) > 8) {
            $display_val = substr($value, 0, 4) . str_repeat('•', 24) . substr($value, -4);
        }

        echo '<div style="display: flex; gap: 10px; position: relative; align-items: center;">';
        
        echo '<div style="display: flex; gap: 10px; max-width: 400px; position: relative; align-items: center;">';
        
        // Campo visible al usuario (puede estar ofuscado si ya hay valor)
        echo '<input type="text" id="advaipbl_' . esc_attr($name) . '_display" class="regular-text" style="font-family: monospace;" ';
        if (!empty($value)) {
            echo 'value="' . esc_attr($display_val) . '" disabled';
            echo '>';
            // Campo oculto real que se enviará en el formulario POST sólo si no se edita
            echo '<input type="hidden" name="' . esc_attr(ADVAIPBL_Main::OPTION_SETTINGS) . '[' . esc_attr($name) . ']" id="advaipbl_' . esc_attr($name) . '" value="' . esc_attr($value) . '">';
            // Botón para editar
            echo '<button type="button" class="button" id="advaipbl-edit-api-token" title="' . esc_attr__('Edit API Key', 'advanced-ip-blocker') . '"><span class="dashicons dashicons-edit" style="margin-top: 2px;"></span></button>';
        } else {
             // Si no hay valor, lo mostramos normal como input type="text" pero que envía
            echo 'name="' . esc_attr(ADVAIPBL_Main::OPTION_SETTINGS) . '[' . esc_attr($name) . ']" id="advaipbl_' . esc_attr($name) . '" value="" placeholder="AIB_xxxxxxxxxxxxxxxxxxxxxxxxxx">';
             // Botón mágico para generar clave
            echo '<button type="button" class="button button-primary" id="advaipbl-get-api-token" title="' . esc_attr__('Get a Free VIP Key instantly', 'advanced-ip-blocker') . '">' . esc_html__('Get Free Key', 'advanced-ip-blocker') . '</button>';
            echo '<span class="spinner" id="advaipbl-api-token-spinner" style="float:none; margin:0;"></span>';
        }

        echo '</div>';
        
        if (isset($args['description']) && empty($value)) {
            echo '<p class="description" style="margin-top:5px;">' . wp_kses_post($args['description']) . '</p>';
        } else if (!empty($value)) {
            echo '<p class="description" style="margin-top:5px;">' . esc_html__('Your API key is hidden for security.', 'advanced-ip-blocker') . '</p>';
        }

        // Script para manejar la edición y la validación
        ?>
        <script>
        jQuery(document).ready(function($) {
            $('#advaipbl-edit-api-token').on('click', function(e) {
                e.preventDefault();
                var $display = $('#advaipbl_<?php echo esc_js($name); ?>_display');
                var $hidden = $('#advaipbl_<?php echo esc_js($name); ?>');
                
                // Convert display to a real input field connected to POST
                $display.prop('disabled', false)
                        .val('')
                        .attr('name', '<?php echo esc_js(ADVAIPBL_Main::OPTION_SETTINGS); ?>[<?php echo esc_js($name); ?>]')
                        .focus();
                
                // Remove hidden field and button
                $hidden.remove();
                $(this).remove();
            });

            // Validación simple del lado del cliente antes de enviar
            $('form').on('submit', function() {
                var apiTokenInput = $('input[name="<?php echo esc_js(ADVAIPBL_Main::OPTION_SETTINGS); ?>[<?php echo esc_js($name); ?>]"]');
                if (apiTokenInput.length && !apiTokenInput.prop('disabled')) {
                    var val = apiTokenInput.val().trim();
                    if (val !== '' && !val.startsWith('AIB_')) {
                        alert('<?php echo esc_js(__('Invalid API Key format. It should start with AIB_.', 'advanced-ip-blocker')); ?>');
                        apiTokenInput.focus();
                        return false;
                    }
                }
                return true;
            });
        });
        </script>
        <?php
    }
	/**
 * Muestra el campo <select> para el modo de protección XML-RPC.
 */
public function xmlrpc_protection_mode_callback() {
    $current_mode = $this->plugin->options['xmlrpc_protection_mode'] ?? 'smart'; // 'smart' es el nuevo valor por defecto

    $modes = [
        'enabled'  => __('Enabled (Not Recommended)', 'advanced-ip-blocker'),
        'smart'    => __('Smart Protection (Recommended)', 'advanced-ip-blocker'),
        'disabled' => __('Completely Disabled', 'advanced-ip-blocker'),
    ];
    ?>
    <select name="advaipbl_settings[xmlrpc_protection_mode]" id="advaipbl_xmlrpc_protection_mode">
        <?php foreach ($modes as $key => $label) : ?>
            <option value="<?php echo esc_attr($key); ?>" <?php selected($current_mode, $key); ?>>
                <?php echo esc_html($label); ?>
            </option>
        <?php endforeach; ?>
    </select>
    <p class="description">
        <?php esc_html_e('Choose how to handle requests to `xmlrpc.php`:', 'advanced-ip-blocker'); ?><br>
        - <strong><?php esc_html_e('Smart Protection:', 'advanced-ip-blocker'); ?></strong> <?php esc_html_e('Blocks all requests except those from trusted services like Jetpack and the WordPress mobile app.', 'advanced-ip-blocker'); ?><br>
        - <strong><?php esc_html_e('Completely Disabled:', 'advanced-ip-blocker'); ?></strong> <?php esc_html_e('The most secure option. Blocks all XML-RPC traffic, but will break Jetpack and mobile apps.', 'advanced-ip-blocker'); ?>
    </p>
    <?php
}
/**
     * Muestra la descripción para la sección de Geoblocking.
     */
    public function geoblocking_section_callback() {
        echo '<p>' . esc_html__( 'Block access from entire countries. This feature requires a working Geolocation Provider to be configured above.', 'advanced-ip-blocker' ) . '</p>';
        echo '<p><strong>' . esc_html__( 'Warning:', 'advanced-ip-blocker' ) . '</strong> ' . esc_html__( 'Blocking countries can prevent legitimate users and services (like payment gateways) from accessing your site. Use with caution.', 'advanced-ip-blocker' ) . '</p>';
    }

        /**
     * Muestra el campo de selección múltiple para los países, reutilizable para Geoblocking y Geo-Challenge.
     * @param array $args Argumentos pasados desde add_settings_field.
     */
    public function geoblock_countries_callback($args) {
        $type = $args['type'] ?? 'geoblock'; // Por defecto es geoblock para retrocompatibilidad
        
        if ($type === 'geo_challenge') {
            $option_name = 'geo_challenge_countries';
            $placeholder_text = __('Search for a country to challenge...', 'advanced-ip-blocker');
        } elseif ($type === 'login_restrict') {
            $option_name = 'login_restrict_countries';
            $placeholder_text = __('Search for an allowed country...', 'advanced-ip-blocker');
        } else {
            $option_name = 'geoblock_countries';
            $placeholder_text = __('Search for a country to block...', 'advanced-ip-blocker');
        }
        
        $select_id = 'advaipbl_' . $option_name;

        $selected_countries = $this->plugin->options[$option_name] ?? [];
        $all_countries     = $this->plugin->get_country_list();
        ?>
        <select id="<?php echo esc_attr($select_id); ?>" name="advaipbl_settings[<?php echo esc_attr($option_name); ?>][]" class="advaipbl-country-select" multiple="multiple" style="width: 100%;" data-placeholder="<?php echo esc_attr($placeholder_text); ?>">
            <?php foreach ( $all_countries as $code => $name ) : ?>
                <option value="<?php echo esc_attr( $code ); ?>" <?php selected( in_array( $code, $selected_countries, true ) ); ?>>
                    <?php echo esc_html( $name ); ?>
                </option>
            <?php endforeach; ?>
        </select>
        <?php if (isset($args['description'])) : ?>
            <p class="description"><?php echo wp_kses_post($args['description']); ?></p>
        <?php else : ?>
            <p class="description">
                <?php esc_html_e( 'Select one or more countries. Type in the box to search.', 'advanced-ip-blocker' ); ?>
            </p>
        <?php endif; ?>
        <?php
    }
	public function clear_cache_button_callback() {
        $nonce_url = wp_nonce_url(
            admin_url( 'admin-post.php?action=advaipbl_clear_location_cache_action' ), // Usamos un admin-post para la acción
            'advaipbl_clear_location_cache_nonce'
        );
        ?>
        <a href="<?php echo esc_url($nonce_url); ?>" class="button"><?php esc_html_e('Clear Location Cache', 'advanced-ip-blocker'); ?></a>
        <p class="description">
            <?php esc_html_e('Recommended when you change the geolocation provider or if location data appears to be outdated.', 'advanced-ip-blocker'); ?>
        </p>
        <?php
    }
	
	/**
     * Renders the "Send Test Email" button on the settings page.
     */

    public function send_test_email_button_callback() {
        $nonce_url = wp_nonce_url(
            admin_url( 'admin-post.php?action=advaipbl_send_test_email' ),
            'advaipbl_send_test_email_nonce'
        );
        ?>
        <a href="<?php echo esc_url( $nonce_url ); ?>" class="button">
            <?php esc_html_e( 'Send Setup Guide Email', 'advanced-ip-blocker' ); ?>
        </a>
        <p class="description">
            <?php esc_html_e( 'Click here to send a welcome email with a quick setup guide to the configured address.', 'advanced-ip-blocker' ); ?>
        </p>
        <?php
    }
	
	    /**
     * Renders the "Send Test Push Notification" button on the settings page.
     */
    public function send_test_push_button_callback() {
        $nonce_url = wp_nonce_url(
            admin_url('admin-post.php?action=advaipbl_send_test_push'),
            'advaipbl_send_test_push_nonce'
        );
        ?>
        <a href="<?php echo esc_url($nonce_url); ?>" class="button">
            <?php esc_html_e('Send Test Notification', 'advanced-ip-blocker'); ?>
        </a>
        <p class="description">
            <?php esc_html_e('Click to send a test alert to all configured webhook URLs.', 'advanced-ip-blocker'); ?>
        </p>
        <?php
    }

    /**
     * Renders the "Run FIM Scan Now" button on the settings page.
     */
    public function fim_manual_scan_button_callback() {
        // Only show if enabled
        if (empty($this->plugin->options['enable_fim'])) {
            echo '<p class="description">' . esc_html__('Enable the File Integrity Monitor to run scans.', 'advanced-ip-blocker') . '</p>';
            return;
        }

        $nonce = wp_create_nonce('advaipbl_run_fim_scan_nonce');
        ?>
        <button type="button" id="advaipbl-manual-fim-scan-btn" class="button button-secondary advaipbl-run-fim-scan" data-nonce="<?php echo esc_attr($nonce); ?>">
            <?php esc_html_e('Scan Files Now', 'advanced-ip-blocker'); ?>
        </button>
        <span id="advaipbl-fim-scan-status" class="advaipbl-fim-status" style="margin-left: 10px; font-style: italic;"></span>
        <p class="description">
            <?php esc_html_e('Triggers an immediate file integrity check. Results will be shown here and logged to the Audit Log if changes are found.', 'advanced-ip-blocker'); ?>
        </p>
        <?php
    }

	/**
     * Muestra el selector para el método de geolocalización.
     */
    public function geolocation_method_callback() {
        $current_method = $this->plugin->options['geolocation_method'] ?? 'api';
        ?>
        <select name="advaipbl_settings[geolocation_method]" id="advaipbl_geolocation_method">
            <option value="api" <?php selected($current_method, 'api'); ?>><?php esc_html_e( 'Real-time API (Easy, Good Performance)', 'advanced-ip-blocker' ); ?></option>
            <option value="local_db" <?php selected($current_method, 'local_db'); ?>><?php esc_html_e( 'Local Database (MaxMind, Highest Performance)', 'advanced-ip-blocker' ); ?></option>
        </select>
        <p class="description"><?php esc_html_e( 'Choose how to get IP location data. The Local Database is recommended for high-traffic sites.', 'advanced-ip-blocker' ); ?></p>
        <?php
    }

/**
 * Muestra el estado de la base de datos de GeoIP local.
 */
public function geoip_db_status_callback() {
    // Solo mostramos el estado si el GeoIP Manager está activo y es una instancia de nuestra clase.
    if ( ! $this->plugin->geoip_manager instanceof ADVAIPBL_GeoIP_Manager ) {
        echo '<p class="description">' . esc_html__('This status is only available when the "Local Database" method is selected and active.', 'advanced-ip-blocker') . '</p>';
        return;
    }
    
    $status = $this->plugin->geoip_manager->get_database_status();
    ?>
    <div id="advaipbl-geoip-db-status-container">
        <p>
            <strong><?php echo esc_html( ADVAIPBL_GeoIP_Manager::DB_CITY_FILENAME ); ?>:</strong>
            <?php if ( $status['city_db_exists'] ) : ?>
                <span style="color: green;"><?php esc_html_e( 'Installed', 'advanced-ip-blocker' ); ?></span>
                (<?php printf( '%s, %s', esc_html( $status['city_db_size'] ), esc_html( $status['city_db_date'] ) ); ?>)
            <?php else : ?>
                <span style="color: red;"><?php esc_html_e( 'Not Found', 'advanced-ip-blocker' ); ?></span>
            <?php endif; ?>
        </p>
        <p>
            <strong><?php echo esc_html( ADVAIPBL_GeoIP_Manager::DB_COUNTRY_FILENAME ); ?>:</strong>
            <?php if ( $status['country_db_exists'] ) : ?>
                <span style="color: green;"><?php esc_html_e( 'Installed', 'advanced-ip-blocker' ); ?></span>
                (<?php printf( '%s, %s', esc_html( $status['country_db_size'] ), esc_html( $status['country_db_date'] ) ); ?>)
            <?php else : ?>
                <span style="color: red;"><?php esc_html_e( 'Not Found', 'advanced-ip-blocker' ); ?></span>
            <?php endif; ?>
        </p>
        <p>
            <strong><?php echo esc_html( ADVAIPBL_GeoIP_Manager::DB_ASN_FILENAME ); ?>:</strong>
            <?php if ( $status['asn_db_exists'] ) : ?>
                <span style="color: green;"><?php esc_html_e( 'Installed', 'advanced-ip-blocker' ); ?></span>
                (<?php printf( '%s, %s', esc_html( $status['asn_db_size'] ), esc_html( $status['asn_db_date'] ) ); ?>)
            <?php else : ?>
                <span style="color: red;"><?php esc_html_e( 'Not Found', 'advanced-ip-blocker' ); ?></span>
            <?php endif; ?>
        </p>
        <p style="margin-top: 15px;">
            <button type="button" id="advaipbl-update-geoip-db" class="button button-secondary" data-nonce="<?php echo esc_attr( wp_create_nonce( 'advaipbl_update_geoip_nonce' ) ); ?>">
                <?php esc_html_e( 'Download/Update Databases', 'advanced-ip-blocker' ); ?>
            </button>
        </p>
        <div id="advaipbl-geoip-update-feedback" style="margin-top: 10px;"></div>
    </div>
    <?php
}
	    /**
     * Muestra los checkboxes para forzar 2FA por rol.
     */
    public function tfa_force_roles_callback() {
        $options = $this->plugin->options['tfa_force_roles'] ?? [];
        $editable_roles = get_editable_roles();
        ?>
        <fieldset>
            <legend class="screen-reader-text"><span><?php esc_html_e( 'Force 2FA for Roles', 'advanced-ip-blocker' ); ?></span></legend>
            <?php foreach ( $editable_roles as $role_slug => $role_details ) : ?>
                <label for="advaipbl_tfa_force_role_<?php echo esc_attr( $role_slug ); ?>">
                    <input type="checkbox"
                           name="advaipbl_settings[tfa_force_roles][]"
                           id="advaipbl_tfa_force_role_<?php echo esc_attr( $role_slug ); ?>"
                           value="<?php echo esc_attr( $role_slug ); ?>"
                           <?php checked( in_array( $role_slug, $options, true ) ); ?>>
                    <?php echo esc_html( translate_user_role( $role_details['name'] ) ); ?>
                </label><br>
            <?php endforeach; ?>
            <p class="description">
                <?php esc_html_e( 'Users with the selected roles will be required to set up 2FA to access the admin area.', 'advanced-ip-blocker' ); ?>
            </p>
        </fieldset>
        <?php
    }
	public function recaptcha_enable_callback($args) {
    $value = $this->plugin->options['recaptcha_enable'] ?? '0';
    ?>
    <input name="advaipbl_settings[recaptcha_enable]" type="hidden" value="0">
    <input name="advaipbl_settings[recaptcha_enable]" type="checkbox" id="advaipbl_recaptcha_enable" value="1" <?php checked($value, '1'); ?>>
    <p class="description">
        <?php esc_html_e('Enables reCAPTCHA verification on the WordPress login form.', 'advanced-ip-blocker'); ?>
        <?php
        // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
        echo $this->get_help_link_html($args);
        ?>
    </p>
    <?php
}

public function recaptcha_version_callback() {
    $value = $this->plugin->options['recaptcha_version'] ?? 'v3';
    ?>
    <select name="advaipbl_settings[recaptcha_version]" id="advaipbl_recaptcha_version">
        <option value="v3" <?php selected($value, 'v3'); ?>><?php esc_html_e('reCAPTCHA v3 (Recommended, Invisible)', 'advanced-ip-blocker'); ?></option>
        <option value="v2" <?php selected($value, 'v2'); ?>><?php esc_html_e('reCAPTCHA v2 (Checkbox)', 'advanced-ip-blocker'); ?></option>
    </select>
    <?php
}

public function recaptcha_site_key_callback() {
    $value = $this->plugin->options['recaptcha_site_key'] ?? '';
    ?>
    <input name="advaipbl_settings[recaptcha_site_key]" type="text" id="advaipbl_recaptcha_site_key" value="<?php echo esc_attr($value); ?>" class="regular-text">
    <?php
}

public function recaptcha_secret_key_callback() {
    $value = $this->plugin->options['recaptcha_secret_key'] ?? '';
    ?>
    <input name="advaipbl_settings[recaptcha_secret_key]" type="password" id="advaipbl_recaptcha_secret_key" value="<?php echo esc_attr($value); ?>" class="regular-text" autocomplete="off">
    <?php
}

public function recaptcha_score_callback() {
    $value = $this->plugin->options['recaptcha_score_threshold'] ?? '0.5';
    ?>
    <div id="advaipbl-recaptcha-v3-options-row">
        <input name="advaipbl_settings[recaptcha_score_threshold]" type="number" step="0.1" min="0.1" max="1.0" id="advaipbl_recaptcha_score_threshold" value="<?php echo esc_attr($value); ?>" class="small-text">
        <p class="description"><?php /* translators: %s: ReCAPTCHA v3 Score Threshold. */ printf(esc_html__('Logins with a score below this value (e.g., %s) will be blocked.', 'advanced-ip-blocker'), '0.5'); ?></p>
    </div>
    <?php
}

/**
 * Sanitiza y valida las reglas del WAF antes de guardarlas.
 * - Elimina duplicados.
 * - Descarta reglas que son expresiones regulares inválidas.
 * - Descarta reglas vacías o que solo contienen espacios.
 *
 * @param string $input El contenido del textarea de las reglas WAF.
 * @return string El contenido saneado y validado.
 */
public function sanitize_waf_rules($input) {
    if (!is_string($input)) {
        return '';
    }

    $lines = explode("\n", $input);
    $sanitized_lines = [];
    $invalid_rules = 0;

    foreach ($lines as $line) {
        // Quitamos espacios en blanco al principio y al final
        $trimmed_line = trim($line);

        // Saltamos líneas vacías
        if (empty($trimmed_line)) {
            continue;
        }
        
        // Si es un comentario, lo mantenemos sin validarlo como regex
        if (strpos($trimmed_line, '#') === 0) {
            $sanitized_lines[] = $trimmed_line;
            continue;
        }

        // Validamos que sea una expresión regular válida.
        // El @ suprime el warning de PHP que se generaría si la regex es inválida.
        if (@preg_match('~' . $trimmed_line . '~i', '') === false) {
            $invalid_rules++;
            continue; // Si no es válida, la descartamos
        }

        // Si llegamos aquí, la regla es válida
        $sanitized_lines[] = $trimmed_line;
    }

    // Eliminamos duplicados, preservando los comentarios
    $unique_lines = array_unique($sanitized_lines);

    if ($invalid_rules > 0) {
        $message = sprintf(
            /* translators: %d: Number of invalid rules. */
            _n(
                '%d invalid regular expression was found and has been discarded.',
                '%d invalid regular expressions were found and have been discarded.',
                $invalid_rules,
                'advanced-ip-blocker'
            ),
            $invalid_rules
        );
        add_settings_error('advaipbl_waf_rules', 'invalid_regex', $message, 'warning');
    }

    return implode("\n", $unique_lines);
}

/**
     * Callback genérico para selectores de acción (Block vs Challenge).
     * Acepta el nombre del campo dinámicamente.
     */
    public function action_select_callback($args) {
        $name = $args['name'];
        $current_action = $this->plugin->options[$name] ?? 'block';
        
        printf('<select name="advaipbl_settings[%s]">', esc_attr($name));
        printf('<option value="block" %s>%s</option>', selected($current_action, 'block', false), esc_html__('Block IP Instantly (Recommended)', 'advanced-ip-blocker'));
        printf('<option value="challenge" %s>%s</option>', selected($current_action, 'challenge', false), esc_html__('Challenge with JavaScript', 'advanced-ip-blocker'));
        echo '</select>';

        if ( ! empty( $args['description'] ) ) {
            echo '<p class="description">' . wp_kses_post( $args['description'] ) . '</p>';
        }
        
        // Icono de ayuda
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
        echo $this->get_help_link_html($args);
    }

/**
 * Muestra el campo de selección para la acción de AbuseIPDB.
 */
public function abuseipdb_action_callback() {
    $options = $this->plugin->options;
    $current_action = $options['abuseipdb_action'] ?? 'block';
    ?>
    <select name="advaipbl_settings[abuseipdb_action]">
        <option value="block" <?php selected($current_action, 'block'); ?>><?php esc_html_e('Block IP Instantly (Recommended)', 'advanced-ip-blocker'); ?></option>
        <option value="challenge" <?php selected($current_action, 'challenge'); ?>><?php esc_html_e('Challenge with JavaScript', 'advanced-ip-blocker'); ?></option>
    </select>
    <p class="description"><?php esc_html_e('Choose whether to block high-risk IPs immediately or to present them with a JavaScript challenge to filter out bots and reduce false positives.', 'advanced-ip-blocker'); ?></p>
    <?php
}

/**
     * Helper para generar el icono de ayuda si existe una URL.
     *
     * @param array $args Argumentos del campo.
     * @return string HTML del enlace de ayuda o cadena vacía.
     */
    private function get_help_link_html($args) {
        if ( empty( $args['help_url'] ) ) {
            return '';
        }
        
        return sprintf(
            ' <a href="%s" target="_blank" class="advaipbl-help-icon" title="%s"><span class="dashicons dashicons-editor-help"></span></a>',
            esc_url( $args['help_url'] ),
            esc_attr__( 'Read Documentation', 'advanced-ip-blocker' )
        );
    }

    /**
     * Callback for visual separator.
     */
    public function separator_callback() {
        echo '<hr style="margin: 20px 0; border: 0; border-top: 1px solid #ddd;">';
    }

}