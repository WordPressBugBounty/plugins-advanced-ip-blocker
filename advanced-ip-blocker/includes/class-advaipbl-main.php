<?php

if ( ! defined( 'ABSPATH' ) ) exit;

class ADVAIPBL_Main {
	const OPTION_SETTINGS            = 'advaipbl_settings';
    const OPTION_WHITELIST           = 'advaipbl_ips_whitelist';
    const OPTION_BLOCKED_MANUAL      = 'advaipbl_blocked_ips_manual';
    const OPTION_BLOCKED_404         = 'advaipbl_blocked_ips_404';
    const OPTION_BLOCKED_403         = 'advaipbl_blocked_ips_403';
    const OPTION_BLOCKED_LOGIN       = 'advaipbl_blocked_ips_login';
    const OPTION_BLOCKED_GEO         = 'advaipbl_blocked_ips_geoblock';
    const OPTION_BLOCKED_HONEYPOT    = 'advaipbl_blocked_ips_honeypot';
    const OPTION_BLOCKED_USER_AGENT  = 'advaipbl_blocked_ips_user_agent';
    const OPTION_BLOCKED_WAF         = 'advaipbl_blocked_ips_waf';
	const OPTION_BLOCKED_THREAT_SCORE = 'advaipbl_blocked_ips_threat_score';
    const OPTION_WAF_RULES           = 'advaipbl_waf_rules';
	const OPTION_BLOCKED_RATE_LIMIT  = 'advaipbl_blocked_ips_rate_limit';
	const OPTION_BLOCKED_ASN         = 'advaipbl_blocked_ips_asn';
	const OPTION_WHITELISTED_ASNS    = 'advaipbl_whitelisted_asns';
    const OPTION_BLOCKED_ASNS        = 'advaipbl_blocked_asns';
	const OPTION_BLOCKED_XMLRPC      = 'advaipbl_blocked_ips_xmlrpc_block';
	const OPTION_HONEYPOT_URLS       = 'advaipbl_honeypot_urls';
    const OPTION_BLOCKED_UAS         = 'advaipbl_blocked_user_agents';
    const OPTION_WHITELISTED_UAS     = 'advaipbl_whitelisted_user_agents';
    const OPTION_ADMIN_IP_TRIGGER    = 'advaipbl_admin_ip_whitelist_trigger';
    const TRANSIENT_ADMIN_NOTICE     = 'advaipbl_admin_notice';
	const AUTOLOAD_OPTIMIZATION_VERSION = '1.1';
	const LEGACY_OPTIONS_CLEANUP_VERSION = '1.1';
    private static $instance;
    public $options;
    public $session_manager;
    public $waf_manager;
	public $rate_limit_manager;
	public $asn_manager;
	private $request_is_asn_whitelisted = false;
	public $dashboard_manager;
	public $threat_score_manager;
	public $fingerprint_manager;
    public $tfa_manager;
	public $geoip_manager;
	public $rules_engine;
    public $audit_logger;
    public $file_verifier;
	private $client_ip = null;
    private $error_handled_this_request = false;
	private $challenge_passed_this_request = false;
	private static $block_queue = [];
    private static $shutdown_hook_registered = false;
	private $client_ip_detection_method = 'Not yet determined';
	private $main_admin_page_hook;
	private $blocked_count = null;
	public $geolocation_manager;
	public $admin_pages;
    public $action_handler;
	public $ajax_handler;
	public $settings_manager;
	public $bot_verifier;
	public $abuseipdb_manager;
	public $htaccess_manager;
	public $cloudflare_manager;
	public $reporter_manager;
	public $community_manager;
	public $site_scanner;
    public $security_headers_manager;
    public $js_challenge_manager;
    public $cache_manager;
    public $live_feed_manager;
    public $notification_manager;
    public $cron_manager;
    /**
     * Flag indicating if a request was explicitly allowed by an Advanced Rule,
     * overriding subsequent checks like AbuseIPDB.
     * @var bool
     */
    public $is_advanced_rule_allowed = false;
	private $block_response_initiated = false;
    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }
	
private function __construct() {
    $this->options = get_option(self::OPTION_SETTINGS, []);
    
    require_once plugin_dir_path(__FILE__) . 'class-advaipbl-admin-pages.php';
    require_once plugin_dir_path(__FILE__) . 'class-advaipbl-action-handler.php';
    require_once plugin_dir_path(__FILE__) . 'class-advaipbl-ajax-handler.php';
    require_once plugin_dir_path(__FILE__) . 'class-advaipbl-settings-manager.php';
    require_once plugin_dir_path(__FILE__) . 'class-advaipbl-geolocation-manager.php';
    require_once plugin_dir_path(__FILE__) . 'class-advaipbl-geoip-manager.php';
    require_once plugin_dir_path(__FILE__) . 'class-advaipbl-session-manager.php';
    require_once plugin_dir_path(__FILE__) . 'class-advaipbl-asn-manager.php';
    require_once plugin_dir_path(__FILE__) . 'class-advaipbl-waf-manager.php';
    require_once plugin_dir_path(__FILE__) . 'class-advaipbl-rate-limiting-manager.php';
    require_once plugin_dir_path(__FILE__) . 'class-advaipbl-dashboard-manager.php';
    require_once plugin_dir_path(__FILE__) . 'class-advaipbl-threat-score-manager.php';
    require_once plugin_dir_path(__FILE__) . 'class-advaipbl-bot-verifier.php';
    require_once plugin_dir_path(__FILE__) . 'class-advaipbl-rules-engine.php';
    require_once plugin_dir_path(__FILE__) . 'class-advaipbl-fingerprint-manager.php';
    require_once plugin_dir_path(__FILE__) . 'class-advaipbl-abuseipdb-manager.php';
	require_once plugin_dir_path(__FILE__) . 'class-advaipbl-htaccess-manager.php';
	require_once plugin_dir_path(__FILE__) . 'class-advaipbl-cloudflare-manager.php';
	require_once plugin_dir_path(__FILE__) . 'class-advaipbl-reporter-manager.php';
    require_once plugin_dir_path(__FILE__) . 'class-advaipbl-community-manager.php';
    require_once plugin_dir_path(__FILE__) . 'class-advaipbl-community-manager.php';
	require_once plugin_dir_path(__FILE__) . 'class-advaipbl-site-scanner.php';
    require_once plugin_dir_path(__FILE__) . 'class-advaipbl-site-scanner.php';
    require_once plugin_dir_path(__FILE__) . 'class-advaipbl-security-headers.php';
    require_once plugin_dir_path(__FILE__) . 'class-advaipbl-audit-logger.php';
    require_once plugin_dir_path(__FILE__) . 'class-advaipbl-file-verifier.php';
    require_once plugin_dir_path(__FILE__) . 'class-advaipbl-js-challenge.php';
    require_once plugin_dir_path(__FILE__) . 'class-advaipbl-cache-manager.php';
    require_once plugin_dir_path(__FILE__) . 'class-advaipbl-live-feed-manager.php';
    require_once plugin_dir_path(__FILE__) . 'class-advaipbl-cron-manager.php';
    require_once plugin_dir_path(__FILE__) . 'class-advaipbl-notification-manager.php';
    
	$this->site_scanner = new ADVAIPBL_Site_Scanner($this);
    $this->community_manager = new ADVAIPBL_Community_Manager($this);
    $this->admin_pages = new ADVAIPBL_Admin_Pages($this);
    $this->action_handler = new ADVAIPBL_Action_Handler($this);
    $this->ajax_handler = new ADVAIPBL_Ajax_Handler($this);
    $this->settings_manager = new ADVAIPBL_Settings_Manager($this, $this->admin_pages);
    
    $this->geolocation_manager = new ADVAIPBL_Geolocation_Manager($this);
    $this->session_manager = new ADVAIPBL_User_Session_Manager($this, $this->geolocation_manager);
    $this->asn_manager = new ADVAIPBL_Asn_Manager($this, $this->geolocation_manager);
    $this->waf_manager = new ADVAIPBL_Waf_Manager($this);
    $this->rate_limit_manager = new ADVAIPBL_Rate_Limiting_Manager($this);
    $this->dashboard_manager = new ADVAIPBL_Dashboard_Manager($this, $this->session_manager);
    $this->threat_score_manager = new ADVAIPBL_Threat_Score_Manager($this);
    $this->bot_verifier = new ADVAIPBL_Bot_Verifier($this);
    $this->rules_engine = new ADVAIPBL_Rules_Engine($this);
    $this->fingerprint_manager = new ADVAIPBL_Fingerprint_Manager($this);
    $this->abuseipdb_manager = new ADVAIPBL_AbuseIPDB_Manager($this);
    $this->htaccess_manager = new ADVAIPBL_Htaccess_Manager($this);
	$this->cloudflare_manager = new ADVAIPBL_Cloudflare_Manager($this);
	$this->reporter_manager = new ADVAIPBL_Reporter_Manager($this);
    $this->security_headers_manager = new ADVAIPBL_Security_Headers($this);
    $this->audit_logger = new ADVAIPBL_Audit_Logger($this);
    $this->file_verifier = new ADVAIPBL_File_Verifier($this);
    $this->js_challenge_manager = new ADVAIPBL_JS_Challenge($this);
    $this->cache_manager = new ADVAIPBL_Cache_Manager();
    $this->live_feed_manager = new ADVAIPBL_Live_Feed_Manager($this);
    $this->cron_manager = new ADVAIPBL_Cron_Manager($this);
    $this->notification_manager = new ADVAIPBL_Notification_Manager($this);
	
    if (version_compare(PHP_VERSION, '8.1', '>=')) {
        // Initialize GeoIP Manager only if needed
        if (($this->options['geolocation_method'] ?? 'api') === 'local_db') {
            $this->geoip_manager = new ADVAIPBL_GeoIP_Manager($this);
        } else {
            $this->geoip_manager = new stdClass();
        }

        // Carga perezosa del 2FA Manager solo en backend y si es seguro
        if (is_admin() || (isset($GLOBALS['pagenow']) && $GLOBALS['pagenow'] === 'wp-login.php')) {
            
            require_once plugin_dir_path(__FILE__) . 'class-advaipbl-2fa-manager.php';
            
            // Verificación de seguridad: ¿Están las librerías cargadas?
            // Esto evita el error fatal si la instalación falló y faltan archivos.
            if ( class_exists('BaconQrCode\Renderer\ImageRenderer') ) {
                $this->tfa_manager = new ADVAIPBL_2FA_Manager($this);
            } else {
                // Fallback silencioso para no romper el sitio
                $this->tfa_manager = new stdClass();
                // error_log('Advanced IP Blocker: 2FA libraries missing. Feature disabled to prevent crash.');
            }
        } else {
            $this->tfa_manager = new stdClass();
        }
    } else {
        $this->geoip_manager = new stdClass();
        $this->tfa_manager = new stdClass();
    }

    // --- Hook para reglas de usuario (Username Block) ---
    add_filter('authenticate', [$this, 'check_login_rules'], 20, 3);

    add_action('admin_init', [$this, 'check_database_update']);
    $this->add_hooks();
    
    if (is_admin()) {
        add_action('admin_notices', [$this, 'display_admin_notice']);
    }
}
	
    public function initialize_backend_managers() {
        static $initialized = false;
        if ($initialized) {
            return;
        }

        require_once plugin_dir_path(__FILE__) . 'class-advaipbl-dashboard-manager.php';
        
        $this->dashboard_manager = new ADVAIPBL_Dashboard_Manager($this, $this->session_manager);

        // Secure logic for 2FA
        if (version_compare(PHP_VERSION, '8.1', '>=')) {
            require_once plugin_dir_path(__FILE__) . 'class-advaipbl-2fa-manager.php';
            
            if (class_exists('BaconQrCode\Renderer\ImageRenderer')) {
                $this->tfa_manager = new ADVAIPBL_2FA_Manager($this);
            } else {
                $this->tfa_manager = new stdClass();
                // error_log('Advanced IP Blocker: 2FA libraries missing in backend init.');
            }
        } else {
            $this->tfa_manager = new stdClass();
        }

        $initialized = true;
    }
    
    private function add_hooks() {
        
        // Ejecutar chequeo de base de datos muy temprano en init
        add_action('init', [$this, 'check_database_version'], -9999);

        // Intercepción global y obligatoria para todos los JS Challenges (evita orfandad en módulos de bloqueo avanzados)
        add_action('init', [$this->js_challenge_manager, 'verify_submission'], -999);
		add_action('init', [$this, 'is_visitor_asn_whitelisted'], -100);
		add_action('init', [$this, 'verify_known_bots'], -99);
		add_action('init', [$this, 'check_ip_with_abuseipdb'], 10);
		add_action('init', [$this, 'block_xmlrpc_requests_if_disabled'], -5);
        add_action('init', [$this, 'log_request_signature'], -2);
        add_action('plugins_loaded', [$this, 'maybe_set_donotcachepage_constant'], 0);
        add_action('init', [$this, 'check_for_endpoint_lockdown'], -1);		
        add_action('init', [$this, 'check_for_malicious_signature'], -1);
        add_action('init', [$this, 'check_for_geo_challenge'], -1);
        add_action('init', [$this, 'run_all_block_checks'], 0);
        add_action('init', [$this, 'log_wp_cron_execution'], 1);
        add_action('init', [$this->rate_limit_manager, 'check_request_rate'], -1); 
        add_action('init', [$this, 'add_admin_ip_to_whitelist_on_first_run']);
        add_filter('status_header', [$this, 'detect_http_error_status'], 10, 2);
		add_action('advaipbl_community_report_event_v2', [$this, 'execute_community_report']);
		add_action('advaipbl_update_community_list_event', [$this->community_manager, 'update_list']);
		add_action('wp_ajax_advaipbl_run_deep_scan', [$this->ajax_handler, 'ajax_run_deep_scan']);
		add_action('wp_ajax_advaipbl_check_server_reputation', [$this->ajax_handler, 'ajax_check_server_reputation']);
        add_action('wp_ajax_advaipbl_clear_audit_log', [$this->ajax_handler, 'ajax_clear_audit_logs']);
        add_action('wp_ajax_advaipbl_run_fim_scan', [$this->ajax_handler, 'ajax_run_fim_scan']);
        
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $action = isset($_GET['action']) ? sanitize_text_field(wp_unslash($_GET['action'])) : '';
        if (is_admin() || (strpos($action, 'advaipbl_') === 0)) {
            add_action('admin_init', [$this, 'initialize_backend_managers'], 0);

        }
        
        global $pagenow;
        if ($pagenow === 'wp-login.php') {
            $this->initialize_backend_managers();
        }

        add_action('init', [$this, 'prevent_author_enumeration_redirect'], 9);
		add_filter('the_author_login', [$this, 'prevent_user_enumeration_via_feeds']);
        add_filter('get_the_author_login', [$this, 'prevent_user_enumeration_via_feeds']);
        add_action('wp_login_failed', [$this, 'registrar_intento_login_fallido']);
        add_action('login_init', [ $this, 'handle_login_page_restriction' ], 1 );
		add_action('login_init', [ $this, 'handle_login_geo_restriction' ], 2 );
        add_action('wp_login', [$this, 'auto_whitelist_admin_on_login'], 10, 2);
        add_filter('rest_endpoints', [ $this, 'disable_rest_api_user_endpoints' ] );
		add_filter('oembed_response_data', [$this, 'prevent_user_enumeration_via_oembed'], 99, 4);
		add_filter('authenticate', [$this, 'prevent_login_hinting'], 99, 1);
        add_action('rest_api_init', [$this, 'register_live_feed_api_endpoint']);
        add_action('rest_api_init', function() {
            register_rest_route('advaipbl/v1', '/live-feed-nonce', [
                'methods'  => WP_REST_Server::READABLE,
                'callback' => [$this, 'get_live_feed_nonce'],
                'permission_callback' => '__return_true',
            ]);
        });
        add_shortcode('advaipbl_live_feed', [$this, 'render_live_feed_shortcode']);
        $this->add_2fa_hooks();
		
        if ( ! empty( $this->options['show_admin_bar_menu'] ) && '1' === $this->options['show_admin_bar_menu'] ) {
            add_action( 'admin_bar_menu', [ $this, 'add_admin_bar_menu' ], 999 );
        }

        add_action('advaipbl_purge_old_logs_event', [$this, 'purge_old_logs']);
        add_action('advaipbl_cloudflare_cleanup_event', [$this->cloudflare_manager, 'clear_all_aib_rules']);
        // add_action('advaipbl_send_summary_email', [$this, 'process_and_send_summary']); // Moved to Notification Manager
        add_action('advaipbl_send_telemetry_data_event', [$this, 'send_telemetry_data']);
		add_action('advaipbl_update_geoip_db_event', [$this, 'execute_geoip_db_update']);
        add_action('advaipbl_clear_expired_blocks_event', [$this, 'limpiar_ips_expiradas']);
        add_action('advaipbl_cleanup_expired_cache_event', [$this, 'cleanup_expired_cache_entries']);
        add_action('advaipbl_daily_fim_scan', [$this->file_verifier, 'scan_files']);
        
        if (is_admin()) {
			add_action('admin_notices', [$this, 'display_setup_wizard_notice']);
			add_action('admin_init', [$this, 'maybe_redirect_to_wizard']);
            add_action('admin_init', [$this, 'schedule_cron_jobs']);
			add_action('admin_init', [$this, 'conditionally_remove_admin_notices']);
            add_action('admin_init', [$this, 'update_option_autoload_states']);
            add_action('admin_menu', [$this, 'admin_menu']);
            add_action('admin_init', [$this->settings_manager, 'register_settings']);
            add_action('admin_init', [$this->action_handler, 'handle_admin_actions']);
            add_action('update_option_' . self::OPTION_SETTINGS, [$this, 'on_settings_update'], 10, 2);
			add_action('update_option_' . self::OPTION_WAF_RULES, [$this, 'on_waf_rules_update'], 10, 2);
			add_action('admin_post_advaipbl_refresh_spamhaus', [$this, 'handle_spamhaus_refresh_action']);
            add_action('admin_notices', [$this, 'display_force_2fa_setup_notice']);
        add_action('admin_notices', [$this, 'display_admin_notice']);

        // CSS Hiding Strategy:
        // Ocultar visualmente el enlace del Setup Wizard del menú lateral
        add_action('admin_head', function() {
            ?>
            <style>
                /* Ocultar el enlace del Setup Wizard en el submenú */
                #toplevel_page_advaipbl_settings_page .wp-submenu a[href$="page=advaipbl-setup-wizard"],
                li.current a[href$="page=advaipbl-setup-wizard"] { 
                    display: none !important; 
                }
            </style>
            <?php
        });
            add_action('admin_enqueue_scripts', [$this, 'load_admin_scripts']);
            add_action('admin_footer', [$this, 'print_modal_html_in_footer']);			
            add_action('wp_ajax_advaipbl_test_outbound_connection', [$this->ajax_handler, 'ajax_test_outbound_connection']);
            add_action('wp_ajax_advaipbl_add_ip_to_whitelist', [$this->ajax_handler, 'ajax_add_ip_to_whitelist']);
            add_action('wp_ajax_advaipbl_verify_api_key', [$this->ajax_handler, 'ajax_verify_api_key']);
            add_action('wp_ajax_advaipbl_get_free_api_key', [$this->ajax_handler, 'ajax_get_free_api_key']);
			add_action('wp_ajax_advaipbl_update_geoip_db', [$this->ajax_handler, 'ajax_update_geoip_db']);
			add_action('wp_ajax_advaipbl_get_dashboard_stats', [$this->ajax_handler, 'ajax_get_dashboard_stats']); 
            add_action('wp_ajax_advaipbl_export_settings_ajax', [ $this, 'handle_export_settings_ajax' ] );
            add_action('wp_ajax_advaipbl_handle_telemetry_notice', [$this->ajax_handler, 'ajax_handle_telemetry_notice']);
			add_action('wp_ajax_advaipbl_reset_threat_score', [$this->ajax_handler, 'ajax_reset_threat_score']);
            add_action('wp_ajax_advaipbl_get_score_history', [$this->ajax_handler, 'ajax_get_score_history']);
			add_action('wp_ajax_advaipbl_delete_signature', [$this->ajax_handler, 'ajax_delete_signature']);
			add_action('wp_ajax_advaipbl_get_signature_details', [$this->ajax_handler, 'ajax_get_signature_details']);
			add_action('wp_ajax_advaipbl_whitelist_signature', [$this->ajax_handler, 'ajax_whitelist_signature']);
			add_action('wp_ajax_advaipbl_get_lockdown_details', [$this->ajax_handler, 'ajax_get_lockdown_details']);
            add_action('admin_post_advaipbl_import_settings', [ $this, 'handle_import_settings' ] );
            add_action('admin_post_advaipbl_clear_location_cache_action', [$this, 'handle_clear_cache_action']);
            add_action('admin_post_advaipbl_send_test_email', [ $this, 'handle_send_test_email' ] );
            add_action('admin_post_advaipbl_send_test_push', [ $this, 'handle_send_test_push' ] );
            add_action('admin_post_advaipbl_run_manual_scan', [ $this, 'handle_run_manual_scan' ] );
			// Hooks para el asistente de configuración
            add_action( 'admin_post_advaipbl_wizard_step_1', [ $this->action_handler, 'handle_wizard_step_1' ] );
			add_action( 'admin_post_advaipbl_wizard_step_2', [ $this->action_handler, 'handle_wizard_step_2' ] );
			add_action( 'admin_post_advaipbl_wizard_step_3', [ $this->action_handler, 'handle_wizard_step_3' ] );
			add_action( 'admin_post_advaipbl_wizard_step_4', [ $this->action_handler, 'handle_wizard_step_4' ] );
        }
		add_action('wp_ajax_advaipbl_get_advanced_rules', [$this->ajax_handler, 'ajax_get_advanced_rules']);
        add_action('wp_ajax_advaipbl_save_advanced_rule', [$this->ajax_handler, 'ajax_save_advanced_rule']);
        add_action('wp_ajax_advaipbl_delete_advanced_rule', [$this->ajax_handler, 'ajax_delete_advanced_rule']);
		add_action('wp_ajax_advaipbl_reorder_rules', [$this->ajax_handler, 'ajax_reorder_advanced_rules']);
		add_action('wp_ajax_advaipbl_bulk_delete_advanced_rules', [$this->ajax_handler, 'ajax_bulk_delete_advanced_rules']);
        add_action('wp_ajax_advaipbl_verify_abuseipdb_key', [$this->ajax_handler, 'ajax_verify_abuseipdb_key']);
		add_action('wp_ajax_advaipbl_bulk_import_whitelist', [$this->ajax_handler, 'ajax_bulk_import_whitelist']);
        add_action('wp_ajax_advaipbl_bulk_export_whitelist', [$this->ajax_handler, 'ajax_bulk_export_whitelist']);
        add_action('wp_ajax_advaipbl_bulk_import_blocked_ips', [$this->ajax_handler, 'ajax_bulk_import_blocked_ips']);
        add_action('wp_ajax_advaipbl_bulk_export_blocked_ips', [$this->ajax_handler, 'ajax_bulk_export_blocked_ips']);
        
        if ( ! empty( $this->options['xmlrpc_protection_mode'] ) && 'disabled' === $this->options['xmlrpc_protection_mode'] ) {
           add_filter( 'xmlrpc_enabled', '__return_false' );
           remove_action( 'wp_head', 'rsd_link' );
           remove_action( 'wp_head', 'wlwmanifest_link' );
        }
        
        if ( !empty($this->options['recaptcha_enable']) && '1' === $this->options['recaptcha_enable'] && !empty($this->options['recaptcha_site_key']) && !empty($this->options['recaptcha_secret_key']) ) {
            add_action('login_enqueue_scripts', array($this, 'enqueue_recaptcha_script'));
            add_action('login_form', array($this, 'display_recaptcha_field'));
            add_filter('authenticate', array($this, 'validate_recaptcha_response'), 20, 3);
        }
    }
    
    /**
     * Comprueba si la versión de la base de datos coincide con la versión definida en el plugin.
     * Si no coincide, o si es forzada, ejecuta la configuración de tablas.
     */
    public function check_database_version() {
        $installed_ver = get_option('advaipbl_db_version');

        if ( version_compare( $installed_ver, ADVAIPBL_DB_VERSION, '<' ) ) {
            self::setup_database_tables();
        }
    }
    
    /**
     * Helper routine to automatically generate V3 API Tokens for users who
     * already had the AIB Network activated in older versions.
     */
    private function auto_migrate_v3_token() {
        // Ensure options are freshly loaded since this runs early in init during updates
        $this->options = get_option(self::OPTION_SETTINGS, []);

        // If the user hasn't opted-in to the community network, do nothing (privacy first)
        if (empty($this->options['enable_community_network'])) {
            return;
        }
        
        // If they already have a V3 token, do nothing
        if (!empty($this->options['api_token_v3'])) {
            return;
        }

        // Trigger the internal site registration to generate keys and fetch the V3 token
        if (isset($this->community_manager)) {
            $this->community_manager->register_site();
            
            // Re-load options into memory as register_site() modifies the DB directly sometimes
            $this->options = get_option(self::OPTION_SETTINGS, []);
        }
    }
	
	  /**
     * @param string $key La clave de la caché.
     * @return mixed El valor de la caché, o false si no existe o ha caducado.
     */
    public function get_from_custom_cache( $key, $get_full_object = false ) {
        if ( ! isset($this->cache_manager) ) {
             $this->cache_manager = new ADVAIPBL_Cache_Manager();
        }
        return $this->cache_manager->get( $key, $get_full_object );
    }

    /**
     * Guarda un valor en tabla de caché personalizada.
     *
     * @param string $key        La clave de la caché.
     * @param mixed  $value      El valor a guardar (será serializado).
     * @param int    $expiration Duración de la caché en segundos.
     */
    public function set_in_custom_cache( $key, $value, $expiration ) {
        if ( ! isset($this->cache_manager) ) {
             $this->cache_manager = new ADVAIPBL_Cache_Manager();
        }
        return $this->cache_manager->set( $key, $value, $expiration );
    }
	
	    /**
     * Limpia todas las entradas caducadas de la tabla de caché personalizada.
     * Diseñado para ser llamado por un WP-Cron job para el mantenimiento de la base de datos.
     */
    public function cleanup_expired_cache_entries() {
        if ( ! isset($this->cache_manager) ) {
             $this->cache_manager = new ADVAIPBL_Cache_Manager();
        }
        $deleted_rows = $this->cache_manager->cleanup_expired();
        
        if ( is_numeric($deleted_rows) && $deleted_rows > 0 ) {
			/* translators: %d: The number of IPs entries that were deleted. */
            $this->log_event( sprintf( __( 'Cache cleanup task ran. Removed %d stale entries.', 'advanced-ip-blocker' ), $deleted_rows ), 'info' );
        }
    }
	
	 /**
     * Registra todos los hooks relacionados con 2FA.
     */
            public function add_2fa_hooks() {
        //if ( ! $this->tfa_manager ) { return; }

        // Hooks del Perfil
        add_action('show_user_profile', [$this, 'display_2fa_section_in_profile']);
        add_action('edit_user_profile', [$this, 'display_2fa_section_in_profile']);
        add_action('personal_options_update', [$this, 'save_2fa_section_in_profile']);
        add_action('edit_user_profile_update', [$this, 'save_2fa_section_in_profile']);
        
        // Hooks de AJAX
        add_action('wp_ajax_advaipbl_2fa_generate', [$this->ajax_handler, 'ajax_2fa_generate']);
        add_action('wp_ajax_advaipbl_2fa_activate', [$this->ajax_handler, 'ajax_2fa_activate']);
        add_action('wp_ajax_advaipbl_2fa_deactivate', [$this->ajax_handler, 'ajax_2fa_deactivate']);

        // Hooks del Proceso de Login
        add_filter('authenticate', [$this, 'intercept_login_step_1'], 20, 3); // Prioridad 20
        add_action('login_form_advaipbl_validate_2fa', [$this, 'display_2fa_login_form_step_2']);
		add_action('login_form_advaipbl_validate_2fa_backup', [$this, 'display_2fa_backup_code_form']);
        add_action('login_form_login', [$this, 'handle_login_action']);
    }

     /**
     * Registra la firma de la petición actual si la opción está activada.
     */
    public function log_request_signature() {
        if (empty($this->options['enable_signature_engine'])) { return; }
        
        $request_uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';
		// No loguear las peticiones del Live Feed interno
        if (strpos($request_uri, '/advaipbl/v1/live-attacks') !== false) {
            return;
        }
        
        // Excluir AJAX, JSON, Cron y procesos internos (ej: Elementor, WP Dashboard), PERO monitorear nuestras APIs JSON
        if (wp_doing_ajax() || is_admin() || wp_doing_cron() || (defined('WP_CLI') && WP_CLI)) { 
            return; 
        }
        
        if (wp_is_json_request() && strpos($request_uri, '/telemetry/') === false && strpos($request_uri, '/aib-network/') === false && strpos($request_uri, '/aib-scanner/') === false && strpos($request_uri, '/aib-api/') === false) {
            return;
        }
        if ($this->challenge_passed_this_request) { return; }
   
        // Skip if whitelisted ASN (e.g. Google, Bing) to avoid false positives.
        if ($this->request_is_asn_whitelisted) { return; }

        $ip = $this->get_client_ip();
        if ($this->is_whitelisted($ip)) { return; }

        $signature_hash = $this->fingerprint_manager->generate_signature();

        // Obtenemos la lista de confianza del usuario settings.
        $raw_user_whitelist = $this->options['trusted_signature_hashes'] ?? '';
        $user_whitelisted_hashes = [];
        if (!empty($raw_user_whitelist)) {
            $lines = explode("\n", $raw_user_whitelist);
            foreach ($lines as $line) {
                $trimmed_line = trim($line);
                if (!empty($trimmed_line) && strpos($trimmed_line, '#') !== 0) {
                    $user_whitelisted_hashes[] = $trimmed_line;
                }
            }
        }

        // Ya no mantenemos firmas hardcoded debido a la fragilidad y rotación continua (Crawler Spoofing y cambios de versión).
        // Los bots buenos legítimos (Google, Bing, etc.) ya han sido excluidos más arriba mediante ASN y rDNS.
        // Aquí solo aplicamos las firmas "custom" añadidas bajo la responsabilidad del usuario.
        $trusted_signature_hashes = apply_filters('advaipbl_trusted_signature_hashes', $user_whitelisted_hashes);

        if (in_array($signature_hash, $trusted_signature_hashes, true)) {
            return;
        }
        
        global $wpdb;
        $table_name = $wpdb->prefix . 'advaipbl_request_log';

        $is_fake_bot = 0;
        // Check if the User-Agent claims to be a known bot (Google, Bing, etc.)
        if ( isset($this->bot_verifier) && $this->bot_verifier->is_known_bot_impersonator($ip, $this->get_user_agent()) ) {
            
            // 1. Check transient cache first (Optimization)
            if ( get_transient('advaipbl_verified_bot_' . md5($ip)) ) {
                $is_fake_bot = 0; // It's verified and legitimate
            } else {
                // 2. Perform DNS verification
                // is_verified_bot performs the DNS lookup if not cached statically
                if ( ! $this->bot_verifier->is_verified_bot($ip, $this->get_user_agent()) ) {
                    $is_fake_bot = 1;
                }
            }
        }

        $data_to_log = [
            'timestamp'         => time(),
            'ip_hash'           => hash('sha256', $ip),
            'request_uri'       => $this->get_current_request_uri(),
            'user_agent'        => $this->get_user_agent(),
            'request_headers'   => $this->fingerprint_manager->get_request_headers_for_log(),
            'request_method'    => $this->get_request_method(),
            'signature_hash'    => $signature_hash,
            'is_fake_bot'       => $is_fake_bot,
        ];

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $wpdb->insert($table_name, $data_to_log);
    }           

    /**
     * Purges all cache from popular caching plugins.
     * Called when security settings or blocklists change to ensure immediate effect.
     */
    public function purge_all_page_caches() {
        // LiteSpeed Cache
        if (has_action('litespeed_purge_all')) {
            // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound
            do_action('litespeed_purge_all');
        } elseif (defined('LSCWP_V')) {
            // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound
            do_action('litespeed_purge_all_hook'); 
        }

        // WP Rocket
        if (function_exists('rocket_clean_domain')) {
            rocket_clean_domain();
        }

        // W3 Total Cache
        if (function_exists('w3tc_flush_all')) {
            w3tc_flush_all();
        }

        // WP Super Cache
        if (function_exists('wp_cache_clear_cache')) {
            wp_cache_clear_cache();
        }

        // WP Fastest Cache
        if (isset($GLOBALS['wp_fastest_cache']) && method_exists($GLOBALS['wp_fastest_cache'], 'deleteCache')) {
            $GLOBALS['wp_fastest_cache']->deleteCache(true);
        }

        // Autoptimize
        if (class_exists('autoptimizeCache')) {
            autoptimizeCache::clearall();
        }

        // SG Optimizer (SiteGround)
        if (function_exists('sg_cachepress_purge_cache')) {
            sg_cachepress_purge_cache();
        }
        
        // Kinsta Cache
        if (class_exists('Kinsta\Cache')) {
            // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound
            do_action('kinsta_purge_edge_cache');
        }
        
        /* translators: %s: Type of action triggered. */
        $this->log_event(__('System page caches successfully flushed after a security update.', 'advanced-ip-blocker'), 'info', 'localhost');
    }
      
	/**
 * Se ejecuta temprano para verificar bots conocidos y tomar acciones.
 */
public function verify_known_bots() {
    // 1. Salir si la función está desactivada o no aplica a esta petición.
    if (empty($this->options['enable_bot_verification']) || is_admin() || wp_doing_cron() || (defined('WP_CLI') && WP_CLI)) {
        return;
    }

    $ip = $this->get_client_ip();
    $user_agent = $this->get_user_agent();
    
    // 2. Comprobar si la IP ya ha sido verificada en una petición anterior (cacheado en transient).
    if (get_transient('advaipbl_verified_bot_' . md5($ip))) {
        $this->request_is_asn_whitelisted = true; // Reutilizamos esta bandera para saltar otras comprobaciones.
        return;
    }

    // 3. Realizar la verificación de DNS (solo si el User-Agent parece de un bot conocido).
    $is_verified = $this->bot_verifier->is_verified_bot($ip, $user_agent);

    if ($is_verified) {
        // -- ÉXITO: Es un bot legítimo --
        // Verificar si el usuario quiere bloquearlo explícitamente
            $blocked_uas = get_option('advaipbl_blocked_user_agents', []);
            foreach ($blocked_uas as $blocked_ua) {
                // Eliminar comentarios
                $blocked_ua = trim(preg_replace('/#.*$/', '', $blocked_ua));
                if (!empty($blocked_ua) && stripos($user_agent, $blocked_ua) !== false) {
                    // El usuario lo ha bloqueado explícitamente. NO damos inmunidad.
                    // Dejamos que siga el flujo normal, donde será bloqueado por la regla de User-Agent.
                    return; 
                }
            }

            // Si no está bloqueado explícitamente, damos inmunidad y cacheamos
            set_transient('advaipbl_verified_bot_' . md5($ip), true, DAY_IN_SECONDS);
            $this->request_is_asn_whitelisted = true;

        } elseif ($this->bot_verifier->is_known_bot_impersonator($ip, $user_agent)) {
        // -- FALLO: Es un impostor conocido --
        // Instant Block (Zero Tolerance)
        // Skip scoring system as impersonation is a confirmed threat.
        
        $duration_minutes = 1440; // Default fallback

        // 1. Si el sistema de Puntuación (Threat Scoring) está activo:
        //    a) Registramos los puntos para que conste en el Log de Confianza.
        //    b) Usamos su duración configurada.
        if (!empty($this->options['enable_threat_scoring'])) {
             // Registrar Puntos
             $points_impersonation = (int) ($this->options['score_impersonation'] ?? 100);
             $this->threat_score_manager->increment_score(
                 $ip, 
                 $points_impersonation, 
                 'impersonation', 
                 ['user_agent' => $user_agent]
             );

             // Usar Duración
             $duration_minutes = (int) ($this->options['duration_threat_score'] ?? 1440);
        } else {
             // 2. Si no, usamos la duración configurada para User-Agents "malos" 
             $duration_minutes = (int) ($this->options['duration_user_agent'] ?? 1440);
        }

        $duration_seconds = ($duration_minutes > 0) ? $duration_minutes * 60 : 0; // 0 = Permanent

        $this->block_ip_instantly(
            $ip, 
            'impersonation',
            __('Blocked for impersonating a known crawler.', 'advanced-ip-blocker'),
            [
                'impersonated_user_agent' => $user_agent,
                'uri' => $this->get_current_request_uri()
            ],
            $context = 'frontend_block',
            $duration_seconds // Pass explicit duration
        );
    }
} 
	  
     /**
     * Se ejecuta en un hook muy temprano para comprobar la firma de la petición.
     * Si la firma es maliciosa, sirve un desafío JavaScript.
     */
         public function check_for_malicious_signature() {
		if ($this->is_request_uri_excluded()) { return; }	
		if ($this->request_is_asn_whitelisted) { return; }
		
        // Excluir AJAX, JSON, Cron y procesos internos (ej: Elementor, WP Dashboard)
        if (wp_doing_ajax() || wp_is_json_request() || is_admin() || wp_doing_cron() || (defined('WP_CLI') && WP_CLI)) {
            return;
        }
		// Si el usuario acaba de pasar un desafío, le damos un pase de gracia de 15s.
        if (get_transient('advaipbl_grace_pass_' . md5($this->get_client_ip()))) {
           return;
        }
        if (empty($this->options['enable_signature_blocking'])) {
            return;
        }

        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        if (isset($_POST['_advaipbl_js_token'])) {
    // Parámetros para el desafío de firmas: cookie 'advaipbl_js_verified', duración 4 horas.
    $this->js_challenge_manager->verify_challenge('advaipbl_js_verified', 4 * HOUR_IN_SECONDS);
}
        if (isset($_COOKIE['advaipbl_js_verified']) && $_COOKIE['advaipbl_js_verified'] === '1') {
            return;
        }
        
        $signature_hash = $this->fingerprint_manager->generate_signature();

        global $wpdb;
        $signatures_table = $wpdb->prefix . 'advaipbl_malicious_signatures';
        
        // Fix: Check if table exists to avoid fatal error on fresh install
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        if ($wpdb->get_var("SHOW TABLES LIKE '$signatures_table'") != $signatures_table) {
            return;
        }

        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $is_malicious = $wpdb->get_var($wpdb->prepare(
            "SELECT id FROM {$signatures_table} WHERE signature_hash = %s AND expires_at > %d",
            $signature_hash,
            time()
        ));

        if ($is_malicious) {
            // 1. Registramos el evento aquí, en el punto de decisión.
            $this->log_specific_error(
                'signature_challenge', 
                $this->get_client_ip(), 
                [
                    'signature_hash' => $signature_hash,
                    'uri' => $this->get_current_request_uri()
                ], 
                'warning'
            );
            
            // 2. Luego, servimos el desafío.
            $mode = $this->options['signature_challenge_mode'] ?? 'managed';
            $this->js_challenge_manager->serve_challenge('signature', $mode);
        }
    }
	
        /**
     * Comprueba si el visitante proviene de un país que requiere un desafío geográfico.
     * Se ejecuta en un hook 'init' temprano.
     */
    public function check_for_geo_challenge() {
		if ($this->is_request_uri_excluded()) { return; }
        if (empty($this->options['enable_geo_challenge'])) {
            return;
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        if (isset($_POST['_advaipbl_challenge_type']) && $_POST['_advaipbl_challenge_type'] === 'geo_challenge') {
            $duration_hours = (int)($this->options['geo_challenge_cookie_duration'] ?? 24);
            $duration_seconds = ($duration_hours > 0) ? $duration_hours * HOUR_IN_SECONDS : 0;
            $this->js_challenge_manager->verify_challenge('advaipbl_js_verified', $duration_seconds);
        }
        if (isset($_COOKIE['advaipbl_js_verified']) && $_COOKIE['advaipbl_js_verified'] === '1') {
            return;
        }
        
        $ip = $this->get_client_ip();

        if (get_transient('advaipbl_grace_pass_' . md5($ip))) {
            return;
        }
        
        if ($this->request_is_asn_whitelisted || wp_doing_cron() || is_admin() || (defined('WP_CLI') && WP_CLI) || $this->is_whitelisted($ip)) {
            return;
        }

        $challenged_countries = $this->options['geo_challenge_countries'] ?? [];
        if (empty($challenged_countries)) {
            return;
        }

        $location = $this->geolocation_manager->fetch_location($ip);
        if ($location && !empty($location['country_code'])) {
            if (in_array($location['country_code'], $challenged_countries, true)) {
                $this->log_specific_error(
                    'geo_challenge', 
                    $ip, 
                    [
                        'country' => $location['country'] ?? $location['country_code'],
                        'uri' => $this->get_current_request_uri()
                    ], 
                    'warning'
                );
                
                $mode = $this->options['geo_challenge_mode'] ?? 'managed';
                $this->js_challenge_manager->serve_challenge('geo_challenge', $mode);
            }
        }
    }



     

     /**
     * Envía notificaciones (Email/Push) cuando una nueva firma maliciosa es identificada.
     *
     * @param string $signature_hash El hash de la firma.
     * @param string $reason La razón por la que fue marcada.
     * @param string $user_agent El User-Agent de ejemplo asociado a la firma.
     */
    /**
     * Envía notificaciones (Email/Push) cuando una nueva firma maliciosa es identificada.
     */
    public function send_signature_flagged_notification($signature_hash, $reason, $user_agent = 'N/A') {
        if ( isset($this->notification_manager) ) {
            $this->notification_manager->send_signature_flagged_notification($signature_hash, $reason, $user_agent);
        }
    }

    /**
     * Callback para el evento de cron que ejecuta el decaimiento de la puntuación de amenaza.
     */
    public function execute_threat_score_decay() {
        // Solo se ejecuta si el sistema de puntuación está activado.
        if (empty($this->options['enable_threat_scoring'])) {
            return;
        }
        
        $decay_points = (int) ($this->options['score_decay_points'] ?? 1);
        $decay_frequency_hours = (int) ($this->options['score_decay_frequency'] ?? 1);
        $inactive_for_seconds = $decay_frequency_hours * HOUR_IN_SECONDS;
        
        if ($decay_points > 0 && $decay_frequency_hours > 0) {
            $result = $this->threat_score_manager->decay_scores($decay_points, $inactive_for_seconds);
            
            if (($result['updated'] ?? 0) > 0 || ($result['deleted'] ?? 0) > 0) {
                
                $log_message = sprintf( /* translators: 1: Number of scores reduced, 2: Number of scores reset to zero. */
                    __('Threat score decay process ran. Reduced: %1$d IPs, Reset: %2$d IPs.', 'advanced-ip-blocker'),
                    $result['updated'],
                    $result['deleted']
                );
                $this->log_event($log_message, 'info');
            }
        }
    }
	
	 /**
     * Callback para el evento de cron que ejecuta el análisis de firmas de ataque.
     */
    public function execute_signature_analysis() {
        if (empty($this->options['enable_signature_analysis'])) {
            return;
        }

        $ip_threshold = (int) ($this->options['signature_ip_threshold'] ?? 5);
        $analysis_window_hours = (int) ($this->options['signature_analysis_window'] ?? 1);
        $rule_ttl_hours = (int) ($this->options['signature_rule_ttl'] ?? 24);

        $this->fingerprint_manager->analyze_and_flag_signatures(
            $ip_threshold,
            $analysis_window_hours * HOUR_IN_SECONDS,
            $rule_ttl_hours * HOUR_IN_SECONDS
        );
    }

     /**
     * Registra el endpoint de la API REST para el feed de ataques en vivo.
     */
    public function register_live_feed_api_endpoint() {
        if ( ! isset($this->live_feed_manager) ) {
             $this->live_feed_manager = new ADVAIPBL_Live_Feed_Manager($this);
        }
        $this->live_feed_manager->register_api_endpoint();
    }

/**
 * Callback para el endpoint de la API. Devuelve los últimos ataques.
 *
 * @param WP_REST_Request $request
 * @return WP_REST_Response
 */
public function get_live_attacks_for_feed(WP_REST_Request $request) {
    if ( ! isset($this->live_feed_manager) ) {
         $this->live_feed_manager = new ADVAIPBL_Live_Feed_Manager($this);
    }
    return $this->live_feed_manager->get_live_attacks($request);
}

     /**
     * Endpoint de la API REST para obtener un nonce fresco para el feed en vivo.
     * Esto evita problemas de caché de página.
     */
    public function get_live_feed_nonce() {
        if ( ! isset($this->live_feed_manager) ) {
             $this->live_feed_manager = new ADVAIPBL_Live_Feed_Manager($this);
        }
        return $this->live_feed_manager->get_nonce();
    }

     /**
     * Función del shortcode [advaipbl_live_feed].
     * Genera el HTML y el CSS necesario para el feed, y encola el script JS.
     *
     * @param array $atts Atributos del shortcode.
     * @return string El HTML y CSS para el feed.
     */
    public function render_live_feed_shortcode($atts) {
        if ( ! isset($this->live_feed_manager) ) {
             $this->live_feed_manager = new ADVAIPBL_Live_Feed_Manager($this);
        }
        return $this->live_feed_manager->render_shortcode($atts);
    }

   /**
   * Detecta y registra las ejecuciones de WP-Cron.
   */
    public function log_wp_cron_execution() {
        $is_doing_cron = ( defined( 'DOING_CRON' ) && DOING_CRON );
        $is_cron_url = ( strpos($this->get_current_request_uri(), 'wp-cron.php') !== false );

        if ( $is_doing_cron || $is_cron_url ) {
            $ip = $this->get_client_ip();
            
            $transient_key = 'advaipbl_cron_log_lock_' . md5($ip);
            if ( false !== get_transient($transient_key) ) {
                return;
            }
            set_transient($transient_key, true, 60);

            global $wpdb;
            $table_name = $wpdb->prefix . 'advaipbl_logs';
            
            $cron_array = _get_cron_array();
            $due_hooks = [];
            if ( is_array( $cron_array ) ) {
                $current_time = time();
                foreach ( $cron_array as $timestamp => $hooks ) {
                    if ( $timestamp <= $current_time ) {
                        foreach ( $hooks as $hook_name => $events ) {
                            $due_hooks[] = $hook_name;
                        }
                    }
                }
            }
            $due_hooks = array_unique( $due_hooks );
            
            $server_ip = $this->get_server_ip();
            $source = 'External'; // Por defecto, asumimos que es externa.
            if ( $ip === $server_ip || $ip === '127.0.0.1' || $ip === '::1' ) {
                $source = 'Server'; // Si coincide con la IP del servidor o localhost, es interna.
            }

            $details = [
                'url'        => $this->get_current_request_uri(),
				'uri'        => $this->get_current_request_uri(),
                'method'     => $this->get_request_method(),
                'user_agent' => $this->get_user_agent(),
                'due_hooks'  => $due_hooks,
                'source'     => $source, // Añadimos la nueva información
            ];

            @$wpdb->insert(
                $table_name,
                [
                    'timestamp' => current_time('mysql', 1),
                    'ip'        => $ip,
                    'log_type'  => 'wp_cron',
                    'level'     => 'info',
                    'message'   => __('WP-Cron execution triggered.', 'advanced-ip-blocker'),
                    'details'   => wp_json_encode($details)
                ]
            );
        }
    }
	
     /**
     * Enqueues the Google reCAPTCHA API script on the login page.
     */
      public function enqueue_recaptcha_script() {
    $version = $this->options['recaptcha_version'] ?? 'v3';
    $site_key = $this->options['recaptcha_site_key'] ?? '';

    // La comprobación de si la clave está vacía ya se hace en add_hooks,
    // pero una doble comprobación no hace daño.
    if (empty($site_key)) {
        return;
    }

    $script_url = 'https://www.google.com/recaptcha/api.js';
    if ('v3' === $version) {
        $script_url = add_query_arg('render', $site_key, $script_url);
    }

    // phpcs:ignore WordPress.WP.EnqueuedResourceParameters.MissingVersion
    wp_enqueue_script(
        'google-recaptcha',
        $script_url,
        array(),
        null,
        true
    );
}

    /**
    * Se dispara cuando las reglas del WAF son actualizadas desde la página de ajustes.
    * Registra el evento en el log general.
    *
    * @param mixed $old_value El valor antiguo de la opción.
    * @param mixed $new_value El nuevo valor de la opción.
    */
     public function on_waf_rules_update($old_value, $new_value) {
    // Solo registramos si el valor ha cambiado realmente.
    if ($old_value !== $new_value) {
        $message = sprintf(
            /* translators: %s: El nombre de usuario del administrador que realizó el cambio. */
            __('WAF rules list updated by %s.', 'advanced-ip-blocker'),
            $this->get_current_admin_username()
        );
        $this->log_event($message, 'info');
    }
}

/**
 * Descarga y procesa la lista Spamhaus ASN DROP y la guarda en la base de datos.
 * Es llamada por el WP-Cron y por la acción de refresco manual.
 */
public function update_spamhaus_list() {
    $url = 'https://www.spamhaus.org/drop/asndrop.json';
    $response = wp_remote_get($url, ['timeout' => 15]);

    if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
        $error_message = is_wp_error($response) ? $response->get_error_message() : 'HTTP ' . wp_remote_retrieve_response_code($response);
        $this->log_event(sprintf('Failed to download Spamhaus ASN list. Error: %s', $error_message), 'error');
        return;
    }

    $body_string = wp_remote_retrieve_body($response);
    
    // El archivo de Spamhaus es una secuencia de objetos JSON, no un único array JSON.
    // Lo dividimos en objetos individuales.
    // Usamos una expresión regular para encontrar cada objeto JSON { ... }
    preg_match_all('/\{.*?\}/', $body_string, $matches);

    if (empty($matches[0])) {
        $this->log_event('Failed to parse Spamhaus ASN list: No valid JSON objects found in the response.', 'error');
        return;
    }
    
    $json_objects = $matches[0];
    $asns = [];

    foreach ($json_objects as $json_string) {
        $entry = json_decode($json_string, true);
        if (json_last_error() === JSON_ERROR_NONE && isset($entry['asn'])) {
            // El formato es correcto y tiene la clave 'asn'.
            $asns[] = 'AS' . $entry['asn'];
        }
    }

    if (empty($asns)) {
        $this->log_event('Spamhaus ASN list was parsed but no ASN entries were extracted.', 'warning');
        return;
    }

    update_option('advaipbl_spamhaus_asn_list', array_unique($asns));
    update_option('advaipbl_spamhaus_last_update', time());
    
    $this->log_event(sprintf('Successfully updated Spamhaus ASN list with %d entries.', count($asns)), 'info');
}

public function handle_spamhaus_refresh_action() {
    if (!current_user_can('manage_options') || !wp_verify_nonce(sanitize_text_field(wp_unslash($_GET['_wpnonce'] ?? '')), 'advaipbl-refresh-spamhaus')) {
        wp_die('Security check failed.');
    }
    $this->update_spamhaus_list();
    set_transient(self::TRANSIENT_ADMIN_NOTICE, ['message' => __('Spamhaus ASN list has been updated.', 'advanced-ip-blocker'), 'type' => 'success'], 30);
    wp_safe_redirect(wp_get_referer());
    exit;
}

/**
 * Displays the reCAPTCHA field on the login form.
 */
public function display_recaptcha_field() {
    $site_key = $this->options['recaptcha_site_key'] ?? '';
    $version = $this->options['recaptcha_version'] ?? 'v3';
    
    if ('v2' === $version) {
        echo '<div class="g-recaptcha" data-sitekey="' . esc_attr($site_key) . '" style="margin-bottom: 15px;"></div>';
    } else {
        echo '<input type="hidden" id="g-recaptcha-response" name="g-recaptcha-response">';
        ?>
        <script type="text/javascript">
            document.addEventListener('DOMContentLoaded', function() {
                grecaptcha.ready(function() {
                    grecaptcha.execute('<?php echo esc_js($site_key); ?>', {action: 'login'}).then(function(token) {
                        var recaptchaResponse = document.getElementById('g-recaptcha-response');
                        if (recaptchaResponse) {
                           recaptchaResponse.value = token;
                        }
                    });
                });
            });
        </script>
        <?php
    }
}

/**
 * Validates the reCAPTCHA response during the authentication process.
 *
 * @param WP_User|WP_Error|null $user     User object or error.
 * @param string|null           $username The submitted username.
 * @param string|null           $password The submitted password.
 * @return WP_User|WP_Error User object if successful, WP_Error on failure.
 */
public function validate_recaptcha_response($user, $username, $password) {
    if (is_wp_error($user)) {
        return $user;
    }

    $secret_key = $this->options['recaptcha_secret_key'] ?? '';   
    // La comprobación principal ya se hace en add_hooks,
    // pero si alguien modificara la opción mientras tanto, esto es un seguro.
    if (empty($secret_key)) {
        return $user;
    }

    // FIX: XML-RPC requests cannot perform reCAPTCHA validation (no JS).
    // Allow them to bypass this check to prevent infinite authentication loops.
    if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
        return $user;
    }

    // phpcs:ignore WordPress.Security.NonceVerification.Missing
    $recaptcha_response = isset($_POST['g-recaptcha-response']) ? sanitize_text_field(wp_unslash($_POST['g-recaptcha-response'])) : '';
    if (empty($recaptcha_response)) {
        return new WP_Error('recaptcha_empty', __('<strong>ERROR</strong>: Please complete the reCAPTCHA verification.', 'advanced-ip-blocker'));
    }

    $token = $recaptcha_response;
    $visitor_ip = $this->get_client_ip(); 

    $response = wp_remote_post('https://www.google.com/recaptcha/api/siteverify', array(
        'body' => array(
            'secret'   => $secret_key,
            'response' => $token,
            'remoteip' => $visitor_ip,
        ),
    ));

    if (is_wp_error($response)) {
        return new WP_Error('recaptcha_api_error', __('<strong>ERROR</strong>: Could not connect to the reCAPTCHA service.', 'advanced-ip-blocker'));
    }

    $result = json_decode(wp_remote_retrieve_body($response), true);

    if (!isset($result['success']) || true !== $result['success']) {
        return new WP_Error('recaptcha_failed', __('<strong>ERROR</strong>: reCAPTCHA verification failed. Please try again.', 'advanced-ip-blocker'));
    }
    
    $version = $this->options['recaptcha_version'] ?? 'v3';
    if ('v3' === $version) {
        $threshold = (float) ($this->options['recaptcha_score_threshold'] ?? 0.5);
        if (!isset($result['score']) || $result['score'] < $threshold) {
             return new WP_Error('recaptcha_low_score', __('<strong>ERROR</strong>: Your action was blocked as it was flagged as automated.', 'advanced-ip-blocker'));
        }
    }
    
    return $user;
}

    /**
    * Detecta plugins activos que probablemente usan la interfaz XML-RPC.
    *
    * Utiliza una combinación de una lista de plugins conocidos y un análisis de los hooks de XML-RPC.
    *
    * @return array Un array con los nombres de los plugins detectados. Vacío si no se encuentra ninguno.
    */
    public function get_xmlrpc_dependent_plugins() {
    $dependent_plugins = [];
    $active_plugins = get_option('active_plugins');

    // 1. Lista de plugins conocidos que dependen de XML-RPC.
    $known_slugs = [
    'jetpack/jetpack.php',
    // Si encuentras más en el futuro, como la app de WooCommerce si usa un plugin puente.
    'xmlrpc-debugger/xmlrpc-debugger.php' 
    ];

    foreach ($known_slugs as $slug) {
        if (in_array($slug, $active_plugins, true)) {
            $plugin_path = WP_PLUGIN_DIR . '/' . $slug;
            if (file_exists($plugin_path)) {
                $plugin_data = get_plugin_data($plugin_path);
                if (!empty($plugin_data['Name'])) {
                    $dependent_plugins[$slug] = $plugin_data['Name'];
                }
            }
        }
    }

    // 2. Análisis de Hooks (Heurística).
    // Buscamos plugins que se enganchen a los eventos de XML-RPC.
    global $wp_filter;
    $xmlrpc_hooks = [
        'xmlrpc_methods',
        'xmlrpc_call',
        'xmlrpc_call_success',
        'xmlrpc_call_failure',
        'xmlrpc_before_insert_post',
    ];
    
    foreach ($xmlrpc_hooks as $hook_name) {
        if (isset($wp_filter[$hook_name])) {
            foreach ($wp_filter[$hook_name]->callbacks as $priority => $callbacks) {
                foreach ($callbacks as $callback) {
                    $function = $callback['function'];
                    $reflection = null;
                    
                    try {
                        if (is_array($function) && is_object($function[0])) {
                            $reflection = new ReflectionClass($function[0]);
                        } elseif (is_string($function) && function_exists($function)) {
                            $reflection = new ReflectionFunction($function);
                        }
                    } catch (ReflectionException $e) {
                        // Ignorar funciones/clases que no se pueden reflejar (ej. closures)
                        continue;
                    }

                    if ($reflection) {
                        $file_path = $reflection->getFileName();
                        // Comprobamos si la ruta del archivo está dentro del directorio de plugins.
                        if ($file_path && strpos($file_path, WP_PLUGIN_DIR) !== false) {
                            $plugin_dir_path = str_replace('\\', '/', WP_PLUGIN_DIR);
                            $file_path = str_replace('\\', '/', $file_path);
                            $relative_path = ltrim(str_replace($plugin_dir_path, '', $file_path), '/');
                            $plugin_slug_parts = explode('/', $relative_path);
                            $plugin_folder = $plugin_slug_parts[0];

                            // Buscamos el nombre real del plugin para no mostrar solo el slug.
                            foreach ($active_plugins as $active_plugin_slug) {
                                if (strpos($active_plugin_slug, $plugin_folder) === 0) {
                                    if (!isset($dependent_plugins[$active_plugin_slug])) {
                                        $plugin_data = get_plugin_data(WP_PLUGIN_DIR . '/' . $active_plugin_slug);
                                        if (!empty($plugin_data['Name'])) {
                                            $dependent_plugins[$active_plugin_slug] = $plugin_data['Name'];
                                        }
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    return array_values($dependent_plugins);
}

/**
 * Obtiene el número de IPs/rangos bloqueados.
 * Cachea el resultado para mejorar el rendimiento.
 *
 * @return int El número total de entradas de IP bloqueadas.
 */
public function get_blocked_count() {
    if ( null !== $this->blocked_count ) {
        return $this->blocked_count;
    }

    // Usamos la caché de objetos de WP para un mejor rendimiento
    $count = wp_cache_get('blocked_ips_count', 'advaipbl');
    if (false === $count) {
        $this->limpiar_ips_expiradas(); // La limpieza es crucial antes de contar
        global $wpdb;
        $table_name = $wpdb->prefix . 'advaipbl_blocked_ips';
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $count = (int) $wpdb->get_var("SELECT COUNT(id) FROM {$table_name}");
        wp_cache_set('blocked_ips_count', $count, 'advaipbl', 300); // Cache por 5 minutos
    }
    
    $this->blocked_count = $count;
    return $this->blocked_count;
}

    /**
 * Obtiene el número de firmas de ataque activas.
 * @return int
 */
public function get_blocked_signatures_count() {
    global $wpdb;
    $table_name = $wpdb->prefix . 'advaipbl_malicious_signatures';
    // Usamos cache para evitar consultas repetidas en la misma petición
    $count = wp_cache_get('blocked_signatures_count', 'advaipbl');
    if (false === $count) {
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $count = (int) $wpdb->get_var($wpdb->prepare("SELECT COUNT(id) FROM {$table_name} WHERE expires_at > %d", time()));
        wp_cache_set('blocked_signatures_count', $count, 'advaipbl', 300); // Cache por 5 minutos
    }
    return $count;
}

/**
 * Obtiene el número de endpoints actualmente en lockdown.
 * @return int
 */
public function get_blocked_endpoints_count() {
    global $wpdb;
    $table_name = $wpdb->prefix . 'advaipbl_endpoint_lockdowns';
    $count = wp_cache_get('blocked_endpoints_count', 'advaipbl');
    if (false === $count) {
        // Primero, limpiamos los expirados para un conteo preciso
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $wpdb->query($wpdb->prepare("DELETE FROM {$table_name} WHERE expires_at <= %d", time()));
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $count = (int) $wpdb->get_var("SELECT COUNT(id) FROM {$table_name}");
        wp_cache_set('blocked_endpoints_count', $count, 'advaipbl', 300); // Cache por 5 minutos
    }
    return $count;
}

    /**
     * Gets the username of the current logged-in administrator.
     *
     * @return string The username or a default string if not available.
     */
    public function get_current_admin_username() {
        $user = wp_get_current_user();
        // Si el usuario existe y tiene un ID, devuelve su login. Si no, devuelve un texto genérico.
        return ( $user && $user->ID ) ? $user->user_login : __( 'an unknown user', 'advanced-ip-blocker' );
    }

    /**
    * Añade una entrada (IP o rango) a la whitelist y se asegura de que sea eliminada
    * de todas las listas de bloqueo. Este es el método centralizado para esta acción.
    *
    * @param string $entry_to_whitelist La IP o rango a añadir a la whitelist.
    * @param string $detail Una descripción de por qué se añadió.
    * @return bool True si la entrada se añadió con éxito, false si ya existía.
    */
    public function add_to_whitelist_and_unblock( $entry_to_whitelist, $detail ) {
    if ( ! $this->is_valid_ip_or_range( $entry_to_whitelist ) ) {
        return false;
    }

    $whitelist = get_option( self::OPTION_WHITELIST, [] );
    if ( array_key_exists( $entry_to_whitelist, $whitelist ) ) {
        return false;
    }
    
    $whitelist[ $entry_to_whitelist ] = [ 'timestamp' => time(), 'detail' => $detail ];
    update_option( self::OPTION_WHITELIST, $whitelist );

    wp_cache_delete( self::OPTION_WHITELIST, 'options' );
        // FIX: Always unblock from DB/Htaccess/Cloudflare (IPs AND Ranges)
        $this->desbloquear_ip( $entry_to_whitelist );

        // Legacy Cleanup: Only for ranges (to clean old wp_options arrays if they exist)
        if ( ! filter_var( $entry_to_whitelist, FILTER_VALIDATE_IP ) ) {
            // Usar el mapa de constantes para limpiar el rango de TODAS las listas.
            $option_key_map = [
                'geoblock'     => self::OPTION_BLOCKED_GEO,
                'honeypot'     => self::OPTION_BLOCKED_HONEYPOT,
                'user_agent'   => self::OPTION_BLOCKED_USER_AGENT,
                'manual'       => self::OPTION_BLOCKED_MANUAL,
                '404'          => self::OPTION_BLOCKED_404,
                '403'          => self::OPTION_BLOCKED_403,
                'login'        => self::OPTION_BLOCKED_LOGIN,
                'waf'          => self::OPTION_BLOCKED_WAF,
                'rate_limit'   => self::OPTION_BLOCKED_RATE_LIMIT,
                'asn'          => self::OPTION_BLOCKED_ASN,
                'xmlrpc_block' => self::OPTION_BLOCKED_XMLRPC,
                'threat_score' => self::OPTION_BLOCKED_THREAT_SCORE,
            ];

            foreach ( $option_key_map as $type => $option_key ) {
                $list = get_option( $option_key, [] );
                if ( is_array($list) && array_key_exists( $entry_to_whitelist, $list ) ) {
                    unset( $list[ $entry_to_whitelist ] );
                    update_option( $option_key, $list );
                }
            }
        }/* translators: 1: The whitelisted IP/range, 2: The admin username. */
    $this->log_event( sprintf( __( 'Entry %1$s added to whitelist by %2$s.', 'advanced-ip-blocker' ), $entry_to_whitelist, $this->get_current_admin_username() ), 'info', is_array($entry_to_whitelist) ? wp_json_encode($entry_to_whitelist) : $entry_to_whitelist );
    
    return true;
}

	public function handle_clear_cache_action() {
        if (!isset($_GET['_wpnonce']) || !wp_verify_nonce(sanitize_text_field(wp_unslash($_GET['_wpnonce'])), 'advaipbl_clear_location_cache_nonce')) {
            wp_die('Invalid nonce.');
        }
        if (!current_user_can('manage_options')) {
            wp_die('Permission denied.');
        }
        // Vaciamos la tabla de caché.
        global $wpdb;
        $table_name = $wpdb->prefix . 'advaipbl_cache';
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $wpdb->query("TRUNCATE TABLE `{$table_name}`");

        /* translators: %s: Admin username. */
        $this->log_event( sprintf( __( 'User session location cache manually cleared by %s.', 'advanced-ip-blocker' ), $this->get_current_admin_username() ), 'info' );
        
        set_transient('advaipbl_admin_notice', ['message' => __('Location cache has been cleared.', 'advanced-ip-blocker'), 'type' => 'success'], 30);
        
        wp_safe_redirect(wp_get_referer());
        exit;
    }


	
	 /**
     * Handles the request to send a test email from the settings page.
     */

    public function handle_send_test_email() {
        // 1. Security check: Nonce and user permissions.
        if ( ! isset( $_GET['_wpnonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_GET['_wpnonce'] ) ), 'advaipbl_send_test_email_nonce' ) ) {
            wp_die( 'Invalid nonce.' );
        }
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( 'Permission denied.' );
        }

        // 2. Preparar variables
        $to = ! empty( $this->options['notification_email'] ) && is_email( $this->options['notification_email'] ) ? $this->options['notification_email'] : get_option( 'admin_email' );
        $site_name = get_bloginfo( 'name' );
        $settings_url = admin_url( 'options-general.php?page=advaipbl_settings_page' );

        if ( isset($this->notification_manager) ) {
            $sent = $this->notification_manager->send_test_email($to);
        } else {
             $sent = false;
        }

        // 5. Lógica de notificación y redirección
        if ( $sent ) {
            $message = __( 'The setup guide has been sent successfully to your configured email address.', 'advanced-ip-blocker' );
            $type    = 'success';
            /* translators: 1: Recipient's email address, 2: Admin username */
            $this->log_event( sprintf( __( 'Setup guide sent to %1$s by %2$s.', 'advanced-ip-blocker' ), $to, $this->get_current_admin_username() ), 'info' );
        } else {
            $message = __( 'Failed to send the setup guide email. Please check your site\'s email configuration.', 'advanced-ip-blocker' );
            $type    = 'error';
            /* translators: 1: Recipient's email address, 2: Admin username */
            $this->log_event( sprintf( __( 'FAILED to send setup guide to %1$s. Action by %2$s.', 'advanced-ip-blocker' ), $to, $this->get_current_admin_username() ), 'error' );
        }
        set_transient( 'advaipbl_admin_notice', [ 'message' => $message, 'type' => $type ], 30 );
        wp_safe_redirect( wp_get_referer() );
        exit;
    }

    public function handle_send_test_push() {
        check_admin_referer('advaipbl_send_test_push_nonce');
        
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( esc_html__( 'Cheatin&#8217; uh?', 'advanced-ip-blocker' ) );
        }

		$webhook_urls_str = $this->options['push_webhook_urls'] ?? '';
        $webhook_urls = array_filter(array_map('trim', explode("\n", $webhook_urls_str)));
		
		if (empty($webhook_urls)) {
            wp_die(
                '<h1>' . esc_html__('No Webhooks Configured', 'advanced-ip-blocker') . '</h1>' .
                '<p>' . esc_html__('Please add at least one Webhook URL in the settings before sending a test.', 'advanced-ip-blocker') . '</p>' .
                '<p><a href="' . esc_url(admin_url('admin.php?page=advaipbl_settings_page')) . '" class="button">' . esc_html__('Go Back', 'advanced-ip-blocker') . '</a></p>'
            );
        }

        if ( isset($this->notification_manager) && $this->notification_manager->send_test_push() ) {
             // Assuming success if it returns true
            $sent_count = count($webhook_urls);
            $failed_count = 0;
        } else {
            $sent_count = 0;
            $failed_count = count($webhook_urls);
        }

        // Redireccionar de vuelta con un mensaje de éxito
        wp_safe_redirect( add_query_arg( 
            ['page' => 'advaipbl_settings_page', 'settings-updated' => 'true', 'push-test-sent' => $sent_count, 'push-test-failed' => $failed_count], 
            admin_url( 'admin.php' ) 
        ) );
        exit;
    }
    
    /**
     * Executes the scheduled deep scan and sends the email report.
     * @param bool $is_manual Whether the scan was triggered manually.
     */
    public function execute_scheduled_scan($is_manual = false) {
        $email = $this->options['scan_notification_email'] ?? get_option('admin_email');
        if (empty($email)) {
             $email = get_option('admin_email');
        }
        
        $this->site_scanner->run_full_scan_and_email($email, $is_manual);
    }
    
    /**
     * Handles the manual "Run Scan Now" action from the settings page.
     */
    public function handle_run_manual_scan() {
        check_admin_referer('advaipbl_run_manual_scan_nonce');
        
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( esc_html__( 'Cheatin&#8217; uh?', 'advanced-ip-blocker' ) );
        }
        
        $this->execute_scheduled_scan(true);
        
        wp_safe_redirect( add_query_arg( 
            [
                'page' => 'advaipbl_settings_page', 
                'tab' => 'settings',
                'sub-tab' => 'general_settings',
                'scan-sent' => 'true'
            ], 
            admin_url( 'admin.php' ) 
        ) . '#section-notifications' );
        exit;
    }

        public function load_admin_scripts($hook) {
        // Cargar scripts en nuestras páginas Y en las páginas de perfil/edición de usuario.
        $allowed_hooks = ['profile.php', 'user-edit.php'];
        $is_plugin_page = strpos($hook, 'advaipbl_settings_page') !== false || strpos($hook, 'advaipbl-setup-wizard') !== false;

        if ( !in_array($hook, $allowed_hooks) && !$is_plugin_page ) {
            return;
        }



        // --- 1. Determinar la pestaña y sub-pestaña activas ---
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $current_page_slug = isset($_GET['page']) ? sanitize_key($_GET['page']) : '';
        
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        if (isset($_GET['tab'])) {
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            $active_main_tab = sanitize_key($_GET['tab']);
        } else {
            // Si no hay tab, intentamos deducirlo del page slug (Menu Navigation fix)
            $page_slug_to_tab_map = [
                'advaipbl_settings_page'           => 'dashboard',
                'advaipbl_settings_page-settings'  => 'settings',
                'advaipbl_settings_page-security-headers' => 'security_headers',
                'advaipbl_settings_page-rules'     => 'rules',
                'advaipbl_settings_page-ip-management' => 'ip_management',
                'advaipbl_settings_page-scanner'   => 'scanner',
                'advaipbl_settings_page-logs'      => 'logs',
                'advaipbl_settings_page-about'     => 'about',
            ];
            
            if (isset($page_slug_to_tab_map[$current_page_slug])) {
                $active_main_tab = $page_slug_to_tab_map[$current_page_slug];
            } else {
                $active_main_tab = 'dashboard';
            }
        }
        
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $active_sub_tab = isset($_GET['sub-tab']) ? sanitize_key($_GET['sub-tab']) : null;

        // Si no hay sub-pestaña en la URL, la deducimos de la pestaña principal.
        if (is_null($active_sub_tab)) {
            switch ($active_main_tab) {
                case 'dashboard':
                    $active_sub_tab = 'main_dashboard';
                    break;
                case 'settings':
                    $active_sub_tab = 'general_settings';
                    break;
                case 'rules':
                    $active_sub_tab = 'waf';
                    break;
                case 'ip_management':
                    $active_sub_tab = 'blocked_ips';
                    break;
                case 'logs':
                    $active_sub_tab = 'security_log';
                    break;
                case 'about':
                    $active_sub_tab = 'credits';
                    break;
                case 'security_headers':
                    $active_sub_tab = 'headers_config';
                    break;
                case 'scanner':
                     $active_sub_tab = 'scan_overview';
                     break;
                default:
                    $active_sub_tab = 'main_dashboard';
            }
        }
        
        // --- 2. Cargar Assets Comunes (siempre necesarios en nuestras páginas) ---
        if ($is_plugin_page || in_array($hook, $allowed_hooks)) {
            $this->session_manager->enqueue_scripts_styles(); // Asumiendo que es necesario en el perfil también.
            wp_enqueue_style( 'advaipbl-styles-main', plugin_dir_url( dirname( __FILE__ ) ) . 'css/advaipbl-styles.css', [], ADVAIPBL_VERSION );
            wp_enqueue_style( 'advaipbl-select2-css', plugin_dir_url( dirname( __FILE__ ) ) . 'assets/css/select2.min.css', [], '4.1.0-rc.0' );
            wp_enqueue_script( 'advaipbl-select2-js', plugin_dir_url( dirname( __FILE__ ) ) . 'assets/js/select2.min.js', [ 'jquery' ], '4.1.0-rc.0', true );
            
            // --- Core JS (Always loaded) ---
            wp_enqueue_script( 'advaipbl-admin-core-js', plugin_dir_url( dirname( __FILE__ ) ) . 'js/admin-core.js', [ 'jquery', 'advaipbl-select2-js' ], ADVAIPBL_VERSION, true );
            
            // --- Modular JS (Conditional) ---
            
            // Rules/Blocked IPs logic
            if ( in_array($active_main_tab, ['rules', 'ip_management']) ) {
                wp_enqueue_script( 'advaipbl-admin-rules-js', plugin_dir_url( dirname( __FILE__ ) ) . 'js/admin-rules.js', [ 'advaipbl-admin-core-js' ], ADVAIPBL_VERSION, true );
            }
            
            // Logs logic
            if ( $active_main_tab === 'logs' || $active_main_tab === 'ip_management' ) {
                wp_enqueue_script( 'advaipbl-admin-logs-js', plugin_dir_url( dirname( __FILE__ ) ) . 'js/admin-logs.js', [ 'advaipbl-admin-core-js' ], ADVAIPBL_VERSION, true );
            }
            
            // Settings logic (Settings page + Profile + Setup Wizard + Scanner + Dashboard/Status)
            if ( $active_main_tab === 'settings' || $active_main_tab === 'dashboard' || $active_main_tab === 'about' || $active_main_tab === 'scanner' || $active_main_tab === 'ip_trust_log' || in_array($hook, $allowed_hooks) || strpos($hook, 'advaipbl-setup-wizard') !== false ) {
                 wp_enqueue_script( 'advaipbl-admin-settings-js', plugin_dir_url( dirname( __FILE__ ) ) . 'js/admin-settings.js', [ 'advaipbl-admin-core-js' ], ADVAIPBL_VERSION, true );
            }
            
            $floating_bar_css = " #advaipbl-floating-save-bar { position: fixed; bottom: 0; left: 160px; right: 0; background-color: #fff; box-shadow: 0 -2px 5px rgba(0,0,0,0.1); padding: 15px 30px; z-index: 999; transition: transform 0.3s ease-in-out; transform: translateY(100%); } #advaipbl-floating-save-bar.advaipbl-save-bar-visible { transform: translateY(0); } .advaipbl-save-bar-content { display: flex; justify-content: space-between; align-items: center; max-width: 1200px; margin: 0 auto; } .advaipbl-save-bar-text { font-size: 1.1em; font-weight: 600; } .advaipbl-save-bar-buttons .button { margin-left: 10px; } @media screen and (max-width: 960px) { #advaipbl-floating-save-bar { left: 36px; } } @media screen and (max-width: 782px) { #advaipbl-floating-save-bar { left: 0; padding: 10px 15px; } .advaipbl-save-bar-text { display: none; } .advaipbl-save-bar-content { justify-content: flex-end; } }";
            wp_add_inline_style('advaipbl-styles-main', $floating_bar_css);
        }

        // --- 3. Cargar Assets Específicos (solo cuando sea necesario) ---
        if ($is_plugin_page) {
            
            // Cargar assets del Dashboard Principal
            if ( 'main_dashboard' === $active_sub_tab ) {
                wp_enqueue_script('chartjs', plugin_dir_url( dirname( __FILE__ ) ) . 'assets/js/chart.min.js', [], '3.9.1', true);
                // phpcs:ignore WordPress.WP.EnqueuedResourceParameters.MissingVersion
                wp_enqueue_style('leaflet-css', plugin_dir_url( dirname( __FILE__ ) ) . 'assets/css/leaflet.css');
                wp_enqueue_script('leaflet-js', plugin_dir_url( dirname( __FILE__ ) ) . 'assets/js/leaflet.js', [], '1.9.4', true);
                // phpcs:ignore WordPress.WP.EnqueuedResourceParameters.MissingVersion
                wp_enqueue_style('leaflet-markercluster-css', plugin_dir_url( dirname( __FILE__ ) ) . 'assets/css/MarkerCluster.css');
                // phpcs:ignore WordPress.WP.EnqueuedResourceParameters.MissingVersion
                wp_enqueue_style('leaflet-markercluster-default-css', plugin_dir_url( dirname( __FILE__ ) ) . 'assets/css/MarkerCluster.Default.css');
                wp_enqueue_script('leaflet-markercluster-js', plugin_dir_url( dirname( __FILE__ ) ) . 'assets/js/leaflet.markercluster.js', ['leaflet-js'], '1.5.3', true);
                wp_enqueue_script('advaipbl-dashboard-js', plugin_dir_url( dirname( __FILE__ ) ) . 'js/advaipbl-dashboard.js', ['jquery', 'chartjs', 'leaflet-markercluster-js', 'advaipbl-admin-core-js'], ADVAIPBL_VERSION, true);
            }

            // Cargar assets de la página "About"
            // STRICT CHECK: Ensure we are explicitly on the about tab to avoid loading Stripe/Sift on other pages (CSP issues)
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            if (isset($_GET['tab']) && $_GET['tab'] === 'about') {
                // phpcs:ignore WordPress.WP.EnqueuedResourceParameters.MissingVersion
                wp_enqueue_script('stripe-buy-button', 'https://js.stripe.com/v3/buy-button.js', [], null, true);
            }
        }
        
        // --- 4. Localizar Datos para JS (siempre necesario en nuestras páginas) ---
        if ($is_plugin_page) {
            // --- Procesar información del servidor ---
            $server_ip = $this->get_server_ip();
            $server_info = [ 'ip' => $server_ip, 'country_code' => '', 'country_name' => '', 'is_whitelisted' => false ];
            if ( $server_ip ) {
                $location = $this->geolocation_manager->fetch_location( $server_ip );
                if ( $location && empty( $location['error'] ) ) {
                    $server_info['country_code'] = $location['country_code'] ?? '';
                    $server_info['country_name'] = $location['country'] ?? '';
                }
                $server_info['is_whitelisted'] = $this->is_whitelisted( $server_ip );
            }

            // --- Procesar información del administrador (usuario actual) ---
            $admin_ip = $this->get_client_ip();
            $admin_info = [ 'ip' => $admin_ip, 'country_code' => '', 'country_name' => '', 'is_whitelisted' => false ];
            if ( $admin_ip && filter_var( $admin_ip, FILTER_VALIDATE_IP ) ) {
                $location = $this->geolocation_manager->fetch_location( $admin_ip );
                if ( $location && empty( $location['error'] ) ) {
                    $admin_info['country_code'] = $location['country_code'] ?? '';
                    $admin_info['country_name'] = $location['country'] ?? '';
                }
                $admin_info['is_whitelisted'] = $this->is_whitelisted( $admin_ip );
            }

            // --- Localizar scripts con datos para el frontend (Attached to Core) ---
            wp_localize_script('advaipbl-admin-core-js', 'advaipbl_admin_data', [
                'counts' => [
                    'blocked' => count( $this->get_all_blocked_entries() ),
                ],
                'geoblock' => [
                    'server'            => $server_info,
                    'admin'             => $admin_info,
                    'blocked_countries' => $this->options['geoblock_countries'] ?? [],
                    'challenged_countries' => $this->options['geo_challenge_countries'] ?? [],
                ],
                'nonces' => [
                    'test_connection'     => wp_create_nonce( 'advaipbl_test_connection_nonce' ),
                    'add_whitelist'       => wp_create_nonce( 'advaipbl_add_whitelist_nonce' ),
                    'export'              => wp_create_nonce( 'advaipbl_export_nonce' ),
                    'clear_log_nonce'     => wp_create_nonce( 'advaipbl_clear_audit_logs_nonce' ),
                    'verify_api'          => wp_create_nonce( 'advaipbl_verify_api_nonce' ),
                    'get_dashboard_stats' => wp_create_nonce( 'wp_ajax_advaipbl_get_dashboard_stats' ),
                    'telemetry' => wp_create_nonce('advaipbl_telemetry_nonce'),
                    'reset_score' => wp_create_nonce('advaipbl_reset_score_nonce'),
                    'get_history' => wp_create_nonce('advaipbl_get_history_nonce'),
                    'delete_signature' => wp_create_nonce('advaipbl_delete_signature_nonce'),
                    'get_signature_details' => wp_create_nonce('advaipbl_get_signature_details_nonce'),
                    'whitelist_signature' => wp_create_nonce('advaipbl_whitelist_signature_nonce'),
					'get_lockdown_details' => wp_create_nonce('advaipbl_get_lockdown_details_nonce'),
					'get_rules_nonce' => wp_create_nonce('advaipbl_get_rules_nonce'),
                    'save_rule_nonce' => wp_create_nonce('advaipbl_save_rule_nonce'),
                    'delete_rule_nonce' => wp_create_nonce('advaipbl_delete_rule_nonce'),
					'bulk_delete_rules_nonce' => wp_create_nonce('advaipbl_bulk_delete_rules_nonce'),
					'reorder_rules_nonce' => wp_create_nonce('advaipbl_reorder_rules_nonce'),
					'verify_abuseipdb' => wp_create_nonce('advaipbl_verify_abuseipdb_nonce'),
                    'run_fim_scan' => wp_create_nonce('advaipbl_run_fim_scan_nonce'),
                    'bulk_import_nonce' => wp_create_nonce('advaipbl_bulk_import_whitelist_nonce'),
                    'bulk_export_nonce' => wp_create_nonce('advaipbl_bulk_export_whitelist_nonce'),
                    'bulk_import_blocked_nonce' => wp_create_nonce('advaipbl_bulk_import_blocked_ips_nonce'),
                    'bulk_export_blocked_nonce' => wp_create_nonce('advaipbl_bulk_export_blocked_ips_nonce'),
                ],
                'text' => [ /* translators: 1: Country, 2:IP. */
                    'server_whitelisted'       => __( 'Info: Your server is located in %1$s and its IP (%2$s) is correctly whitelisted. You can safely block this country.', 'advanced-ip-blocker' ),
                    /* translators: 1: Country, 2:IP. */
					'server_not_whitelisted'   => __( 'CRITICAL WARNING! Your server is located in %1$s and its IP (%2$s) is NOT whitelisted. Blocking this country WILL likely break your site. Please add the server IP to the whitelist BEFORE blocking this country.', 'advanced-ip-blocker' ),
                    /* translators: 1: IP, 2:Country. */
					'admin_whitelisted'        => __( 'Info: Your current IP address (%1$s) from %2$s is whitelisted. You will not be locked out if you block this country.', 'advanced-ip-blocker' ),
                    /* translators: 1: IP, 2:Country. */
					'admin_not_whitelisted'    => __( 'Caution: Your current IP address (%1$s) from %2$s is NOT whitelisted. If you block this country, you may lose access to your admin panel.', 'advanced-ip-blocker' ),
                    /* translators: 1: IP, 2:Country. */
					'remove_server_ip_warning' => __( 'CRITICAL WARNING: This IP (%1$s) belongs to your server, located in a blocked country (%2$s). REMOVING IT FROM THE WHITELIST WILL LIKELY BREAK YOUR SITE!', 'advanced-ip-blocker' ),
                    /* translators: 1: IP, 2:Country. */
					'remove_admin_ip_warning'  => __( 'CAUTION: This is your current IP address (%1$s) from a blocked country (%2$s). REMOVING THIS IP FROM THE WHITELIST MAY LOCK YOU OUT OF YOUR ADMIN PANEL.', 'advanced-ip-blocker' ),
                    'confirm_removal'          => __( 'Are you absolutely sure you want to proceed?', 'advanced-ip-blocker' ),
                    'add_to_whitelist_btn'     => __( 'Add to Whitelist', 'advanced-ip-blocker' ),
                    'adding_to_whitelist'      => __( 'Adding...', 'advanced-ip-blocker' ),
                    'added_to_whitelist'       => __( 'Successfully Added!', 'advanced-ip-blocker' ),
                    'select2_placeholder_block'      => __( 'Search for a country to block...', 'advanced-ip-blocker' ),
                    'select2_placeholder_challenge'  => __( 'Search for a country to challenge...', 'advanced-ip-blocker' ),
                    'verify_api_button'        => __( 'Verify', 'advanced-ip-blocker' ),
                    'verifying_api'            => __( 'Verifying...', 'advanced-ip-blocker' ),
                    'enter_api_key'            => __( 'Please enter an API key.', 'advanced-ip-blocker' ),
                    'ajax_error'               => __( 'AJAX error. Check browser console.', 'advanced-ip-blocker' ),
                    'missing_detail'           => __( 'Please provide a reason/detail for these IPs (Required).', 'advanced-ip-blocker' ),
                    'discard_title'            => __( 'Discard Changes?', 'advanced-ip-blocker' ),
                    'discard_message'          => __( 'You have unsaved changes. Are you sure you want to discard them?', 'advanced-ip-blocker' ),
                    'discard_confirm_btn'      => __( 'Yes, Discard', 'advanced-ip-blocker' ),
                    'attacks_label'            => __( 'attacks', 'advanced-ip-blocker' ),
                    'blocks_label'             => __( 'blocks', 'advanced-ip-blocker' ),
                    'confirm_bulk_action_title' => __( 'Confirm Bulk Action', 'advanced-ip-blocker' ),
                    /* translators: %d: The number IPs that were unblocked. */
					'confirm_bulk_unblock_message' => __( 'Are you sure you want to unblock the selected %d entries? This action cannot be undone.', 'advanced-ip-blocker' ),
                    'confirm_bulk_unblock_button' => __( 'Yes, Unblock Selected', 'advanced-ip-blocker' ),
                    'alert_no_action' => __( 'Please select a bulk action.', 'advanced-ip-blocker' ),
                    'alert_no_items' => __( 'Please select at least one item to apply the action.', 'advanced-ip-blocker' ),
					/* translators: %d: The number IPs that were removed from the whitelist. */
					'confirm_bulk_whitelist_remove_message' => __( 'Are you sure you want to remove the selected %d entries from the whitelist?', 'advanced-ip-blocker' ),
                    'delete_rule_confirm_title' => __( 'Delete Rule?', 'advanced-ip-blocker' ),
                    /* translators: %s: The name of the rule to be deleted. */
                    'delete_rule_confirm_message' => __( 'Are you sure you want to permanently delete the rule "%s"? This action cannot be undone.', 'advanced-ip-blocker' ),
                    'delete_rule_confirm_button' => __( 'Yes, Delete Rule', 'advanced-ip-blocker' ),

                    'bulk_delete_rules_confirm_title' => __( 'Confirm Bulk Deletion', 'advanced-ip-blocker' ),
                    /* translators: %d: The number of rules to be deleted. */
                    'bulk_delete_rules_confirm_message' => __( 'Are you sure you want to delete the selected %d rule(s)? This action cannot be undone.', 'advanced-ip-blocker' ),
                    'bulk_delete_rules_confirm_button' => __( 'Yes, Delete Selected', 'advanced-ip-blocker' ),
					'no_advanced_rules' => __( 'No advanced rules have been created yet.', 'advanced-ip-blocker' ),
                    'could_not_load_rules' => __( 'Could not load rules.', 'advanced-ip-blocker' ),
					
                    'scan_clean_title' => __('No known vulnerabilities found!', 'advanced-ip-blocker'),
                    'scan_clean_desc'  => __('Your plugins appear secure.', 'advanced-ip-blocker'),
					/* translators: %d: The number of  Vulnerabilities Found. */
                    'scan_vuln_title'  => __('%d Vulnerabilities Found!', 'advanced-ip-blocker'),
                    'scan_vuln_desc'   => __('Please update these plugins immediately.', 'advanced-ip-blocker'),
                    'scan_error'       => __('Server error during scan.', 'advanced-ip-blocker'),
                    'scan_checking'    => __('Checking versions against vulnerability database...', 'advanced-ip-blocker'),
					'scan_again'       => __('Scan Again', 'advanced-ip-blocker'),
					
                    'rep_analyzing'    => __('Analyzing...', 'advanced-ip-blocker'),
                    'rep_check_again'  => __('Check Again', 'advanced-ip-blocker'),
                    'rep_clean_title'  => __('Clean Reputation', 'advanced-ip-blocker'),
					/* translators: %s: server IP. */
                    'rep_clean_desc'   => __('Your server IP (%s) is not blacklisted.', 'advanced-ip-blocker'),
                    'rep_listed_title' => __('Issues Found!', 'advanced-ip-blocker'),
					/* translators: %s: server IP. */
                    'rep_listed_desc'  => __('Your server IP (%s) appears on one or more blocklists.', 'advanced-ip-blocker'),
                    'rep_error'        => __('Server error during check.', 'advanced-ip-blocker'),
                    'status_clean'     => __('Clean', 'advanced-ip-blocker'),
                    'status_blacklisted' => __('Blacklisted', 'advanced-ip-blocker'),
                    'status_skipped'   => __('Skipped (Not Configured)', 'advanced-ip-blocker'),
                    'status_warning'   => __('Warning', 'advanced-ip-blocker'),
                    'status_warning'   => __('Warning', 'advanced-ip-blocker'),
                    'status_unknown'   => __('Unknown', 'advanced-ip-blocker'),
                    
                    // FIM Scan Strings
                    'fim_scan_title'   => __('Start File Scan', 'advanced-ip-blocker'),
                    'fim_scan_confirm' => __('Start manual file integrity scan? This may take a few seconds.', 'advanced-ip-blocker'),
                    'fim_scan_btn'     => __('Scan Now', 'advanced-ip-blocker'),
                    'fim_complete_title' => __('Scan Complete', 'advanced-ip-blocker'),
                    'reload_btn'       => __('Reload', 'advanced-ip-blocker'),
                    'scan_error_generic' => __('Error occurred during scan.', 'advanced-ip-blocker'),
                    
                    // 2FA Deactivation Strings
                    'deactivate_2fa_title' => __('Deactivate Two-Factor Authentication?', 'advanced-ip-blocker'),
                    'deactivate_2fa_message' => __('Are you sure you want to deactivate 2FA? Your account will be less secure.', 'advanced-ip-blocker'),
                    'deactivate_2fa_confirm_btn' => __('Yes, Deactivate', 'advanced-ip-blocker'),
				],
				'countries' => $this->get_country_list(),
            ]);
        }
    }
 
    public function detect_http_error_status($status_header, $code) {
        $uri = $this->get_current_request_uri();
        if ( empty($uri) || php_sapi_name() === 'cli' || defined('WP_CLI') ) {
            return $status_header;
        }

        if ($this->request_is_asn_whitelisted) { return $status_header; }	
        if ($this->error_handled_this_request || is_admin()) {
            return $status_header;
        }

    if ($this->is_request_uri_excluded()) {
    return $status_header;
}

    if ($code === 404) {
        $this->error_handled_this_request = true;
        $ip = $this->get_client_ip();
        if ($this->is_whitelisted($ip)) return $status_header;
        
        if (!empty($this->options['enable_honeypot_blocking'])) {
            $honeypot_urls = get_option(self::OPTION_HONEYPOT_URLS, []);
            if (!empty($honeypot_urls)) {
                $requested_url = strtolower($this->get_current_request_uri());
                foreach ($honeypot_urls as $trap_url) {
                    if (!empty($trap_url) && stripos($requested_url, strtolower(trim($trap_url))) !== false) {
                        /* translators: %d: Honeypot URL accessed. */
						$reason = sprintf(__('Honeypot URL accessed: %s', 'advanced-ip-blocker'), $trap_url);
                        // Llamamos a nuestra función central y LUEGO terminamos.
                        $this->handle_threat_event($ip, 'honeypot', $reason, ['url' => $requested_url]);
                        return $status_header; 
                    }
                }
            }
        }

        // --- SMART 404 CHALLENGE ---
        // Si la opción está activada, verificamos si es humano antes de procesar el error 404.
        if (!empty($this->options['enable_404_challenge'])) {
             // Si ya está verificado, pasamos (y se registrará como un 404 normal de humano).
             if (isset($_COOKIE['advaipbl_js_verified']) && $_COOKIE['advaipbl_js_verified'] === '1') {
                 // Humano confirmado. Dejamos que el flujo continúe hacia handle_error('404') abajo.
             } else {
                 // No está verificado. Servimos el desafío e interrumpimos la ejecución.
                 $this->js_challenge_manager->serve_challenge('404_challenge');
                 exit;
             }
        }

    
    // --- DISTRIBUTED LOCKDOWN CHECK (404) ---
    if (!empty($this->options['enable_404_lockdown'])) {
        // 1. Check if Lockdown is currently ACTIVE
        if ($this->is_lockdown_active_for_type('404')) {
             if (isset($_COOKIE['advaipbl_js_verified']) && $_COOKIE['advaipbl_js_verified'] === '1') {
                 // Pass (Human verified previously)
             } else {
                 $this->log_specific_error('endpoint_challenge', $this->get_client_ip(), ['endpoint' => '404', 'reason' => '404 Lockdown Mode Active', 'uri' => $this->get_current_request_uri()], 'warning');
                 $mode = $this->options['lockdown_404_challenge_mode'] ?? 'managed';
                 $this->js_challenge_manager->serve_challenge('404_lockdown', $mode);
                 exit;
             }
        }
        
        // 2. Monitor: Increment counter for this 404 event
        $this->monitor_distributed_attack('404');
    }

    $this->handle_error('404');
} elseif ($code === 403) {
    
    // --- SMART 403 CHALLENGE ---
    if (!empty($this->options['enable_403_challenge'])) {
             if (isset($_COOKIE['advaipbl_js_verified']) && $_COOKIE['advaipbl_js_verified'] === '1') {
                 // Pass
             } else {
                 $this->js_challenge_manager->serve_challenge('403_challenge');
                 exit;
             }
        }

    // --- DISTRIBUTED LOCKDOWN CHECK (403) ---
    if (!empty($this->options['enable_403_lockdown'])) {
        // 1. Check if Lockdown is currently ACTIVE
        if ($this->is_lockdown_active_for_type('403')) {
             if (isset($_COOKIE['advaipbl_js_verified']) && $_COOKIE['advaipbl_js_verified'] === '1') {
                 // Pass
             } else {
                 $this->log_specific_error('endpoint_challenge', $this->get_client_ip(), ['endpoint' => '403', 'reason' => '403 Lockdown Mode Active', 'uri' => $this->get_current_request_uri()], 'warning');
                 $mode = $this->options['lockdown_403_challenge_mode'] ?? 'managed';
                 $this->js_challenge_manager->serve_challenge('403_lockdown', $mode);
                 exit;
             }
        }
        
        // 2. Monitor
        $this->monitor_distributed_attack('403');
    }

    $this->error_handled_this_request = true;
    $ip = $this->get_client_ip();

        // Comprobación de whitelist.
        if ($this->is_whitelisted($ip)) return $status_header;

        $all_block_types = ['geoblock', 'honeypot', '404', '403', 'login', 'user_agent', 'waf', 'rate_limit', 'asn', 'xmlrpc_block', 'threat_score'];
        foreach ($all_block_types as $type) {
            if (get_transient('advaipbl_bloqueo_' . $type . '_' . md5($ip))) {
                return $status_header;
            }
        }
        
    $this->handle_error('403');
    return $status_header;
}
return $status_header;
}

    /**
     * Bloquea de forma temprana y completa todas las peticiones a xmlrpc.php si la opción está en modo 'disabled'.
     * Enganchado a un hook 'init' temprano para máxima eficacia.
     */
    public function block_xmlrpc_requests_if_disabled() {
        // Solo actuar si la opción está explícitamente en modo 'disabled'.
        if ( empty( $this->options['xmlrpc_protection_mode'] ) || 'disabled' !== $this->options['xmlrpc_protection_mode'] ) {
            return;
        }

        // Comprobamos si la petición actual es para xmlrpc.php.
        $request_uri = $this->get_current_request_uri();
        if ( strpos( $request_uri, 'xmlrpc.php' ) !== false ) {
            $ip = $this->get_client_ip();

            // Logueamos el intento de acceso (opcional pero recomendado para visibilidad)
            $this->log_event(
                sprintf( 'Access to disabled xmlrpc.php endpoint was denied for IP: %s', $ip ),
                'warning',
                ['uri' => $request_uri]
            );

        // AIB Community Network Reporting
        if ( ! empty( $this->options['enable_community_network'] ) ) {
             $this->reporter_manager->queue_report( $ip, 'xmlrpc_block', ['uri' => $request_uri] );
        }

            // Enviamos una respuesta 403 Forbidden y terminamos la ejecución de forma robusta.
            if (!headers_sent()) {
                header('HTTP/1.1 403 Forbidden');
               // Prevenimos que los navegadores intenten cachear esta respuesta de error.
               header('Cache-Control: no-cache, must-revalidate, max-age=0');
               header('Pragma: no-cache');
               header('Expires: Wed, 11 Jan 1984 05:00:00 GMT');
            }
           // Usamos exit() con un mensaje simple, que es más fiable que wp_die() en un hook tan temprano.
           exit('XML-RPC services are disabled on this site.');
        }
    }

    /**
     * Comprueba las reglas avanzadas durante el intento de login (principalmente para bloquear Usernames).
     * @param null|WP_User|WP_Error $user
     * @param string $username
     * @param string $password
     * @return null|WP_User|WP_Error
     */
    public function check_login_rules($user, $username, $password) {
        if (!empty($username)) {
            // Pasamos el username al motor de reglas
            $this->rules_engine->set_context(['username' => $username]);
            
            // Evaluamos. Si hay un bloqueo, evaluate() terminará la ejecución (exit).
            // Si devuelve false, es que no hubo coincidencia.
            $this->rules_engine->evaluate();
            
            // Limpiamos el contexto por si acaso
            $this->rules_engine->set_context([]);
        }
        return $user;
    }

    /**
     * Handles the actual restriction of the login page.
     * Hooked to 'login_init'.
     */
    public function handle_login_page_restriction() {
        // Solo actuar si la opción está activada
        if ( ! empty( $this->options['restrict_login_page'] ) ) {
            $client_ip = $this->get_client_ip();
            
            // Si la IP del visitante no está en la whitelist...
            if ( ! $this->is_whitelisted( $client_ip ) ) {
                /* translators: %s: The IP address that was denied access. */
                $this->log_event( sprintf( __( 'Access to wp-login.php denied for non-whitelisted IP: %s', 'advanced-ip-blocker' ), $client_ip ), 'critical', ['ip' => $client_ip] );
                
                // Mostramos un mensaje genérico de acceso denegado y terminamos.
                wp_die(
                    esc_html__( 'Access to this page has been restricted by the administrator.', 'advanced-ip-blocker' ),
                    esc_html__( 'Access Denied', 'advanced-ip-blocker' ),
                    [ 'response' => 403 ]
                );
            }
        }
    }

    /**
     * Handles the geo-restriction of the login page.
     * Hooked to 'login_init' with priority 2.
     */
    public function handle_login_geo_restriction() {
        if ( ! empty( $this->options['login_restrict_countries'] ) && is_array( $this->options['login_restrict_countries'] ) ) {
            $client_ip = $this->get_client_ip();
            
            // Bypass logic: whitelisted IPs are always allowed
            if ( $this->is_whitelisted( $client_ip ) ) {
                return;
            }

            // Fetch the location of the IP
            $location = $this->geolocation_manager->fetch_location( $client_ip );
            $country_code = $location['country_code'] ?? '';

            // If the country is not found, or it's not in the allowed list, block it
            if ( empty($country_code) || ! in_array( $country_code, $this->options['login_restrict_countries'], true ) ) {
                
                /* translators: 1: The IP address, 2: The Country Code */
                $this->log_event( sprintf( __( 'Login access denied due to Geo-Blocking restrictions for IP %1$s (%2$s)', 'advanced-ip-blocker' ), $client_ip, empty($country_code) ? 'Unknown' : $country_code ), 'warning', ['ip' => $client_ip] );
                
                // Show a generic access denied message
                wp_die(
                    esc_html__( 'Login access from your location is not allowed.', 'advanced-ip-blocker' ),
                    esc_html__( 'Access Denied', 'advanced-ip-blocker' ),
                    [ 'response' => 403 ]
                );
            }
        }
    }
	
    /**
     * Disables the REST API user endpoints for non-authenticated users if the option is enabled.
     * Respects IP and User-Agent Whitelists.
     *
     * @param array $endpoints The available REST API endpoints.
     * @return array The modified endpoints.
     */
    public function disable_rest_api_user_endpoints( $endpoints ) {
        // Solo actuar si la opción está activada
        if ( empty( $this->options['disable_user_enumeration'] ) ) {
            return $endpoints;
        }

        // 1. Permitir usuarios logueados
        if ( is_user_logged_in() ) {
            return $endpoints;
        }

        // 2. Permitir IPs en la Whitelist
        if ( $this->is_whitelisted( $this->get_client_ip() ) ) {
            return $endpoints;
        }

        // 3. Permitir User-Agents en la Whitelist (Plan A support)
        $ua = $this->get_user_agent();
        $whitelisted_uas = get_option( self::OPTION_WHITELISTED_UAS, [] );
        if ( ! empty( $whitelisted_uas ) && is_array( $whitelisted_uas ) ) {
            foreach ( $whitelisted_uas as $whitelisted_ua ) {
                if ( stripos( $ua, $whitelisted_ua ) !== false ) {
                    return $endpoints;
                }
            }
        }

        // Si llegamos aquí, aplicamos el bloqueo
        if ( isset( $endpoints['/wp/v2/users'] ) ) {
            unset( $endpoints['/wp/v2/users'] );
        }
        if ( isset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] ) ) {
            unset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] );
        }
        
        return $endpoints;
    }
	
    /**
    * Prevents user enumeration by redirecting author archive scans at an early hook.
    * Enganchado a 'init'.
    */
    public function prevent_author_enumeration_redirect() {
    // Solo actuar si la opción está activada y no estamos en el admin.
    if ( ! empty( $this->options['prevent_author_scanning'] ) && ! is_admin() ) {
        // Comprobamos directamente el parámetro GET 'author'. Es mucho más fiable.
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        if ( isset( $_GET['author'] ) && is_numeric( $_GET['author'] ) ) {
            wp_safe_redirect( home_url(), 301 );
            exit;
        }
      }
    }

/**
     * Checks if a given IP address falls within a specified range (CIDR, hyphenated, or single).
     * Supports both IPv4 and IPv6.
     *
     * @param string $ip The IP address to check.
     * @param string $range The range to check against.
     * @return bool True if the IP is in the range, false otherwise.
     */
    public function is_ip_in_range( $ip, $range ) {
        $ip = trim($ip);
        $range = trim($range);

        // 1. IP Única (Comparación directa)
        if ( $ip === $range ) {
            return true;
        }

        // 2. Rango con guion (Solo IPv4 por simplicidad y rendimiento, raro en IPv6)
        if ( strpos( $range, '-' ) !== false ) {
            // Si alguno es IPv6, saltamos la lógica de guiones (compleja de calcular)
            if ( strpos($ip, ':') !== false || strpos($range, ':') !== false ) {
                return false; 
            }
            list( $start_ip, $end_ip ) = explode( '-', $range, 2 );
            $ip_long = ip2long( $ip );
            $start_long = ip2long( trim( $start_ip ) );
            $end_long = ip2long( trim( $end_ip ) );
            return $ip_long >= $start_long && $ip_long <= $end_long;
        }

        // 3. Rango CIDR (IPv4 e IPv6)
        if ( strpos( $range, '/' ) !== false ) {
            list( $subnet, $bits ) = explode( '/', $range );
            $bits = (int) $bits;
            
            // Detectar versión de IP
            $ip_is_v6 = (strpos($ip, ':') !== false);
            $subnet_is_v6 = (strpos($subnet, ':') !== false);

            // Si las versiones no coinciden, no puede estar en el rango
            if ( $ip_is_v6 !== $subnet_is_v6 ) {
                return false;
            }

            // Lógica IPv4
            if ( ! $ip_is_v6 ) {
                $ip_long = ip2long( $ip );
                $subnet_long = ip2long( $subnet );
                $mask = -1 << ( 32 - $bits );
                $subnet_masked = $subnet_long & $mask;
                return ( $ip_long & $mask ) === $subnet_masked;
            }

            // Lógica IPv6 (Matemática binaria)
            if ( $ip_is_v6 ) {
                $ip_bin = inet_pton( $ip );
                $subnet_bin = inet_pton( $subnet );
                
                if ( $ip_bin === false || $subnet_bin === false ) {
                    return false; // IP inválida
                }

                // Convertir a string binario de 128 bits
                $ip_bits = '';
                $subnet_bits = '';
                foreach (str_split($ip_bin) as $char) {
                    $ip_bits .= str_pad(decbin(ord($char)), 8, '0', STR_PAD_LEFT);
                }
                foreach (str_split($subnet_bin) as $char) {
                    $subnet_bits .= str_pad(decbin(ord($char)), 8, '0', STR_PAD_LEFT);
                }

                // Comparar los primeros N bits
                return substr($ip_bits, 0, $bits) === substr($subnet_bits, 0, $bits);
            }
        }

        return false;
    }

	public function run_all_block_checks() {
		if ($this->request_is_asn_whitelisted) { return; }

        $ip = $this->get_client_ip();

        if ($this->is_whitelisted($ip)) {
            return;
        }
		
		if ($this->rules_engine->evaluate()) {
            return;
         }
		
        if ( $this->is_visitor_actively_blocked() ) {
            $this->access_denied_page(__('403 - Access Denied', 'advanced-ip-blocker'), $this->get_block_message('generic'));
            exit;
        }

        // Apply Global URL Exclusions AFTER hard security blocks (Rules Engine and Active DB Blocks)
        if ($this->is_request_uri_excluded()) { return; }

        if ( defined( 'WP_CLI' ) && WP_CLI ) {
            return;
        }
        
        $request_uri = $this->get_current_request_uri();
        $is_xmlrpc_request = (strpos($request_uri, 'xmlrpc.php') !== false);
        
        // ENDPOINT LOCKDOWN (PRIMERA ACCIÓN)
        if ($is_xmlrpc_request && !empty($this->options['enable_xmlrpc_lockdown'])) {
            if (get_transient('advaipbl_lockdown_active_xmlrpc')) {
                $user_agent = $this->get_user_agent();
                $is_trusted_service = false;
                $automattic_ua_patterns = [ '/^WordPress\/\d+\.\d+/i', '/jetpack by wordpress\.com/i', '/woocommerce/i' ];
                foreach ($automattic_ua_patterns as $pattern) { if (preg_match($pattern, $user_agent)) { $is_trusted_service = true; break; } }
                
                if (!$is_trusted_service) {
                    $this->log_specific_error('endpoint_challenge', $ip, ['endpoint' => 'xmlrpc.php', 'reason' => 'XML-RPC Lockdown Mode Active', 'uri' => $request_uri], 'warning');
                    $mode = $this->options['xmlrpc_lockdown_challenge_mode'] ?? 'managed';
                    $this->js_challenge_manager->serve_challenge('endpoint', $mode);
                }
            }
        }
        if ($is_xmlrpc_request && ($this->options['xmlrpc_protection_mode'] ?? 'smart') === 'smart') {            
            $is_trusted_request = false;

            // Capa 2: Confianza en la Infraestructura (ASN de la conexión directa)
            $remote_addr = $this->get_remote_addr();
            if ($remote_addr) {
                $location_data_remote = $this->geolocation_manager->fetch_location($remote_addr);
                $remote_asn = $this->asn_manager->extract_asn_from_data($location_data_remote);
                
                // Lista de ASNs de infraestructura de confianza.
                $trusted_infra_asns = ['AS2635', 'AS13335']; // Automattic, Cloudflare
                if ($remote_asn && in_array($remote_asn, $trusted_infra_asns, true)) {
                    $is_trusted_request = true;
                }
            }

            // Capa 3: Confianza en el User-Agent (si la capa de infraestructura no lo confirmó)
            if (!$is_trusted_request) {				
                $user_agent = $this->get_user_agent();
                $automattic_ua_patterns = ['/^WordPress\/\d+\.\d+/i', '/jetpack by wordpress\.com/i', '/woocommerce/i'];
                foreach ($automattic_ua_patterns as $pattern) {
                    if (preg_match($pattern, $user_agent)) {
                        $is_trusted_request = true;
                        break;
                    }
                }
            }
            
            // Capa 4: Decisión final de bloqueo
            if (!$is_trusted_request) {				
                /* translators: %s: User-Agent. */
                $reason = sprintf(__('Blocked untrusted XML-RPC request from User-Agent: %s', 'advanced-ip-blocker'), $this->get_user_agent());
                $log_data = ['user_agent' => $this->get_user_agent(), 'uri' => $request_uri, 'remote_addr' => $remote_addr];
                
                if (!empty($this->options['enable_xmlrpc_lockdown'])) {
                    $this->increment_lockdown_counter('xmlrpc');
                }
                
                $this->block_ip_instantly($ip, 'xmlrpc_block', $reason, $log_data);
            }
            
            // Si es una petición XML-RPC, no continuamos con las demás comprobaciones
            return;
        }
        // Comprobación de bloqueos manuales
        $manual_blocks = get_option( self::OPTION_BLOCKED_MANUAL, [] );
        if ( ! empty( $manual_blocks ) ) {
            foreach ( array_keys( $manual_blocks ) as $entry ) {
                if ( $this->is_ip_in_range( $ip, $entry ) ) {
                    $this->block_ip_instantly( $ip, 'manual', __('Access manually blocked.', 'advanced-ip-blocker') );
                }
            }
        }
                
		// AIB COMMUNITY CHECK
    if (!empty($this->options['enable_community_blocking'])) {
        if ($this->community_manager->is_ip_blocked($ip)) {
            $action = $this->options['community_blocking_action'] ?? 'block';
            
            $log_data = [
                'source' => 'AIB Community Network',
                'uri' => $this->get_current_request_uri()
            ];

            if (strpos($action, 'challenge') !== false) {
                // Check if user has already passed the challenge
                if ((isset($_COOKIE['advaipbl_js_verified']) && $_COOKIE['advaipbl_js_verified'] === '1') || get_transient('advaipbl_grace_pass_' . md5($ip))) {
                    return;
                }
                
                $this->log_specific_error('aib_network_challenge', $ip, $log_data, 'warning');
                $mode = ($action === 'challenge_automatic') ? 'automatic' : 'managed';
                $this->js_challenge_manager->serve_challenge('aib_network', $mode);
            } else {
                // Bloqueo
                $reason = __('Blocked by AIB Community Network (Global Threat).', 'advanced-ip-blocker');
                $this->block_ip_instantly($ip, 'aib_network', $reason, $log_data);
            }
        }
    }
	
        // GEOBLOCKING
        if (!empty($this->options['enable_geoblocking'])) {
            $blocked_countries = $this->options['geoblock_countries'] ?? [];
            if ( ! empty( $blocked_countries ) ) {
                $location = $this->geolocation_manager->fetch_location( $ip );
                if ( $location && ! empty( $location['country_code'] ) ) {
                    if ( in_array( $location['country_code'], $blocked_countries, true ) ) {
						/* translators: %s: Country block. */
                        $reason = sprintf( __( 'Country block: %s', 'advanced-ip-blocker' ), $location['country'] ?? $location['country_code'] );
                        $log_data = [ 'country' => $location['country'] ?? '', 'uri'     => $this->get_current_request_uri() ];
                        $this->block_ip_instantly( $ip, 'geoblock', $reason, $log_data );
                    }
                }
            }
        }
        
        // USER-AGENT CHECK
        if (!empty($this->options['enable_user_agent_blocking'])) {
            $user_agent = $this->get_user_agent();
            if (!empty($user_agent) && !$this->is_internal_request($user_agent)) {
                $is_ua_whitelisted = false;
                $whitelisted_user_agents = get_option('advaipbl_whitelisted_user_agents', []);
                if (!empty($whitelisted_user_agents)) {
                    foreach ($whitelisted_user_agents as $whitelisted_ua_raw) {
                        $whitelisted_ua = trim(preg_replace('/#.*$/', '', $whitelisted_ua_raw));
                        if (!empty($whitelisted_ua) && stripos($user_agent, $whitelisted_ua) !== false) {
                            $is_ua_whitelisted = true;
                            break;
                        }
                    }
                }

                if (!$is_ua_whitelisted) {
                    $blocked_user_agents = get_option('advaipbl_blocked_user_agents', []);
                    if (!empty($blocked_user_agents)) {
                        foreach ($blocked_user_agents as $blocked_ua_raw) {
                            $blocked_ua = trim(preg_replace('/#.*$/', '', $blocked_ua_raw));
                            if (!empty($blocked_ua) && stripos($user_agent, $blocked_ua) !== false) {
								/* translators: %s: User-Agent. */
                                $reason_message = sprintf(__('Blocked User-Agent pattern: %s', 'advanced-ip-blocker'), $blocked_ua);
                                $log_data = [
                                    'user_agent' => $user_agent,
                                    'detail'     => $reason_message,
                                    'uri'        => $this->get_current_request_uri()
                                ];
                                $this->handle_threat_event($ip, 'user_agent', $reason_message, $log_data);
                                return;
                            }
                        }
                    }
                }
            }
        }

        // WAF CHECK
        if ( ! empty( $this->options['enable_waf'] ) ) {
            $triggered_rule = $this->waf_manager->run_waf_scan();
            if ( $triggered_rule !== false ) {
				/* translators: %s: WAF Rule Triggered. */
                $reason_message = sprintf(__('WAF Rule Triggered: %s', 'advanced-ip-blocker'), $triggered_rule);
                $log_data = [
                    'rule' => $triggered_rule, 
                    'uri'  => $this->get_current_request_uri(), 
                    'method' => $this->get_request_method()
                ];
                $this->handle_threat_event($ip, 'waf', $reason_message, $log_data);
            }
        }
		
        // ASN CHECK
        if (!empty($this->options['enable_spamhaus_asn']) || !empty($this->options['enable_manual_asn'])) {
            $provider = $this->options['geolocation_provider'] ?? '';
            if (in_array($provider, ['ip-api.com', 'ipinfo.io'], true)) {
                $asn_block_data = $this->asn_manager->check_asn_block($ip);
                if ($asn_block_data) {
                    $this->handle_threat_event($ip, 'asn', $asn_block_data['reason_message'], $asn_block_data['log_data']);
                }
            }
        }
    } 

    public function is_whitelisted($ip) {		
    if ( ! filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
        return false; // No es una IP pública válida, no puede estar en la whitelist.
    }

    $whitelist = get_option( self::OPTION_WHITELIST, [] );
    if ( empty( $whitelist ) ) {
        return false;
    }

    // Comprobación rápida para IPs individuales (la mayoría de los casos)
    if ( array_key_exists( $ip, $whitelist ) ) {
        return true;
    }

    // Iterar sobre las claves de la whitelist para buscar rangos.
    foreach ( array_keys( $whitelist ) as $entry ) {
        // Si la entrada no es la IP exacta, podría ser un rango.
        if ( $entry !== $ip && $this->is_ip_in_range( $ip, $entry ) ) {
            return true;
        }
    }

    return false;
}

    /**
     * Comprueba si el ASN del visitante actual está en la lista blanca.
     * Si lo está, establece una bandera interna para saltar otras comprobaciones de seguridad.
     * Esta función está diseñada para ejecutarse en un hook muy temprano.
     *
     * @return bool True si el ASN está en la lista blanca, false en caso contrario.
     */
    public function is_visitor_asn_whitelisted() {
		// Check if we have a valid whitelist
        $whitelisted_asns_raw = get_option(self::OPTION_WHITELISTED_ASNS, []);
        if (empty($whitelisted_asns_raw)) {
            return false;
        }

        // Pre-process: Strip comments from config (e.g. "AS1234 # Comment")
        $clean_whitelist = [];
        foreach ($whitelisted_asns_raw as $entry) {
            $parts = explode('#', $entry);
            $clean_whitelist[] = trim($parts[0]);
        }

        // Obtenemos la IP del visitante.
        $ip = $this->get_client_ip();
        if (!$ip) {
            return false;
        }

        // Obtenemos el ASN de la IP.
        $location_data = $this->geolocation_manager->fetch_location($ip);
        $visitor_asn = $this->asn_manager->extract_asn_from_data($location_data);

        if (!$visitor_asn) {
            return false;
        }

        // Comprobamos si el ASN del visitante está en nuestra lista blanca limpia.
        if (in_array($visitor_asn, $clean_whitelist, true)) {
            // ¡Coincidencia! Establecemos la bandera y devolvemos true.
            $this->request_is_asn_whitelisted = true;
            return true;
        }

        return false;
    }
	
    private function is_internal_request($user_agent) { return strpos($user_agent, 'WordPress/') === 0; }
    
	private function get_block_message($type) {
        $messages = [
		    'generic'    => __('Access denied by security policy.', 'advanced-ip-blocker'),
            'geoblock'   => __('Access from your country has been blocked.', 'advanced-ip-blocker'),
            'honeypot'   => __('Access blocked due to suspicious activity.', 'advanced-ip-blocker'),
            'manual'     => __('Access manually blocked.', 'advanced-ip-blocker'),
            '404'        => __('Access blocked due to repeated 404 errors.', 'advanced-ip-blocker'),
            '403'        => __('Access blocked due to repeated attempts on protected resources.', 'advanced-ip-blocker'),
            'login'      => __('Access blocked due to multiple failed login attempts.', 'advanced-ip-blocker'),
            'user_agent' => __('Access blocked due to suspicious User-Agent.', 'advanced-ip-blocker'),
			'waf'        => __('Your request was blocked by the security firewall.', 'advanced-ip-blocker'),
            'rate_limit' => __('Your connection has been temporarily suspended due to an excessive request rate.', 'advanced-ip-blocker'),
			'asn'        => __('Access from your network (ASN) has been blocked by the administrator.', 'advanced-ip-blocker'),
			'xmlrpc_block' => __('Blocked suspicious XML-RPC request.', 'advanced-ip-blocker'),
			'threat_score' => __('Your connection has been blocked due to a high threat score.', 'advanced-ip-blocker'),
            'impersonation' => __('Access blocked for impersonating a known crawler (Googlebot, Bingbot, etc.).', 'advanced-ip-blocker'),
        ];
        return $messages[$type] ?? __('Access blocked.', 'advanced-ip-blocker');
    }

    public function block_ip_instantly($ip, $type, $reason_message, $extra_data = [], $context = 'frontend_block', $custom_duration_seconds = null) {
        if ( in_array( $ip, [ '127.0.0.1', '::1' ], true ) ) {
            $remote_addr = $this->get_remote_addr();
            if ( $remote_addr && ! in_array( $remote_addr, [ '127.0.0.1', '::1' ], true ) ) {
                $original_ip = $ip;
                $ip = $remote_addr;
                $extra_data['_spoofed_ip'] = $original_ip;
                /* translators: %s: The real attacker IP. */
                $reason_message .= sprintf(' (Spoofing attempt from %s)', $ip);
            } else {
                return;
            }
        }

        global $wpdb;
        $lock_key = 'lock_blocking_' . md5($ip);
        
        // Suppress errors to avoid filling the log with "Deadlock found" messages. 
        // If a deadlock occurs, it just means another process is handling this IP, which is fine.
        $wpdb->suppress_errors();
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $lock_acquired = $wpdb->query($wpdb->prepare("INSERT IGNORE INTO {$wpdb->prefix}advaipbl_cache (cache_key, cache_value, expires_at) VALUES (%s, '1', %d)", $lock_key, time() + 15));
        $wpdb->show_errors();

        if (!$lock_acquired) {
            if ($context === 'frontend_block') { $this->access_denied_page(__('403 - Access Denied', 'advanced-ip-blocker'), $this->get_block_message('generic')); exit; }
            return;
        }
        
        
        $table_name = $wpdb->prefix . 'advaipbl_blocked_ips';
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        if ($wpdb->get_var($wpdb->prepare("SELECT id FROM {$table_name} WHERE ip_range = %s", $ip))) {
            $wpdb->delete("{$wpdb->prefix}advaipbl_cache", ['cache_key' => $lock_key]);
            if ($context === 'frontend_block') { $this->access_denied_page(__('403 - Access Denied', 'advanced-ip-blocker'), $this->get_block_message('generic')); exit; }
            return;
        }

        $definitions = $this->get_all_block_type_definitions();
        $def = $definitions[$type] ?? null;
        
        $timestamp = time();

// Por defecto, calculamos la duración según el tipo de bloqueo.
$duration_in_seconds = 10 * YEAR_IN_SECONDS; // Permanente por defecto
if ($def && !empty($def['duration_key'])) {
    $duration_in_minutes = (int) ($this->options[$def['duration_key']] ?? 1440);
    $duration_in_seconds = ($duration_in_minutes > 0) ? $duration_in_minutes * 60 : 0;
}

// Si se proporciona una duración personalizada, esta tiene prioridad.
if ($custom_duration_seconds !== null) {
    $duration_in_seconds = (int) $custom_duration_seconds;
}

$expires_at = ($duration_in_seconds > 0) ? $timestamp + $duration_in_seconds : 0;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $wpdb->insert($table_name, [ 'ip_range' => $ip, 'block_type' => $type, 'timestamp' => $timestamp, 'expires_at' => $expires_at, 'reason' => $reason_message ]);
        
        // Pass the reason to the logger
        $extra_data['_reason'] = $reason_message;
        
        // CRITICAL FIX: Ensure the calculated duration is always logged.
        // This allows the Security Log to show the correct duration (e.g., 1440 min) instead of defaulting to 'Permanent'.
        $extra_data['duration_seconds'] = $duration_in_seconds;
        
        $this->log_specific_error($type, $ip, $extra_data, 'critical');
        set_transient('advaipbl_blocked_ip_' . md5($ip), true, $duration_in_seconds);
        if ($def && $def['uses_transient']) {
            set_transient('advaipbl_bloqueo_' . $type . '_' . md5($ip), true, $duration_in_seconds);
        }
        $extra_data_for_notification = $extra_data;
if ($custom_duration_seconds !== null) {
    $extra_data_for_notification['duration_seconds'] = $custom_duration_seconds;
}
$this->send_block_notification($ip, $type, 1, $extra_data_for_notification);
        $this->clear_blocked_ips_cache();
        
        // Lógica condicional completa para sincronización
        $write_enabled = !empty($this->options['enable_htaccess_write']);
        $sync_enabled  = !empty($this->options['enable_htaccess_ip_blocking']);
        $include_temps = !empty($this->options['enable_htaccess_all_ips']);
        
        // Es permanente si es manual o la fecha de expiración es 0
        $is_permanent  = ($type === 'manual' || $expires_at == 0);

        // Ejecutar actualización SI:
        // 1. La escritura y la sincronización están activas
        // 2. Y ADEMÁS: Es un bloqueo permanente O tenemos activada la inclusión de temporales
        if ( $write_enabled && $sync_enabled ) {
            if ( $is_permanent || $include_temps ) {
                $this->htaccess_manager->update_htaccess();
            }
        }
		
        $cf_enabled = !empty($this->options['enable_cloudflare']);
        $cf_manual  = !empty($this->options['cf_sync_manual']);
        $cf_temps   = !empty($this->options['cf_sync_temporary']);
        
        // Lógica: Sincronizar si está activado globalmente Y
        // (es manual y tenemos activado sync manual) O (es temporal y tenemos activado sync temporal)
        if ( $cf_enabled ) {
            $should_sync_cf = ($type === 'manual' && $cf_manual) || ($type !== 'manual' && $cf_temps);
            
            if ( $should_sync_cf ) {
                // Ejecutamos en segundo plano para no ralentizar la respuesta al usuario
                // (Opcional: por ahora lo hacemos síncrono para simplificar la depuración, 
                // la API de CF es rápida).
                $this->cloudflare_manager->block_ip( $ip, "Blocked by AIB: " . $reason_message );
            }
        }

        // --- AIB Community Network Reporting ---
    if ( ! empty( $this->options['enable_community_network'] ) ) {
        $this->reporter_manager->queue_report( $ip, $type, $extra_data );
    }

    // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
    $wpdb->delete("{$wpdb->prefix}advaipbl_cache", ['cache_key' => $lock_key]);

        if ($context === 'frontend_block') {
            $this->access_denied_page(__('403 - Access Denied', 'advanced-ip-blocker'), $this->get_block_message($type));
            exit;
        }
    }
        public function add_admin_ip_to_whitelist_on_first_run() { 
        if ( get_option('advaipbl_admin_ip_whitelist_trigger') ) { 
            if ( ! wp_doing_cron() && is_user_logged_in() && current_user_can('manage_options') ) {
                
                $whitelist = get_option('advaipbl_ips_whitelist', []);
                $ips_to_add = [];

                // 1. Obtener IP del administrador.
                $admin_ip = $this->get_client_ip();
                if ( filter_var($admin_ip, FILTER_VALIDATE_IP) && !array_key_exists($admin_ip, $whitelist) ) {
                    $ips_to_add[$admin_ip] = __('Admin IP (auto-added on activation)', 'advanced-ip-blocker');
                }

                // 2. Obtener IP del servidor.
                $server_ip = $this->get_server_ip();
                if ( $server_ip && !array_key_exists($server_ip, $whitelist) ) {
                    // Evitar añadir la misma IP dos veces si el admin y el servidor son el mismo.
                    if (!isset($ips_to_add[$server_ip])) {
                        $ips_to_add[$server_ip] = __('Server IP (auto-added on activation)', 'advanced-ip-blocker');
                    }
                }

                if ( ! empty($ips_to_add) ) {
                    foreach ($ips_to_add as $ip => $detail) {
                        $whitelist[$ip] = [ 'timestamp' => time(), 'detail' => $detail ];
                        /* translators: %1$s: The IP address, %2$s: The reason/detail for whitelisting. */
                        $this->log_event( sprintf( __( 'IP %1$s added to whitelist. Reason: %2$s', 'advanced-ip-blocker' ), $ip, $detail ), 'info', $ip );
                    }
                    update_option('advaipbl_ips_whitelist', $whitelist);
                    
                    // Forzamos la invalidación de la caché aquí también.
                    wp_cache_delete('advaipbl_ips_whitelist', 'options');
                }

                delete_option('advaipbl_admin_ip_whitelist_trigger'); 
            } 
        } 
    }



    public function schedule_cron_jobs() {
        if ( ! isset($this->cron_manager) ) {
             $this->cron_manager = new ADVAIPBL_Cron_Manager($this);
        }

        $this->cron_manager->schedule_jobs();
    }
    
    public function purge_old_logs() {
        $this->options = get_option(self::OPTION_SETTINGS, []);
        $retention_days = (int) ($this->options['log_retention_days'] ?? 30);
        if ($retention_days <= 0) return;
        global $wpdb;
        $table_name = $wpdb->prefix . 'advaipbl_logs';
        
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $wpdb->query($wpdb->prepare("DELETE FROM $table_name WHERE timestamp < DATE_SUB(NOW(), INTERVAL %d DAY)", $retention_days));
    }
    
    public function check_database_update() {
		static $already_checked = false;
        if ( $already_checked ) {
            return;
        }
        
        // Valor por defecto '1.0' para instalaciones muy antiguas
        $current_db_version = get_option('advaipbl_db_version', '1.0');
        $installed_plugin_ver = get_option('advaipbl_version_installed', '0.0.0');
        
        // Si la versión guardada es menor que la versión actual del código ('1.9')
        // O si falta la tabla de logs de auditoría (verificación de auto-reparación)
        global $wpdb;
        $table_audit = $wpdb->prefix . 'advaipbl_activity_log';
        $table_blocked = $wpdb->prefix . 'advaipbl_blocked_ips';
        
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $table_missing = ($wpdb->get_var("SHOW TABLES LIKE '$table_audit'") != $table_audit) 
                      || ($wpdb->get_var("SHOW TABLES LIKE '$table_blocked'") != $table_blocked);

        if ( version_compare($current_db_version, ADVAIPBL_DB_VERSION, '<') || $table_missing ) {
            // 1. Crear/Actualizar tablas (incluida la nueva community_ips y activity_log)
            self::setup_database_tables();
            
            // 2. Guardar la nueva versión
            update_option('advaipbl_db_version', ADVAIPBL_DB_VERSION);
            
            // 3. Migraciones y Limpiezas
            $this->migrate_whitelist_format();
            $this->migrate_blocked_ips_to_table();
            $this->cleanup_legacy_options();
            
            // 4. Forzar descarga inicial de la lista comunitaria (Sync)
            // Esto solo ocurre si venían de una versión anterior a la 1.9
            if (isset($this->community_manager)) {
                 $this->community_manager->update_list();
                 $this->log_event('Community list forced update during DB upgrade.', 'info');
            }
        }
        
        // --- Migraciones de nueva generación basadas en Plugin Version ---
        if ( version_compare($installed_plugin_ver, ADVAIPBL_VERSION, '<') ) {
            
            // Migración a 8.9.0: Auto-Generar Token V3
            if ( version_compare($installed_plugin_ver, '8.9.0', '<') && $installed_plugin_ver !== '0.0.0' ) {
                $this->auto_migrate_v3_token();
            }

            // Actualizar la versión instalada en la base de datos
            update_option('advaipbl_version_installed', ADVAIPBL_VERSION);
        }
		
		$already_checked = true;
    }
	
	    /**
     * Limpia las opciones de la base de datos de versiones muy antiguas del plugin.
     * Se ejecuta una sola vez gracias a un sistema de versionado.
     */
    private function cleanup_legacy_options() {
        if (get_option('advaipbl_legacy_options_cleaned') === self::LEGACY_OPTIONS_CLEANUP_VERSION) {
            return;
        }

        $legacy_options_to_delete = [
		'advaipbl_ips_bloqueadas_manual',
		'advaipbl_ips_bloqueadas_404',
		'advaipbl_ips_bloqueadas_403',
		'advaipbl_ips_bloqueadas_login',
		'advaipbl_ips_bloqueadas_geoblock',
		'advaipbl_ips_bloqueadas_honeypot',
		'advaipbl_ips_bloqueadas_user_agent',
		'advaipbl_ips_bloqueadas_waf',
		'advaipbl_ips_bloqueadas_threat_score',
		'advaipbl_ips_bloqueadas_rate_limit',
		'advaipbl_ips_bloqueadas_asn',
		'advaipbl_ips_bloqueadas_xmlrpc_block',
        'advanced-ip-blocker_ips_bloqueadas_404',
        'advanced-ip-blocker_ips_bloqueadas_403',
        'advanced-ip-blocker_ips_bloqueadas_login',
        'advanced-ip-blocker_ips_bloqueadas_honeypot',
        'advanced-ip-blocker_ips_bloqueadas_user_agent',
        'advanced-ip-blocker_settings',
        'advanced-ip-blocker_blocked_user_agents',
        'advanced-ip-blocker_whitelisted_user_agents',
        'advanced-ip-blocker_ips_whitelist',
        'advanced-ip-blocker_ips_bloqueadas_manual',
        'advanced-ip-blocker_honeypot_urls',            
        ];

        foreach ($legacy_options_to_delete as $option_name) {
            delete_option($option_name);
        }

        update_option('advaipbl_legacy_options_cleaned', self::LEGACY_OPTIONS_CLEANUP_VERSION);
    }

    /**
     * Migrates the old whitelist format ( ip => timestamp ) to the new format ( ip => [ 'timestamp' => ..., 'detail' => ... ] ).
     * Runs only if needed.
     */
    private function migrate_whitelist_format() {
        $whitelist = get_option('advaipbl_ips_whitelist', []);
        if ( empty($whitelist) ) {
            return; // Nada que migrar.
        }

        // Comprobamos el formato de la primera entrada para ver si necesita migración.
        $first_entry = reset($whitelist);
        if ( is_array($first_entry) && isset($first_entry['timestamp']) ) {
            return; 
        }

        $migrated_whitelist = [];
        foreach ($whitelist as $ip => $timestamp) {
            if ( is_string($ip) && filter_var($ip, FILTER_VALIDATE_IP) ) {
                $migrated_whitelist[$ip] = [
                    'timestamp' => is_numeric($timestamp) ? $timestamp : time(),
                    'detail'    => __('Migrated from old format', 'advanced-ip-blocker')
                ];
            }
        }

        update_option( 'advaipbl_ips_whitelist', $migrated_whitelist );
        $this->log_event('Whitelist data format successfully migrated.', 'info');
    }
	
	    /**
     * Migra las IPs bloqueadas desde múltiples opciones de WP a la nueva tabla dedicada.
     * Se ejecuta una sola vez y limpia las opciones antiguas después de la migración.
     */
    private function migrate_blocked_ips_to_table() {
        // Usamos una opción para asegurarnos de que esto solo se ejecute una vez.
        if (get_option('advaipbl_ip_table_migration_complete')) {
            return;
        }

        global $wpdb;
        $table_name = $wpdb->prefix . 'advaipbl_blocked_ips';
        $definitions = $this->get_all_block_type_definitions();
        $migrated_count = 0;

        foreach ($definitions as $type => $def) {
            // Solo migramos tipos que tenían una lista persistente.
            if (empty($def['option_key'])) {
                continue;
            }

            $list = get_option($def['option_key'], []);
            if (!is_array($list) || empty($list)) {
                // Borramos la opción si está vacía para limpiar la BD.
                delete_option($def['option_key']);
                continue;
            }

            foreach ($list as $ip_or_range => $block_data) {
                $timestamp = is_array($block_data) && isset($block_data['timestamp']) ? (int)$block_data['timestamp'] : time();
                $reason    = is_array($block_data) && isset($block_data['detail']) ? $block_data['detail'] : '';
                
                $duration_in_seconds = 10 * YEAR_IN_SECONDS; // Permanente por defecto
                if (!empty($def['duration_key'])) {
                    $duration_in_minutes = (int) ($this->options[$def['duration_key']] ?? 1440);
                    if ($duration_in_minutes > 0) {
                        $duration_in_seconds = $duration_in_minutes * 60;
                    }
                }
                $expires_at = $timestamp + $duration_in_seconds;

                // Insertamos la fila en la nueva tabla.
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
                $wpdb->insert(
                    $table_name,
                    [
                        'ip_range'   => $ip_or_range,
                        'block_type' => $type,
                        'timestamp'  => $timestamp,
                        'expires_at' => $expires_at,
                        'reason'     => $reason,
                    ]
                );
                $migrated_count++;
            }

            // Una vez migradas todas las IPs de esta opción, la borramos.
            delete_option($def['option_key']);
        }

        if ($migrated_count > 0) {
            $this->log_event(sprintf('Successfully migrated %d blocked entries to the new database table.', $migrated_count), 'info');
        }

        // Marcamos la migración como completada para no volver a ejecutarla.
        update_option('advaipbl_ip_table_migration_complete', true);
    }

    public static function setup_database_tables() {
        global $wpdb;
        $charset_collate = $wpdb->get_charset_collate();
        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');

        // Tabla de Logs (existente)
        $table_name_logs = $wpdb->prefix . 'advaipbl_logs';
        $sql_logs = "CREATE TABLE $table_name_logs (
            log_id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            timestamp DATETIME NOT NULL DEFAULT '0000-00-00 00:00:00',
            ip VARCHAR(100) NOT NULL,
            log_type VARCHAR(50) NOT NULL,
            level VARCHAR(20) NOT NULL,
            message TEXT NOT NULL,
            details LONGTEXT NULL,
            PRIMARY KEY  (log_id),
            KEY ip (ip(16)),
            KEY log_type (log_type),
            KEY timestamp (timestamp)
        ) $charset_collate;";
        dbDelta($sql_logs);

        // Tabla de Cola de Notificaciones (existente)
        $table_name_queue = $wpdb->prefix . 'advaipbl_notifications_queue';
        $sql_queue = "CREATE TABLE $table_name_queue (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            timestamp DATETIME NOT NULL DEFAULT '0000-00-00 00:00:00',
            ip VARCHAR(100) NOT NULL,
            block_type VARCHAR(50) NOT NULL,
            reason TEXT NOT NULL,
            PRIMARY KEY  (id),
            KEY timestamp (timestamp)
        ) $charset_collate;";
        dbDelta($sql_queue);

        // Tabla de Puntuación de Amenaza
        $table_name_scores = $wpdb->prefix . 'advaipbl_ip_scores';
        $sql_scores = "CREATE TABLE $table_name_scores (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            ip VARCHAR(100) NOT NULL,
            score INT(11) NOT NULL DEFAULT 0,
            last_event_timestamp INT(11) UNSIGNED NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            log_details TEXT,
            PRIMARY KEY  (id),
            UNIQUE KEY ip (ip),
            KEY score (score)
        ) $charset_collate;";
        dbDelta($sql_scores);
        
		// Tabla de Logs de Peticiones y Firmas
        $table_name_requests = $wpdb->prefix . 'advaipbl_request_log';
        $sql_requests = "CREATE TABLE $table_name_requests (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            timestamp INT(11) UNSIGNED NOT NULL,
            ip_hash CHAR(64) NOT NULL,
            request_uri TEXT NOT NULL,
            user_agent TEXT,
            request_headers TEXT,
            request_method VARCHAR(10) NOT NULL,
            signature_hash CHAR(64) NOT NULL,
            is_fake_bot TINYINT(1) DEFAULT 0,
            PRIMARY KEY  (id),
            KEY signature_hash (signature_hash),
            KEY timestamp (timestamp)
        ) $charset_collate;";
        dbDelta($sql_requests);
		
		// Tabla de Firmas Maliciosas Identificadas
        $table_name_signatures = $wpdb->prefix . 'advaipbl_malicious_signatures';
        $sql_signatures = "CREATE TABLE $table_name_signatures (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            signature_hash CHAR(64) NOT NULL,
            reason VARCHAR(255) NOT NULL,
            first_seen INT(11) UNSIGNED NOT NULL,
            last_seen INT(11) UNSIGNED NOT NULL,
            expires_at INT(11) UNSIGNED NOT NULL,
            PRIMARY KEY  (id),
            UNIQUE KEY signature_hash (signature_hash),
            KEY expires_at (expires_at)
        ) $charset_collate;";
        dbDelta($sql_signatures);
		
		// Tabla de Caché
        $table_name_cache = $wpdb->prefix . 'advaipbl_cache';
        $sql_cache = "CREATE TABLE $table_name_cache (
            cache_id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            cache_key VARCHAR(191) NOT NULL,
            cache_value LONGTEXT NOT NULL,
            expires_at INT(11) UNSIGNED NOT NULL,
            PRIMARY KEY  (cache_id),
            UNIQUE KEY cache_key (cache_key)
        ) $charset_collate;";
        dbDelta($sql_cache);
		
		// Tabla de Endpoint Lockdowns
        $table_name_lockdowns = $wpdb->prefix . 'advaipbl_endpoint_lockdowns';
        $sql_lockdowns = "CREATE TABLE $table_name_lockdowns (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            endpoint_key VARCHAR(50) NOT NULL,
            reason VARCHAR(255) NOT NULL,
            created_at INT(11) UNSIGNED NOT NULL,
            expires_at INT(11) UNSIGNED NOT NULL,
            details TEXT,
            PRIMARY KEY  (id),
            KEY endpoint_key (endpoint_key),
            KEY expires_at (expires_at)
        ) $charset_collate;";
        dbDelta($sql_lockdowns);
		
				// Nueva Tabla de IP Bloqueadas
        $table_name_blocked_ips = $wpdb->prefix . 'advaipbl_blocked_ips';
        $sql_blocked_ips = "CREATE TABLE $table_name_blocked_ips (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            ip_range VARCHAR(100) NOT NULL,
            block_type VARCHAR(50) NOT NULL,
            timestamp INT(11) UNSIGNED NOT NULL,
            expires_at INT(11) UNSIGNED NOT NULL,
            reason TEXT,
            PRIMARY KEY  (id),
            UNIQUE KEY unique_ip_range (ip_range),
            KEY  block_type (block_type),
            KEY  expires_at (expires_at)
        ) $charset_collate;";
        dbDelta($sql_blocked_ips);
		
		// Nueva Tabla de Reportes Pendientes (Inteligencia Colectiva)
        $table_name_reports = $wpdb->prefix . 'advaipbl_pending_reports';
        $sql_reports = "CREATE TABLE $table_name_reports (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            ip VARCHAR(100) NOT NULL,
            report_type VARCHAR(50) NOT NULL,
            timestamp INT(11) UNSIGNED NOT NULL,
            context LONGTEXT NULL,
            PRIMARY KEY  (id),
            KEY sent_status (timestamp)
        ) $charset_collate;";
        dbDelta($sql_reports);
		
		// Nueva Tabla Dedicada para Lista Comunitaria (Rendimiento)
        $table_name_community = $wpdb->prefix . 'advaipbl_community_ips';
        $sql_community = "CREATE TABLE $table_name_community (
            ip VARCHAR(45) NOT NULL,
            PRIMARY KEY  (ip)
        ) $charset_collate;";
        dbDelta($sql_community);

        // Nueva Tabla de Activity Audit Log (v8.7.1)
        $table_name_audit = $wpdb->prefix . 'advaipbl_activity_log';
        $sql_audit = "CREATE TABLE $table_name_audit (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            user_id BIGINT(20) UNSIGNED NULL,
            event_type VARCHAR(50) NOT NULL,
            severity VARCHAR(20) NOT NULL,
            details LONGTEXT NULL,
            ip_address VARCHAR(100) NOT NULL,
            timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY  (id),
            KEY event_type (event_type),
            KEY user_id (user_id),
            KEY timestamp (timestamp)
        ) $charset_collate;";
        dbDelta($sql_audit);
		
        update_option('advaipbl_db_version', ADVAIPBL_DB_VERSION);
    }

    public static function get_formatted_datetime($timestamp) { if (!is_numeric($timestamp)) { $timestamp = strtotime($timestamp); } if ($timestamp === false) { return __('Invalid date', 'advanced-ip-blocker'); } $options = get_option('advaipbl_settings', []); $timezone_string = $options['log_timezone'] ?? wp_timezone_string(); try { $date = new DateTime('@' . $timestamp); $timezone = new DateTimeZone($timezone_string); $date->setTimezone($timezone); return $date->format('Y-m-d H:i:s T'); } catch (Exception $e) { $format = get_option('date_format') . ' ' . get_option('time_format'); return date_i18n($format, $timestamp); } }

    /**
 * Parsea una cadena de User-Agent y devuelve una descripción legible.
 *
 * @param string $ua La cadena de User-Agent.
 * @return string Una descripción formateada (ej. "Chrome on Windows").
 */
    private static function parse_user_agent($ua) {
    if (empty($ua) || $ua === __('Unknown', 'advanced-ip-blocker')) {
        return __('Unknown device', 'advanced-ip-blocker');
    }
    
    $os = __('Unknown OS', 'advanced-ip-blocker');
    $browser = __('Unknown Browser', 'advanced-ip-blocker');

    // Mapeos para una detección más precisa
    $os_map = [
        '/windows nt 10/i'      =>  'Windows 10/11',
        '/windows nt 6.3/i'     =>  'Windows 8.1',
        '/windows nt 6.2/i'     =>  'Windows 8',
        '/windows nt 6.1/i'     =>  'Windows 7',
        '/windows nt 6.0/i'     =>  'Windows Vista',
        '/windows nt 5.1/i'     =>  'Windows XP',
        '/macintosh|mac os x/i' =>  'Mac OS',
        '/linux/i'              =>  'Linux',
        '/android/i'            =>  'Android',
        '/iphone/i'             =>  'iPhone',
        '/ipad/i'               =>  'iPad',
    ];

    $browser_map = [
        '/msie/i'       =>  'Internet Explorer',
        '/firefox/i'    =>  'Firefox',
        '/safari/i'     =>  'Safari',
        '/chrome/i'     =>  'Chrome',
        '/edge/i'       =>  'Edge',
        '/opera/i'      =>  'Opera',
        '/netscape/i'   =>  'Netscape',
        '/maxthon/i'    =>  'Maxthon',
        '/konqueror/i'  =>  'Konqueror',
        '/mobile/i'     =>  'Mobile Browser',
    ];

    foreach ($os_map as $regex => $value) {
        if (preg_match($regex, $ua)) {
            $os = $value;
            break;
        }
    }

    foreach ($browser_map as $regex => $value) {
        if (preg_match($regex, $ua)) {
            $browser = $value;
            break;
        }
    }
    
    // Corrección para que "Chrome" no se identifique como "Safari"
    if ($browser === 'Safari' && strpos(strtolower($ua), 'chrome') !== false) {
        $browser = 'Chrome';
    }

    /* translators: 1: Browser name, 2: Operating System name. */
    return sprintf(__('%1$s on %2$s', 'advanced-ip-blocker'), $browser, $os);
}
		
	/**
    * Obtiene la IP del visitante actual. Actúa como un wrapper para get_ip_intelligence()
    *
    * @return string La IP del visitante.
    */
    public function get_client_ip() {
    if ( null !== $this->client_ip ) {
        return $this->client_ip;
    }
    
    $ip_data = $this->get_ip_intelligence();
    $this->client_ip = $ip_data['visitor_ip'] ?? '0.0.0.0';
    
    return $this->client_ip;
     }

    /**
* Obtiene un análisis completo y verificado de las direcciones IP de una petición.
* Implementa la lógica de "Proxies de Confianza" para prevenir IP spoofing.
*/
public function get_ip_intelligence() {
    static $result = null;
    if (null !== $result) {
        return $result;
    }

    $result = [
        'visitor_ip'        => '0.0.0.0',
        'visitor_ip_source' => 'Unknown',
        'proxy_chain'       => [],
        'is_proxied'        => false,
        'cdn_info'          => ['provider' => 'None', 'ray_id' => null, 'country' => null],
    ];

    $headers = [];
    if (function_exists('getallheaders')) {
         $headers = getallheaders();
    } else {
         foreach ($_SERVER as $key => $value) {
            if (strpos($key, 'HTTP_') === 0) {
                $header_key = str_replace('_', '-', strtolower(substr($key, 5)));
                $headers[$header_key] = $value;
            }
         }
    }
    $headers = array_change_key_case($headers, CASE_LOWER);

    $remote_addr = $this->get_remote_addr();
    $source_is_trusted = $this->is_source_trusted($remote_addr);
    $visitor_ip = $remote_addr; // Por defecto, la IP es la de la conexión directa.
    $result['visitor_ip_source'] = 'Direct Connection (REMOTE_ADDR)';
    
    if ($source_is_trusted) {
        $result['is_proxied'] = true;

        $header_priority = [
            'cf-connecting-ip' => 'Cloudflare',
            'true-client-ip'   => 'True-Client-IP',
            'x-real-ip'        => 'X-Real-IP',
            'x-forwarded-for'  => 'X-Forwarded-For'
        ];
        
        foreach ($header_priority as $header_name => $source_label) {
            if (isset($headers[$header_name])) {
                $found_ip = $this->get_first_public_ip_from_string($headers[$header_name]);
                if ($found_ip) {
                    $visitor_ip = $found_ip;
                    $result['visitor_ip_source'] = 'Header: ' . $source_label;
                    
                    if ($source_label === 'Cloudflare') {
                        $result['cdn_info']['provider'] = 'Cloudflare';
                        $result['cdn_info']['ray_id'] = $headers['cf-ray'] ?? null;
                        $result['cdn_info']['country'] = $headers['cf-ipcountry'] ?? null;
                    }
                    break; // Salimos del bucle en cuanto encontramos una IP válida.
                }
            }
        }
        
        // Construimos la cadena de proxies
        if ($remote_addr && $remote_addr !== $visitor_ip) {
             $result['proxy_chain'][] = $remote_addr;
        }
        if (isset($headers['x-forwarded-for'])) {
            $forwarded_ips = array_map('trim', explode(',', $headers['x-forwarded-for']));
            foreach ($forwarded_ips as $proxy_ip) {
                if (filter_var($proxy_ip, FILTER_VALIDATE_IP) && $proxy_ip !== $visitor_ip && !in_array($proxy_ip, $result['proxy_chain'])) {
                    $result['proxy_chain'][] = $proxy_ip;
                }
            }
        }

    } else {
        // Si la fuente NO es de confianza, ignoramos todas las cabeceras de proxy.
        // La IP del visitante es y será siempre REMOTE_ADDR.
        $result['visitor_ip_source'] = 'Untrusted Source (REMOTE_ADDR)';
    }

    $result['visitor_ip'] = $visitor_ip;
    return $result;
}
	
	 /**
     * Gets the server's public IP address using a robust method.
     * It first tries the fast $_SERVER variable, then falls back to an external API call.
     *
     * @return string|null The server's IP address or null if not found.
     */
    public function get_server_ip() {
        // Método 1: El más rápido, si está disponible y es una IP pública.
        $server_ip = isset($_SERVER['SERVER_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['SERVER_ADDR'])) : null;
        if ( $server_ip && filter_var( $server_ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
            return $server_ip;
        }

        // Método 2: Fallback a un servicio externo (muy fiable).
        // Hacemos una petición a un servicio que nos devuelve nuestra propia IP.
        $response = wp_remote_get( 'https://api.ipify.org' );
        if ( ! is_wp_error( $response ) && wp_remote_retrieve_response_code( $response ) === 200 ) {
            $ip = trim( wp_remote_retrieve_body( $response ) );
            if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
                return $ip;
            }
        }

        // Si ambos métodos fallan, no podemos determinar la IP.
        return null;
    }
	
    public function log_event( $message, $level = 'info', $log_type = 'general', $ip = null, $details = [] ) {
        if ( empty( $this->options['enable_logging'] ) ) {
            return;
        }

        // Support for legacy calls where 3rd arg might be details array
        if ( is_array( $log_type ) ) {
            $details = $log_type;
            $log_type = 'general';
        }

        if ( empty( $ip ) ) {
            $ip = $this->get_client_ip();
        }

        global $wpdb;
        $table_name = $wpdb->prefix . 'advaipbl_logs';
        
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
        @$wpdb->insert(
            $table_name,
            [
                'timestamp' => current_time( 'mysql', 1 ),
                'ip'        => $ip,
                'log_type'  => $log_type,
                'level'     => $level,
                'message'   => $message,
                'details'   => ! empty( $details ) ? (is_array($details) || is_object($details) ? wp_json_encode( $details ) : $details) : null,
            ]
        );
    }
	
public function log_specific_error($type, $ip, $extra_data = [], $level = 'warning') {
    if (empty($this->options['enable_logging'])) {
        return;
    }
    global $wpdb;
    $table_name = $wpdb->prefix . 'advaipbl_logs';
    
    $details = [
        'url'        => $this->get_current_request_uri(),
        'uri'        => $this->get_current_request_uri(),
        'method'     => $this->get_request_method(),
        'referrer'   => $this->get_http_referer(),
        'user_agent' => $this->get_user_agent(),
    ];

    if (is_array($extra_data)) {
        $details = array_merge($details, $extra_data);
    }

    $is_local_db_active = (($this->options['geolocation_method'] ?? 'api') === 'local_db' && $this->geoip_manager instanceof ADVAIPBL_GeoIP_Manager);

    if (!isset($details['country_code']) || $is_local_db_active) {
        $location_data = $this->geolocation_manager->fetch_location($ip);
        if ($location_data && empty($location_data['error'])) {
            $details = array_merge($location_data, $details);
        }
    }

    $message = '';
    switch ($type) {
        /* translators: %s: Username. */
        case 'login': $message = sprintf(__('Failed login attempt for user: %s', 'advanced-ip-blocker'), $details['username'] ?? __('unknown', 'advanced-ip-blocker')); break;
        /* translators: %s: WAF rule. */
		case 'waf': $message = sprintf(__('Request blocked by WAF rule: %s', 'advanced-ip-blocker'), $details['rule'] ?? __('unknown rule', 'advanced-ip-blocker')); break;
        /* translators: 1: Number of request, 2: Seconds */
		case 'rate_limit': $message = sprintf(__('Rate limit exceeded: %1$d requests in %2$d seconds.', 'advanced-ip-blocker'), $details['count'] ?? 0, $details['window'] ?? 0); break;
        /* translators: %s: AS number. */
		case 'asn': $message = sprintf(__('Request blocked due to blacklisted ASN: %s', 'advanced-ip-blocker'), $details['asn_number'] ?? 'N/A'); break;
        /* translators: %s: User-Agent. */
		case 'xmlrpc_block': $message = $details['_reason'] ?? sprintf(__('Blocked untrusted XML-RPC request from User-Agent: %s', 'advanced-ip-blocker'), $details['user_agent'] ?? 'N/A'); break;
        /* translators: %s: Honeypot URL. */
		case 'honeypot': $message = sprintf(__('Honeypot URL accessed: %s', 'advanced-ip-blocker'), $details['url'] ?? 'N/A'); break;
        /* translators: %s: Country. */
		case 'geoblock': $message = sprintf(__('Blocked access from country: %s', 'advanced-ip-blocker'), $details['country'] ?? 'N/A'); break;
        /* translators: %s: User-Agent. */
		case 'user_agent': $message = sprintf(__('Blocked due to User-Agent match: %s', 'advanced-ip-blocker'), $details['user_agent'] ?? 'N/A'); break;        
        case 'threat_score': $message = $details['_reason'] ?? __('Threat score threshold exceeded', 'advanced-ip-blocker'); break;
        /* translators: %d: The abuse confidence score from AbuseIPDB. */
        case 'abuseipdb': $message = sprintf(__('Blocked by AbuseIPDB with a confidence score of %d%%.', 'advanced-ip-blocker'), $details['abuse_score'] ?? 'N/A'); break;
		case 'abuseipdb_challenge': $message = __('Challenged by AbuseIPDB', 'advanced-ip-blocker'); break;
		case 'aib_network': 
            /* translators: %s: The trigger detail. */
            $message = $details['_reason'] ?? __('Blocked by AIB Community Intelligence.', 'advanced-ip-blocker'); 
            break;
		case 'aib_network_challenge': 
            $message = __('Visitor challenged by AIB Community Intelligence.', 'advanced-ip-blocker'); 
            break;	
		case 'advanced_rule':
			if ($level === 'critical') {
                /* translators: %s: Advanced Rule detail. */
				$message = $details['_reason'] ?? sprintf(__('Blocked by Advanced Rule: %s', 'advanced-ip-blocker'), $details['rule_name'] ?? 'N/A');
			} elseif ($level === 'warning') {
                /* translators: %s: Advanced Rule detail. */
				$message = sprintf(__('Challenged by Advanced Rule: %s', 'advanced-ip-blocker'), $details['rule_name'] ?? 'N/A');
			} else {
                /* translators: %s: Advanced Rule detail. */
				$message = sprintf(__('Threat score added by Advanced Rule: %s', 'advanced-ip-blocker'), $details['rule_name'] ?? 'N/A');
			}
			break;
        /* translators: %s: The name of the custom 'Allow' rule. */
        case 'advanced_rule_allow': $message = sprintf(__('Allowed by Advanced Rule: %s', 'advanced-ip-blocker'), $details['rule_name'] ?? 'N/A'); break;
		case 'signature_flagged': $message = $details['_reason'] ?? __('New Attack Signature Identified.', 'advanced-ip-blocker'); break;
		case 'signature_challenge': $message = $details['_reason'] ?? __('Signature challenge.', 'advanced-ip-blocker'); break;
        case 'endpoint_challenge': $message = $details['reason'] ?? __('Endpoint challenge served.', 'advanced-ip-blocker'); break;
        case 'impersonation': 
            /* translators: %s: The impersonated user agent. */
            $message = $details['_reason'] ?? sprintf(__('Blocked for impersonating a known crawler (%s).', 'advanced-ip-blocker'), $details['impersonated_user_agent'] ?? 'unknown'); 
            break;
		/* translators: %s: Country name. */
        case 'geo_challenge': $message = sprintf(__('Visitor from %s was challenged.', 'advanced-ip-blocker'), $details['country'] ?? 'N/A'); break;
		/* translators: %s: Default error reason. */
		default: $message = sprintf(__('A %s error occurred.', 'advanced-ip-blocker'), strtoupper($type)); break;
    }
    
    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
    @$wpdb->insert(
        $table_name,
        [
            'timestamp' => current_time('mysql', 1),
            'ip'        => $ip,
            'log_type'  => $type,
            'level'     => $level,
            'message'   => $message,
            'details'   => wp_json_encode($details)
        ]
    );

    if ('critical' === $level) {
        $type_label = $this->get_all_block_type_definitions()[$type]['label'] ?? ucwords(str_replace('_', ' ', $type));
        $general_log_message = sprintf(
            /* translators: 1: IP Address, 2: Block Type Label (e.g., "WAF Block") */
            __('IP %1$s was automatically blocked. Reason: %2$s.', 'advanced-ip-blocker'),
            $ip,
            $type_label
        );
        $this->log_event($general_log_message, 'critical', ['original_log_type' => $type]);
    }
}
	
	 public function registrar_intento_login_fallido( $username ) {
        $this->handle_error( 'login', [ 'username' => $username ] );
    }

    private function handle_error($type, $extra_data = []) {
    if (is_user_logged_in() && current_user_can('unfiltered_html')) {
        return;
    }

    $ip = $this->get_client_ip();
    if ($this->is_whitelisted($ip)) {
        return;
    }

    $all_block_types = ['geoblock', 'honeypot', 'manual', '404', '403', 'login', 'user_agent', 'waf', 'rate_limit', 'asn', 'xmlrpc_block', 'threat_score'];
    foreach ($all_block_types as $reason_type) {
        if (get_transient('advaipbl_bloqueo_' . $reason_type . '_' . md5($ip))) {
            $this->log_specific_error($type, $ip, $extra_data);
            return;
        }
    }
    // Si es un error 404 o 403, nos aseguramos de que $extra_data contenga la URL.
    if (in_array($type, ['404', '403']) && !isset($extra_data['url'])) {
        $extra_data['url'] = $this->get_current_request_uri();
    }

    $this->log_specific_error($type, $ip, $extra_data);
    
	if ('login' === $type && !empty($this->options['enable_login_lockdown'])) { // Usaremos una nueva opción 'enable_login_lockdown'
        $this->increment_login_lockdown_counter();
    }
	
    if (!empty($this->options['enable_threat_scoring'])) {
        
        $points_to_add = (int) ($this->options['score_' . $type] ?? 0);

        if ($points_to_add > 0) {
            // Pasamos $extra_data, que ahora contiene la URL, a increment_score.
            $new_score = $this->threat_score_manager->increment_score($ip, $points_to_add, $type, $extra_data);
            
            $threshold = (int) ($this->options['threat_score_threshold'] ?? 100);
            
            $should_block = false;
            if ($new_score >= $threshold || $points_to_add >= 100) {
                $should_block = true;
            }

            if ($should_block) {

                    $trigger_detail = '';
                    if ($type === 'login') {
                        $trigger_detail = 'Login attempt for user: ' . ($extra_data['username'] ?? 'N/A');
                    } else {
                        $trigger_detail = $this->get_current_request_uri();
                    }
                    /* translators: 1: Points number, 2: An IP will be blocked when its threat score reaches or exceeds this value. */
                    $score_summary = sprintf(__('Score %1$d/%2$d', 'advanced-ip-blocker'), $new_score, $threshold);
                    
                    $reason_message = sprintf( /* translators: 1: Score, 2: Block type, 3: Triger. (eg. Score 100/100 via User agent | Trigger: Blocked User-Agent pattern: MJ12bot.) */
                        __('%1$s via %2$s | Trigger: %3$s', 'advanced-ip-blocker'),
                        $score_summary,
                        ucfirst($type),
                        $trigger_detail
                    );
                    
                    $locations = $this->session_manager->get_cached_locations([$ip]);
                    $location_data = $locations[$ip] ?? null;
                    $geo_details = [];
                    if ($location_data && empty($location_data['error'])) {
                        $geo_details['country'] = $location_data['country'] ?? null;
                        $geo_details['country_code'] = $location_data['country_code'] ?? null;
                        $geo_details['city'] = $location_data['city'] ?? null;
                        $geo_details['lat'] = $location_data['lat'] ?? null;
                        $geo_details['lon'] = $location_data['lon'] ?? null;
                    }

                    $log_details = array_merge([
                        'final_score' => $new_score, 
                        'triggering_event' => $type, 
                        '_reason' => $reason_message,
                        'block_reason_code' => $type // Dato extra para depuración
                    ], $geo_details);
                    
                    $this->block_ip_instantly($ip, 'threat_score', $reason_message, $log_details);
                }
            }

        } else {
            // LÓGICA ANTIGUA (FALLBACK)
            $s = $this->options;
            $minute_in_seconds = 60;
            $threshold = (int) ($s["threshold_{$type}"] ?? 5);
            $window = (int) ($s["transient_expiration_{$type}"] ?? 60) * $minute_in_seconds;
            $count_key = "advaipbl_errores_{$type}_" . md5($ip);
            
            $errors = (int) get_transient($count_key) + 1;
            set_transient($count_key, $errors, $window);
            
            if ($errors >= $threshold) {
                $trigger_detail = ($type === 'login') 
                    ? ($extra_data['username'] ?? 'N/A') 
                    : $this->get_current_request_uri();

                self::$block_queue = [
                    'ip'      => $ip,
                    'type'    => $type,
                    'trigger' => $trigger_detail,
                    'to'      => !empty($this->options['notification_email']) && is_email($this->options['notification_email']) ? $this->options['notification_email'] : get_option('admin_email'),
                    'options' => $this->options,
                    'errors'  => $errors,
                ];

                if (!self::$shutdown_hook_registered) {
                    register_shutdown_function([$this, 'execute_shutdown_block']);
                    self::$shutdown_hook_registered = true;
                }

                delete_transient($count_key);
            }
        }
    }

     /**
     * Centraliza la decisión de cómo manejar un evento de amenaza instantáneo (WAF, Honeypot, etc.).
     * Si el sistema de puntuación está activo, suma puntos. Si no, bloquea directamente.
     *
     * @param string $ip La dirección IP del atacante.
     * @param string $type El tipo de evento (ej. 'waf', 'honeypot').
     * @param string $reason_message La razón detallada del evento.
     * @param array  $log_data Datos adicionales para el log.
     */
    public function handle_threat_event($ip, $type, $reason_message, $log_data) {
        $scoring_system_active = !empty($this->options['enable_threat_scoring']);

        $this->log_specific_error($type, $ip, $log_data, 'warning');
        
		if ( isset($this->reporter_manager) ) {
            $this->reporter_manager->queue_report( $ip, $type, $log_data );
        }
		
        if ($scoring_system_active) {
            $points_to_add = (int) ($this->options['score_' . $type] ?? 0);
            if ($points_to_add <= 0) { return; }

            $new_score = $this->threat_score_manager->increment_score($ip, $points_to_add, $type, $log_data);
            $threshold = (int) ($this->options['threat_score_threshold'] ?? 100);

            if ($new_score >= $threshold) {
				 /* translators: 1: Points number, 2: An IP will be blocked when its threat score reaches or exceeds this value. */
                $score_summary = sprintf(__('Score %1$d/%2$d', 'advanced-ip-blocker'), $new_score, $threshold);
                $block_reason_detail = sprintf( /* translators: 1: Points number, 2: An IP will be blocked when its threat score reaches or exceeds this value, 3: Trigger. */
                    __('%1$s via %2$s | Trigger: %3$s', 'advanced-ip-blocker'),
                    $score_summary, ucfirst(str_replace('_', ' ', $type)), $reason_message
                );
                $locations = $this->session_manager->get_cached_locations([$ip]);
                $location_data = $locations[$ip] ?? null;
                $geo_details = [];
                if ($location_data && empty($location_data['error'])) {
                    $geo_details = ['country' => $location_data['country'] ?? null, 'country_code' => $location_data['country_code'] ?? null, 'city' => $location_data['city'] ?? null];
                }
                $block_log_details = array_merge($log_data, $geo_details, ['_reason' => $block_reason_detail]);
                $this->block_ip_instantly($ip, 'threat_score', $block_reason_detail, $block_log_details);
            }
        } else {
            $this->block_ip_instantly($ip, $type, $reason_message, $log_data);
        }
    }
	
     public function execute_shutdown_block() {
        if (empty(self::$block_queue)) {
            return;
        }

        $q = self::$block_queue;
        $ip = $q['ip'];
        $original_ip_for_log = $ip; // Guardamos la IP original para los logs
        $extra_data_for_log = ['trigger' => $q['trigger'], 'count' => ($q['errors'] ?? 1)];

        if ( in_array( $ip, [ '127.0.0.1', '::1' ], true ) ) {
            $remote_addr = $this->get_remote_addr();
            if ( $remote_addr && ! in_array( $remote_addr, [ '127.0.0.1', '::1' ], true ) ) {
                $ip = $remote_addr; // Cambiamos el objetivo del bloqueo
                $extra_data_for_log['_spoofed_ip'] = $original_ip_for_log;
            } else {
                return; // Petición interna genuina, no bloquear.
            }
        }
		
        global $wpdb;
        $lock_key = 'lock_blocking_shutdown_' . md5($ip);
        
        $wpdb->suppress_errors(); // Avoid deadlock noise
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $lock_acquired = $wpdb->query($wpdb->prepare(
            "INSERT IGNORE INTO {$wpdb->prefix}advaipbl_cache (cache_key, cache_value, expires_at) VALUES (%s, %s, %d)",
            $lock_key, '1', time() + 15
        ));
        $wpdb->show_errors();

        if ( ! $lock_acquired ) {
            return;
        }
        $table_name_blocked = $wpdb->prefix . 'advaipbl_blocked_ips';
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $existing_block = $wpdb->get_var($wpdb->prepare("SELECT id FROM {$table_name_blocked} WHERE ip_range = %s", $ip));
        if ($existing_block) {
            // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $wpdb->delete("{$wpdb->prefix}advaipbl_cache", ['cache_key' => $lock_key]);
            return;
        }
        
        $type = $q['type'];
        $trigger = $q['trigger'];
        $to = $q['to'];
        $options = $q['options'];
        $errors = (isset($q['errors']) && is_numeric($q['errors'])) ? $q['errors'] : 1;

        // 1. Mapear el tipo de bloqueo a su constante de opción correspondiente.
        $option_key_map = [
            '404'   => self::OPTION_BLOCKED_404,
            '403'   => self::OPTION_BLOCKED_403,
            'login' => self::OPTION_BLOCKED_LOGIN,
        ];
        $option_key = $option_key_map[$type] ?? null;
        if ( ! $option_key ) {
            // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $wpdb->delete("{$wpdb->prefix}advaipbl_cache", ['cache_key' => $lock_key]); // Liberar cerrojo antes de salir
            return;
        }

        // 2. Acciones de bloqueo (transient y opción persistente)
        $duration = (int) ($options["duration_{$type}"] ?? 120) * 60;
        $block_key = "advaipbl_bloqueo_{$type}_" . md5($ip);
        set_transient($block_key, true, $duration);
        
        $list = get_option($option_key, []);
        if (!is_array($list)) $list = [];
        $list[$ip] = ['timestamp' => time(), 'detail' => $trigger];
        update_option($option_key, $list);
        
        // 3. Obtener datos de geolocalización COMPLETOS
        $location_data = $this->geolocation_manager->fetch_location($ip);
        $geo_details = [];
        if ($location_data && empty($location_data['error'])) {
            $geo_details['country'] = $location_data['country'] ?? null;
            $geo_details['country_code'] = $location_data['country_code'] ?? null;
            $geo_details['city'] = $location_data['city'] ?? null;
            $geo_details['lat'] = $location_data['lat'] ?? null;
            $geo_details['lon'] = $location_data['lon'] ?? null;
        }

        // 4. Lógica de email y logs
        $notification_enabled = !empty($options['enable_email_notifications']) && '1' === $options['enable_email_notifications'];
        $frequency = $options['notification_frequency'] ?? 'disabled';
        $email_sent = null;

        $reason = '';
        switch ($type) {
            case '404':
            case '403':
                $reason = sprintf( /* translators: 1: %1\$d errors number, 2: %2\$s errors number, 3: Triggering URL. */ __("Generated %1\$d %2\$s errors. Triggering URL: %3\$s", 'advanced-ip-blocker'), $errors, strtoupper($type), $trigger);
                break;
            case 'login':
                $reason = sprintf( /* translators: 1: %1$d failed login attempts, 2: %2$s Username. */ __('Made %1$d failed login attempts for user: %2$s', 'advanced-ip-blocker'), $errors, $trigger);
                break;
        }

        if ($notification_enabled && $frequency === 'instant') {
            $site_name = get_bloginfo( 'name' );
			/* translators: %s: Site name. */
            $email_subject = sprintf(__('[%s] Security Alert: IP Automatically Blocked', 'advanced-ip-blocker'), $site_name);
            $template_title = __('Security Alert: IP Blocked', 'advanced-ip-blocker');
			/* translators: %d: Minutes. */
            $duration_text = sprintf(__('%d minutes', 'advanced-ip-blocker'), (int) ($options["duration_{$type}"] ?? 120));

            $button_url = admin_url('admin.php?page=advaipbl_ip_management&sub-tab=blocked_ips');
            $button_style = "background-color: #2271b1; color: #ffffff; padding: 12px 25px; text-decoration: none; border-radius: 4px; display: inline-block; font-weight: bold;";

            $content_html = 
                '<p style="font-size: 16px; line-height: 1.6;">' . esc_html__( "An IP address has been automatically blocked on your website.", 'advanced-ip-blocker' ) . '</p>' .
                '<table style="width: 100%; border-collapse: collapse; margin-top: 20px;">' .
                '<tr><td style="padding: 8px; border: 1px solid #ddd; background-color: #f9f9f9; width: 150px;"><strong>' . esc_html__( 'Blocked IP', 'advanced-ip-blocker' ) . '</strong></td><td style="padding: 8px; border: 1px solid #ddd;">' . esc_html( $ip ) . '</td></tr>' .
                '<tr><td style="padding: 8px; border: 1px solid #ddd; background-color: #f9f9f9;"><strong>' . esc_html__( 'Date and Time', 'advanced-ip-blocker' ) . '</strong></td><td style="padding: 8px; border: 1px solid #ddd;">' . esc_html( self::get_formatted_datetime(time()) ) . '</td></tr>' .
                '<tr><td style="padding: 8px; border: 1px solid #ddd; background-color: #f9f9f9;"><strong>' . esc_html__( 'Reason', 'advanced-ip-blocker' ) . '</strong></td><td style="padding: 8px; border: 1px solid #ddd;">' . esc_html( $reason ) . '</td></tr>' .
                '<tr><td style="padding: 8px; border: 1px solid #ddd; background-color: #f9f9f9;"><strong>' . esc_html__( 'Block Duration', 'advanced-ip-blocker' ) . '</strong></td><td style="padding: 8px; border: 1px solid #ddd;">' . esc_html( $duration_text ) . '</td></tr>' .
                '</table>' .
                '<p style="margin-top: 20px; font-size: 14px; color: #555;">' . esc_html__( 'No action is required on your part. This is just a notification.', 'advanced-ip-blocker' ) . '</p>' .
                '<table style="width: 100%; text-align: center; margin-top: 30px;"><tr><td>' .
                '<a href="' . esc_url( $button_url ) . '" style="' . esc_attr( $button_style ) . '">' . esc_html__( 'View Blocked IPs', 'advanced-ip-blocker' ) . '</a>' .
                '</td></tr></table>';

            $body = $this->get_html_email_template($template_title, $content_html);
            add_filter('wp_mail_content_type', [$this, 'set_html_mail_content_type']);
            $email_sent = wp_mail($to, $email_subject, $body);
            remove_filter('wp_mail_content_type', [$this, 'set_html_mail_content_type']);

        } elseif ($notification_enabled && in_array($frequency, ['daily', 'weekly'])) {
            $table_name_queue = $wpdb->prefix . 'advaipbl_notifications_queue';
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            @$wpdb->insert($table_name_queue, ['timestamp' => current_time('mysql', 1), 'ip' => $ip, 'block_type' => $type, 'reason' => $reason]);
        }

        // 5. Loguear los eventos de forma segura
        if (!empty($options['enable_logging'])) {
            $log_details = array_merge(['trigger' => $trigger], $geo_details);
            
            // Log específico del evento (404, 403, etc.) con nivel 'critical' porque es un bloqueo.
            $this->log_specific_error($type, $ip, $log_details, 'critical');
            
            // Log general de auditoría
            $log_message_critical = sprintf('IP %1$s blocked via shutdown: %2$d %3$s errors.', $ip, $errors, strtoupper($type));
            $this->log_event($log_message_critical, 'critical', $log_details);
        }

        // AIB Community Network Reporting (Legacy Fallback)
        if ( ! empty( $options['enable_community_network'] ) && $type === 'login' ) {
             $this->reporter_manager->queue_report( $ip, 'login_lockdown', ['trigger' => $trigger] );
        }

        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $wpdb->delete("{$wpdb->prefix}advaipbl_cache", ['cache_key' => $lock_key]);
    }
	
    public function add_cron_intervals($schedules) {
        if (!isset($schedules['10_minutes'])) {
            $schedules['10_minutes'] = [
                'interval' => 10 * MINUTE_IN_SECONDS,
                'display'  => esc_html__('Every 10 Minutes', 'advanced-ip-blocker')
            ];
        }
        if (!isset($schedules['30_minutes'])) {
            $schedules['30_minutes'] = [
                'interval' => 30 * MINUTE_IN_SECONDS,
                'display'  => esc_html__('Every 30 Minutes', 'advanced-ip-blocker')
            ];
        }
        if (!isset($schedules['six_hours'])) {
             $schedules['six_hours'] = [
                'interval' => 21600,
                'display'  => esc_html__('Every 6 Hours', 'advanced-ip-blocker')
             ];
        }
        if (!isset($schedules['hourly'])) {
            $schedules['hourly'] = [
                'interval' => 60 * MINUTE_IN_SECONDS,
                'display'  => esc_html__('Once hourly', 'advanced-ip-blocker')
            ];
        }
        if (!isset($schedules['3_days'])) {
             $schedules['3_days'] = [
                'interval' => 259200, // 3 * 24 * 3600
                'display'  => esc_html__('Every 3 Days', 'advanced-ip-blocker')
             ];
        }
        if (!isset($schedules['5_days'])) {
            $schedules['5_days'] = [
                'interval' => 5 * DAY_IN_SECONDS,
                'display'  => esc_html__('Every 5 Days', 'advanced-ip-blocker')
            ];
        }
        if (!isset($schedules['weekly'])) {
            $schedules['weekly'] = [
                'interval' => 7 * DAY_IN_SECONDS,
                'display'  => esc_html__('Once Weekly', 'advanced-ip-blocker')
            ];
        }    
        return $schedules;
    }

    public function schedule_notification_cron() {
        $frequency = $this->options['notification_frequency'] ?? 'disabled';
        $this->clear_notification_cron();
        if ($frequency === 'daily' || $frequency === 'weekly') {
            $timestamp = strtotime('tomorrow 2:00 am');
            wp_schedule_event($timestamp, $frequency, 'advaipbl_send_summary_email');
        }
    }
    public function clear_notification_cron() { wp_clear_scheduled_hook('advaipbl_send_summary_email'); }

    public function process_and_send_summary() {
        if ( isset($this->notification_manager) ) {
            $this->notification_manager->send_summary_email();
        }
    }

    private function send_block_notification($ip, $type, $count, $extra_data) {
        // Obtenemos los datos de geolocalización una sola vez para usarlos en ambas notificaciones.
        // ADVAIPBL_Notification_Manager se encarga de esto, pero para mantener compatibilidad
        // con la firma de este metodo (que es private, pero por si acaso), delegamos.
        
        // --- PASO 1: Construimos la razón detallada y la etiqueta una sola vez ---
        $reason = __('Unknown reason', 'advanced-ip-blocker');
        $reason_label = ucwords(str_replace('_', ' ', $type));
        
        // ... (Logic to build reason string is duplicated here just to pass it? Or Notification Manager rebuilds it?)
        // Notification Manager rebuilds reason_label if empty. But $reason calculation is complex (switch case).
        // I should Copy the Switch Case OR Pass the raw data.
        // Notification Manager's `notify_block` accepts `$reason`.
        // So I MUST calculate `$reason` here before delegating? 
        // OR move the calculation to Notification Manager?
        // I moved logic to `notify_block` but wait. `notify_block` signature is:
        // notify_block($ip, $type, $reason, $reason_label = '', $extra_data = [])
        // Meaning caller must provide $reason.
        // So I must keep the Switch Case here to generate $reason?
        // But I wanted to extract LOGIC.
        // It seems `notify_block` in Manager uses `$reason` passed to it.
        // I should have moved the Switch Case to Manager.
        // Let's check the Manager code I wrote (Step 972).
        // `notify_block` takes `$reason`. It DOES NOT calculate it.
        // Check Step 972 content.
        // Correct.
        // So `ADVAIPBL_Main` MUST calculate reason.
        // This defeats the purpose of extraction if the big switch case stays in Main.
        // I should have a helper `get_block_reason($type, $count, $extra_data)` in Manager?
        // Or in Main?
        // I will keep the Switch Case in Main for now (delegating only the SENDING),
        // OR I will extract the reason builder to a method and move it.
        // Given I want to clean Main, I should move the reason builder.
        // But `notify_block` in Manager doesn't have it.
        
        // I will keep the Switch Case and call `notify_block`.
        
        // ... (Switch case 404, login, etc. - lines 3719-3781)
        
        switch ($type) {
            case '404': case '403':                
                $reason = sprintf(/* translators: 1: The number of errors. 2: The error type (e.g., "404"). 3: The URL that triggered the error. */
                    __('Generated %1$d %2$s errors. Triggering URL: %3$s', 'advanced-ip-blocker'),
                    $count,
                    strtoupper($type),
                    $extra_data['trigger'] ?? 'N/A'
                );
                break;
            case 'login':
			/* translators: %1$d: The number of failed login attempts for user, %2$s: Username*/
                $reason = sprintf(__('Made %1$d failed login attempts for user: %2$s', 'advanced-ip-blocker'), $count, isset($extra_data['trigger']) ? sanitize_text_field($extra_data['trigger']) : __('unknown', 'advanced-ip-blocker'));
                break;
            case 'manual':
                $reason = __('Manually blocked by an administrator.', 'advanced-ip-blocker');
                break;
            case 'honeypot':
			/* translators: %s: Accessed Honeypot URL. */
                $reason = sprintf(__('Accessed Honeypot URL: %s', 'advanced-ip-blocker'), $extra_data['url'] ?? 'N/A');
                break;
            case 'user_agent':
			/* translators: %s: Used a blocked User-Agent. */
                $reason = sprintf(__('Used a blocked User-Agent: %s', 'advanced-ip-blocker'), $extra_data['user_agent'] ?? 'N/A');
                break;
            case 'geoblock':
			/* translators: %s: Blocked due to country policy reason.  */
                $reason = sprintf( __( 'Blocked due to country policy: %s', 'advanced-ip-blocker' ), $extra_data['country'] ?? 'Unknown Country' );
                break;
            case 'waf':
			/* translators: %s: WAF Rule Triggered. */
                $reason = $extra_data['detail'] ?? sprintf(__('WAF Rule Triggered: %s', 'advanced-ip-blocker'), $extra_data['rule'] ?? 'Unknown');
                break;
            case 'rate_limit': 
			/* translators: 1: Number of request, 2: Seconds */
                $reason = sprintf(__('Rate limit exceeded: %1$d requests in %2$d seconds', 'advanced-ip-blocker'), $extra_data['count'] ?? 0, $extra_data['window'] ?? 0);
                break;
            case 'asn':
			/* translators: %1$d: AS number, %2$s: ASN Provider, 3$s: List (Spamhaus or Manula List).  */
                $reason = sprintf(__('Blocked ASN: %1$s (%2$s) - Source: %3$s', 'advanced-ip-blocker'), $extra_data['asn_number'] ?? 'N/A', $extra_data['asn_name'] ?? 'Unknown', $extra_data['source'] ?? 'N/A');
                break;
            case 'xmlrpc_block':
			/* translators: %s: User-Agent. */
                $reason = sprintf(__('Blocked untrusted XML-RPC request from User-Agent: %s', 'advanced-ip-blocker'), $extra_data['user_agent'] ?? 'N/A');
                break;
            case 'threat_score':
                $reason = $extra_data['_reason'] ?? __('Threat score threshold exceeded', 'advanced-ip-blocker');
                break;
			case 'advanced_rule':
            /* translators: %s: The name of the custom rule. */
            $reason = sprintf(__('Blocked by Advanced Rule: %s', 'advanced-ip-blocker'), $extra_data['rule_name'] ?? 'N/A');
            break;
            case 'abuseipdb':
            /* translators: %d: The abuse confidence score from AbuseIPDB. */
            $reason = sprintf(__('Blocked by AbuseIPDB with a confidence score of %d%%.', 'advanced-ip-blocker'), $extra_data['abuse_score'] ?? 'N/A');
            break;
            case 'aib_network':
                $reason = __('IP identified as malicious by the AIB Community Defense Network.', 'advanced-ip-blocker');
                break;
            case 'impersonation':
                /* translators: %s: The User-Agent being impersonated code. */
                $reason = sprintf(__('Blocked for impersonating a known crawler. Fake User-Agent: %s', 'advanced-ip-blocker'), $extra_data['impersonated_user_agent'] ?? 'Unknown');
                break;			
        }

        if ( isset($this->notification_manager) ) {
            $this->notification_manager->notify_block($ip, $type, $reason, $reason_label, $extra_data);
        }
    }

    public function execute_webhook_send($message) {
        if ( isset($this->notification_manager) ) {
            return $this->notification_manager->execute_webhook_send($message);
        }
        return false;
    }

        public function on_settings_update($old_value, $new_value) {
        // antes de ejecutar cualquier lógica que dependa de $this->options (como el Htaccess Manager).
        $this->options = $new_value;

        $this->log_settings_change($old_value, $new_value);
        
        // Lógica para el cron de notificaciones por email
        $old_freq = $old_value['notification_frequency'] ?? 'disabled';
        $new_freq = $new_value['notification_frequency'] ?? 'disabled';
        if ($old_freq !== $new_freq) {
            wp_clear_scheduled_hook('advaipbl_send_summary_email');
            if ($new_freq === 'daily' || $new_freq === 'weekly') {
                $this->schedule_notification_cron();
            }
        }

        // Lógica para el cron de Spamhaus
        $old_spamhaus = $old_value['enable_spamhaus_asn'] ?? '0';
        $new_spamhaus = $new_value['enable_spamhaus_asn'] ?? '0';
        if ($new_spamhaus !== $old_spamhaus) {
            if ('1' === $new_spamhaus) {
                // Si se acaba de activar, forzamos una actualización inmediata para el usuario.
                // schedule_cron_jobs() se encargará de la programación recurrente.
                $this->update_spamhaus_list();
            } else {
                // Si se acaba de desactivar, limpiamos el cron inmediatamente.
                wp_clear_scheduled_hook('advaipbl_update_spamhaus_list_event');
            }
        }
        
        // Lógica de roles forzados de 2FA
        $old_forced_roles = $old_value['tfa_force_roles'] ?? [];
        $new_forced_roles = $new_value['tfa_force_roles'] ?? [];

        // Comparamos los roles antiguos con los nuevos para ver qué ha cambiado.
        $roles_added = array_diff($new_forced_roles, $old_forced_roles);
        $roles_removed = array_diff($old_forced_roles, $new_forced_roles);

        // Si se han añadido nuevos roles a la lista de forzados...
        if ( ! empty($roles_added) ) {
            $users_to_notify = get_users(['role__in' => $roles_added]);
            foreach ( $users_to_notify as $user ) {
                // Les ponemos la "marca" para que vean el aviso, solo si no tienen 2FA ya.
                if ( $this->tfa_manager && ! $this->tfa_manager->is_2fa_enabled_for_user( $user->ID ) ) {
                    update_user_meta( $user->ID, '_advaipbl_2fa_setup_required', true );
                }
            }
        }

        // Si se han quitado roles de la lista de forzados...
        if ( ! empty($roles_removed) ) {
            $users_to_unflag = get_users(['role__in' => $roles_removed]);
            foreach ( $users_to_unflag as $user ) {
                // Les quitamos la "marca".
                delete_user_meta( $user->ID, '_advaipbl_2fa_setup_required' );
            }
        }

        // --- Lógica de Actualización del .htaccess ---
        $htaccess_related_keys = [
            'enable_htaccess_write',
			'enable_htaccess_ip_blocking',
			'enable_htaccess_all_ips',
            'htaccess_protect_system_files',
            'htaccess_protect_wp_config',
            'htaccess_protect_readme'
        ];

        $htaccess_needs_update = false;
        foreach ($htaccess_related_keys as $key) {
            if (($old_value[$key] ?? null) !== ($new_value[$key] ?? null)) {
                $htaccess_needs_update = true;
                break;
            }
        }

        if ($htaccess_needs_update) {
            if (!empty($new_value['enable_htaccess_write']) && '1' === $new_value['enable_htaccess_write']) {
                // Si está activado (o se acaba de activar), actualizamos/escribimos las reglas
                // El manager usará $this->options, que ya fue actualizado en la línea 1 de esta función.
                $result = $this->htaccess_manager->update_htaccess();
                if (is_wp_error($result)) {
                    $this->log_event('Failed to update .htaccess: ' . $result->get_error_message(), 'error');
                    set_transient(self::TRANSIENT_ADMIN_NOTICE, ['message' => __('Failed to update .htaccess. Check permissions.', 'advanced-ip-blocker'), 'type' => 'error'], 45);
                } else {
                    $this->log_event('.htaccess rules updated successfully.', 'info');
                }
            } else {
                // Si se acaba de desactivar, eliminamos nuestras reglas
                $this->htaccess_manager->remove_rules();
                $this->log_event('.htaccess rules removed (feature disabled).', 'info');
            }
        }

        // Optimization: Force cron schedule refresh when settings change
        $this->schedule_cron_jobs(true);
    }	   

public function add_admin_bar_menu( $wp_admin_bar ) {
    if ( ! current_user_can( 'manage_options' ) ) {
        return;
    }
    
    // 1. Obtenemos todos los contadores al principio
    $blocked_ips_count = $this->get_blocked_count();
    $blocked_signatures_count = $this->get_blocked_signatures_count();
    $blocked_endpoints_count = $this->get_blocked_endpoints_count();
    $total_blocks = $blocked_ips_count + $blocked_signatures_count + $blocked_endpoints_count;

    // 2. Función auxiliar para generar el HTML del contador (burbuja)
    $create_bubble = function($count) {
        if ($count > 0) {
            return ' <span class="advaipbl-block-count">' . number_format_i18n($count) . '</span>';
        }
        return '';
    };

    $base_admin_url = admin_url( 'admin.php?page=advaipbl_settings_page' );
    
    // Estilos en línea para asegurar que se muestren
    echo '<style type="text/css">#wpadminbar .advaipbl-block-count { display: inline-block !important; vertical-align: middle !important; background-color: #d63638 !important; color: #fff !important; font-size: 11px !important; line-height: 1.4 !important; font-weight: 600 !important; border-radius: 10px !important; padding: 0 7px !important; margin-left: 5px !important; }</style>';

    // --- 1. Nodo Principal con el contador TOTAL ---
    $main_title = '<span class="ab-icon"></span><span class="ab-label">' . esc_html__( 'Security', 'advanced-ip-blocker' ) . '</span>' . $create_bubble($total_blocks);
    $wp_admin_bar->add_node( [
        'id'    => 'advaipbl_menu',
        'title' => $main_title,
        'href'  => add_query_arg( ['tab' => 'dashboard', 'sub-tab' => 'main_dashboard'], $base_admin_url ),
    ] );

    // --- 2. Grupo "Settings" ---
    $wp_admin_bar->add_node(['id' => 'advaipbl_settings_group', 'parent' => 'advaipbl_menu', 'title' => __('Settings', 'advanced-ip-blocker'), 'href' => false]);
    $wp_admin_bar->add_node(['id' => 'advaipbl_settings_config', 'parent' => 'advaipbl_settings_group', 'title' => __('Configuration', 'advanced-ip-blocker'), 'href' => add_query_arg(['tab' => 'settings', 'sub-tab' => 'general_settings'], $base_admin_url)]);
    $wp_admin_bar->add_node(['id' => 'advaipbl_settings_2fa', 'parent' => 'advaipbl_settings_group', 'title' => __('2FA Management', 'advanced-ip-blocker'), 'href' => add_query_arg(['tab' => 'settings', 'sub-tab' => '2fa_management'], $base_admin_url)]);
    $wp_admin_bar->add_node(['id' => 'advaipbl_settings_import_export', 'parent' => 'advaipbl_settings_group', 'title' => __('Import / Export', 'advanced-ip-blocker'), 'href' => add_query_arg(['tab' => 'settings', 'sub-tab' => 'import_export'], $base_admin_url)]);
    $wp_admin_bar->add_node(['id' => 'advaipbl_settings_security_headers', 'parent' => 'advaipbl_settings_group', 'title' => __('Security Headers', 'advanced-ip-blocker'), 'href' => add_query_arg(['tab' => 'security_headers', 'sub-tab' => 'headers_config'], $base_admin_url)]);

    // --- 3. Grupo "Blocking Rules" ---
    $wp_admin_bar->add_node(['id' => 'advaipbl_rules_group', 'parent' => 'advaipbl_menu', 'title' => __('Blocking Rules', 'advanced-ip-blocker'), 'href' => false]);
    $wp_admin_bar->add_node(['id' => 'advaipbl_rules_waf', 'parent' => 'advaipbl_rules_group', 'title' => __('Firewall (WAF) Rules', 'advanced-ip-blocker'), 'href' => add_query_arg(['tab' => 'rules', 'sub-tab' => 'waf'], $base_admin_url)]);
    $wp_admin_bar->add_node(['id' => 'advaipbl_rules_useragent', 'parent' => 'advaipbl_rules_group', 'title' => __('User-Agent Blocking', 'advanced-ip-blocker'), 'href' => add_query_arg(['tab' => 'rules', 'sub-tab' => 'user_agents'], $base_admin_url)]);
    $wp_admin_bar->add_node(['id' => 'advaipbl_rules_honeypot', 'parent' => 'advaipbl_rules_group', 'title' => __('Honeypot URLs', 'advanced-ip-blocker'), 'href' => add_query_arg(['tab' => 'rules', 'sub-tab' => 'honeypot'], $base_admin_url)]);
    $wp_admin_bar->add_node(['id' => 'advaipbl_rules_asn', 'parent' => 'advaipbl_rules_group', 'title' => __('ASN Blocking', 'advanced-ip-blocker'), 'href' => add_query_arg(['tab' => 'rules', 'sub-tab' => 'asn_blocking'], $base_admin_url)]);
    $wp_admin_bar->add_node(['id' => 'advaipbl_rules_advanced', 'parent' => 'advaipbl_rules_group', 'title' => __('Advanced Rules', 'advanced-ip-blocker'), 'href' => add_query_arg(['tab' => 'rules', 'sub-tab' => 'advanced_rules'], $base_admin_url)]);
    
    // --- 4. Grupo "Threat Management" con contadores individuales y TOTAL ---
    $threat_mgmt_title = __('Threat Management', 'advanced-ip-blocker') . $create_bubble($total_blocks);
    $wp_admin_bar->add_node(['id' => 'advaipbl_threat_mgmt_group', 'parent' => 'advaipbl_menu', 'title' => $threat_mgmt_title, 'href' => false]);
    $wp_admin_bar->add_node(['id' => 'advaipbl_threat_blocked_ips', 'parent' => 'advaipbl_threat_mgmt_group', 'title' => __('Blocked IPs', 'advanced-ip-blocker') . $create_bubble($blocked_ips_count), 'href' => add_query_arg(['tab' => 'ip_management', 'sub-tab' => 'blocked_ips'], $base_admin_url)]);
    $wp_admin_bar->add_node(['id' => 'advaipbl_threat_blocked_signatures', 'parent' => 'advaipbl_threat_mgmt_group', 'title' => __('Blocked Signatures', 'advanced-ip-blocker') . $create_bubble($blocked_signatures_count), 'href' => add_query_arg(['tab' => 'ip_management', 'sub-tab' => 'blocked_signatures'], $base_admin_url)]);
    $wp_admin_bar->add_node(['id' => 'advaipbl_threat_blocked_endpoints', 'parent' => 'advaipbl_threat_mgmt_group', 'title' => __('Blocked Endpoints', 'advanced-ip-blocker') . $create_bubble($blocked_endpoints_count), 'href' => add_query_arg(['tab' => 'ip_management', 'sub-tab' => 'blocked_endpoints'], $base_admin_url)]);
    $wp_admin_bar->add_node(['id' => 'advaipbl_threat_whitelist', 'parent' => 'advaipbl_threat_mgmt_group', 'title' => __('Whitelist', 'advanced-ip-blocker'), 'href' => add_query_arg(['tab' => 'ip_management', 'sub-tab' => 'whitelist'], $base_admin_url)]);

    // --- 5. Grupo "Logs & Sessions" (y restantes) ---
    $wp_admin_bar->add_node(['id' => 'advaipbl_logs_group', 'parent' => 'advaipbl_menu', 'title' => __('Logs & Sessions', 'advanced-ip-blocker'), 'href' => false]);
    $wp_admin_bar->add_node(['id' => 'advaipbl_log_security', 'parent' => 'advaipbl_logs_group', 'title' => __('Security Log', 'advanced-ip-blocker'), 'href' => add_query_arg(['tab' => 'logs', 'sub-tab' => 'security_log'], $base_admin_url)]);
    $wp_admin_bar->add_node(['id' => 'advaipbl_log_audit', 'parent' => 'advaipbl_logs_group', 'title' => __('Activity Audit', 'advanced-ip-blocker'), 'href' => add_query_arg(['tab' => 'logs', 'sub-tab' => 'audit_log'], $base_admin_url)]);
    $wp_admin_bar->add_node(['id' => 'advaipbl_log_ip_trust', 'parent' => 'advaipbl_logs_group', 'title' => __('IP Trust Log', 'advanced-ip-blocker'), 'href' => add_query_arg(['tab' => 'logs', 'sub-tab' => 'ip_trust_log'], $base_admin_url)]);
    $wp_admin_bar->add_node(['id' => 'advaipbl_log_general', 'parent' => 'advaipbl_logs_group', 'title' => __('General Log', 'advanced-ip-blocker'), 'href' => add_query_arg(['tab' => 'logs', 'sub-tab' => 'general_log'], $base_admin_url)]);
    $wp_admin_bar->add_node(['id' => 'advaipbl_user_sessions', 'parent' => 'advaipbl_logs_group', 'title' => __('User Sessions', 'advanced-ip-blocker'), 'href' => add_query_arg(['tab' => 'logs', 'sub-tab' => 'user_sessions'], $base_admin_url)]);
    $wp_admin_bar->add_node(['id' => 'advaipbl_log_cron', 'parent' => 'advaipbl_logs_group', 'title' => __('WP-Cron Log', 'advanced-ip-blocker'), 'href' => add_query_arg(['tab' => 'logs', 'sub-tab' => 'cron_logs'], $base_admin_url)]);
    // --- NUEVO: Nodo para Site Scanner ---
    $wp_admin_bar->add_node([
        'id'     => 'advaipbl_scanner',
        'parent' => 'advaipbl_menu',
        'title'  => __('Site Scanner', 'advanced-ip-blocker'),
        'href'   => add_query_arg(['tab' => 'scanner', 'sub-tab' => 'scan_overview'], $base_admin_url),
    ]);
	$wp_admin_bar->add_node(['id' => 'advaipbl_status', 'parent' => 'advaipbl_menu', 'title' => __('System Status', 'advanced-ip-blocker'), 'href' => add_query_arg(['tab' => 'dashboard', 'sub-tab' => 'status'], $base_admin_url)]);
    $wp_admin_bar->add_node(['id' => 'advaipbl_credits', 'parent' => 'advaipbl_menu', 'title' => __('About', 'advanced-ip-blocker'), 'href' => add_query_arg(['tab' => 'about', 'sub-tab' => 'credits'], $base_admin_url)]);
}

    public function log_settings_change($old_value, $new_value) {
    if ($old_value === $new_value) {
        return;
    }
    
    $user = wp_get_current_user();
    $username = ($user && $user->ID) ? $user->user_login : __('an unknown user', 'advanced-ip-blocker');

    // Mapeo completo de claves a nombres legibles.
    $friendly_names = [
        // General
        'enable_logging' => __('Logging', 'advanced-ip-blocker'),
        'log_retention_days' => __('Log Retention', 'advanced-ip-blocker'),
        'log_timezone' => __('Log Timezone', 'advanced-ip-blocker'),
        'custom_block_message' => __('Custom Block Message', 'advanced-ip-blocker'),
        'excluded_error_urls' => __('Excluded URLs', 'advanced-ip-blocker'),
        'show_admin_bar_menu' => __('Admin Bar Menu', 'advanced-ip-blocker'),
        // --- CLAVES DEL WAF, ASN(spamhaus) Y RATE LIMITING ---
        'enable_waf' => __('Web Application Firewall (WAF)', 'advanced-ip-blocker'),
        'duration_waf' => __('WAF Block Duration', 'advanced-ip-blocker'),
		'duration_rate_limit' => __('Rate Limiting Block Duration', 'advanced-ip-blocker'),
        'rate_limiting_enable' => __('Rate Limiting', 'advanced-ip-blocker'),
        'rate_limiting_limit' => __('Rate Limiting Request Limit', 'advanced-ip-blocker'),
        'rate_limiting_window' => __('Rate Limiting Time Window', 'advanced-ip-blocker'),
        'duration_rate_limit' => __('Rate Limiting Block Duration', 'advanced-ip-blocker'),
		'enable_geoblocking' => __('Geoblocking Protection', 'advanced-ip-blocker'),
        'enable_honeypot_blocking' => __('Honeypot Protection', 'advanced-ip-blocker'),
        'enable_user_agent_blocking' => __('User-Agent Protection', 'advanced-ip-blocker'),
		'enable_spamhaus_blocking' => __('Spamhaus ASN Protection', 'advanced-ip-blocker'),
		// Notificaciones
        'enable_email_notifications' => __('Email Notifications', 'advanced-ip-blocker'),
        'notification_frequency' => __('Notification Frequency', 'advanced-ip-blocker'),
        'notification_email' => __('Notification Email', 'advanced-ip-blocker'),
        // APIs
		'geolocation_method' => __('Geolocation Method', 'advanced-ip-blocker'),
        'maxmind_license_key' => __('MaxMind License Key', 'advanced-ip-blocker'),
        'geolocation_provider' => __('Geolocation Provider', 'advanced-ip-blocker'),
        'api_key_ip_apicom' => __('ip-api.com API Key', 'advanced-ip-blocker'),
        'api_key_ipinfocom' => __('ipinfo.io API Key', 'advanced-ip-blocker'),
        'api_key_ipapicom' => __('ipapi.com API Key', 'advanced-ip-blocker'),
        'api_key_ipstackcom' => __('ipstack.com API Key', 'advanced-ip-blocker'),
        // Geobloqueo
        'geoblock_countries' => __('Blocked Countries', 'advanced-ip-blocker'),
        'duration_geoblock' => __('Geoblock Duration', 'advanced-ip-blocker'),
        // Reglas de bloqueo
        'duration_honeypot' => __('Honeypot Duration', 'advanced-ip-blocker'),
        'duration_user_agent' => __('User-Agent Duration', 'advanced-ip-blocker'),
        'threshold_404' => __('404 Threshold', 'advanced-ip-blocker'),
        'duration_404' => __('404 Duration', 'advanced-ip-blocker'),
        'transient_expiration_404' => __('404 Time Window', 'advanced-ip-blocker'),
        'threshold_403' => __('403 Threshold', 'advanced-ip-blocker'),
        'duration_403' => __('403 Duration', 'advanced-ip-blocker'),
        'transient_expiration_403' => __('403 Time Window', 'advanced-ip-blocker'),
        'threshold_login' => __('Login Threshold', 'advanced-ip-blocker'),
        'duration_login' => __('Login Duration', 'advanced-ip-blocker'),
        'transient_expiration_login' => __('Login Time Window', 'advanced-ip-blocker'),
        // Protección de Login
        'disable_user_enumeration' => __('REST API Protection', 'advanced-ip-blocker'),
        'prevent_author_scanning' => __('Author Scan Protection', 'advanced-ip-blocker'),
        'restrict_login_page' => __('Whitelist Login Access', 'advanced-ip-blocker'),
        'xmlrpc_protection_mode' => __('XML-RPC Protection Mode', 'advanced-ip-blocker'),
		'enable_xmlrpc_lockdown' => __('XML-RPC Lockdown Mode', 'advanced-ip-blocker'),
		//2FA
		'enable_2fa' => __('Two-Factor Authentication (Global)', 'advanced-ip-blocker'),
        'tfa_force_roles' => __('Force 2FA for Roles', 'advanced-ip-blocker'),
		'prevent_login_hinting' => __('Prevent Login Hinting', 'advanced-ip-blocker'),
        // reCAPTCHA
        'recaptcha_enable' => __('reCAPTCHA', 'advanced-ip-blocker'),
        'recaptcha_version' => __('reCAPTCHA Version', 'advanced-ip-blocker'),
        'recaptcha_site_key' => __('reCAPTCHA Site Key', 'advanced-ip-blocker'),
        'recaptcha_secret_key' => __('reCAPTCHA Secret Key', 'advanced-ip-blocker'),
        'recaptcha_score_threshold' => __('reCAPTCHA Score', 'advanced-ip-blocker'),
        // Desinstalación
        'delete_data_on_uninstall' => __('Delete Data on Uninstall', 'advanced-ip-blocker'),
    ];

    $changed_fields_log = [];

    // Array de todas nuestras opciones de tipo checkbox.
    $checkbox_keys = [
        'enable_logging', 'enable_email_notifications', 'disable_user_enumeration', 'enable_2fa', 'tfa_force_roles',
        'prevent_author_scanning', 'restrict_login_page', 'recaptcha_enable', 'enable_waf', 'rate_limiting_enable',
        'delete_data_on_uninstall', 'disable_xmlrpc', 'show_admin_bar_menu', 'enable_xmlrpc_lockdown'
    ];

    foreach ($friendly_names as $key => $name) {
        $old = $old_value[$key] ?? null;
        $new = $new_value[$key] ?? null;

        if (is_array($old) || is_array($new)) {
            if ($old !== $new) {
				/* translators: %s: Changed fields log. */
                $changed_fields_log[] = sprintf(__('%s: updated', 'advanced-ip-blocker'), $name);
            }
            continue;
        }

        if ($old !== $new) {
            if (strpos($key, '_key') !== false && !empty($new)) {
				/* translators: %s: Changed fields log. */
                $changed_fields_log[] = sprintf(__('%s: updated', 'advanced-ip-blocker'), $name);
            } elseif (in_array($key, $checkbox_keys, true)) {
                $status = ('1' === $new) ? __('enabled', 'advanced-ip-blocker') : __('disabled', 'advanced-ip-blocker');
				/* translators: 1: Changed fields log, 2: Status */
                $changed_fields_log[] = sprintf(__('%1$s: %2$s', 'advanced-ip-blocker'), $name, $status);
            } else {
				/* translators: 1: Changed fields log, 2: Status */
                $changed_fields_log[] = sprintf(__('%1$s: set to "%2$s"', 'advanced-ip-blocker'), $name, esc_html($new));
            }
        }
    }

    if (!empty($changed_fields_log)) {
        $message = sprintf(
		/* translators: 1: Status (enabled or disabled), 2: Changed fields log */
            __('Plugin settings updated by %1$s. Changed fields: %2$s', 'advanced-ip-blocker'),
            $username,
            implode('; ', $changed_fields_log)
        );
        $this->log_event($message, 'info');
    }
}

    private function access_denied_page($title, $message) {
    if (!defined('DONOTCACHEPAGE')) {
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound
        define('DONOTCACHEPAGE', true);
    }

    if (isset($this->block_response_initiated) && $this->block_response_initiated) {
        exit;
    }
    $this->block_response_initiated = true;

    $request_uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';
    $is_xmlrpc_request = (strpos($request_uri, 'xmlrpc.php') !== false);

    $custom_message = $this->options['custom_block_message'] ?? '';
    $display_message = '';

    if ( ! empty( $custom_message ) ) {
    $display_message = wpautop( $custom_message ); 
    } else if ( isset( $this->options['custom_block_message'] ) && $custom_message === '' ) {
    $display_message = esc_html( $message );
    } else {
    $default_title = '<h1>' . esc_html__('Access Restricted', 'advanced-ip-blocker') . '</h1>';
    $default_body = esc_html__('Your request was blocked by the security firewall.', 'advanced-ip-blocker');
    $display_message = $default_title . '<br>' . $default_body;
    }

    if ($is_xmlrpc_request) {
        if (!headers_sent()) {
            header('HTTP/1.1 403 Forbidden');
            header('Content-Type: text/html; charset=utf-8');
        }       

        $html_output = sprintf(
            '<!DOCTYPE html>
            <html xmlns="http://www.w3.org/1999/xhtml">
            <head>
                <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
                <meta name="viewport" content="width=device-width">
                <title>%1$s</title>
                <style type="text/css">
                        html { background: #f1f1f1; }
                        body { background: #fff; color: #444; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif; margin: 2em auto; padding: 1em 2em; max-width: 700px; -webkit-box-shadow: 0 1px 3px rgba(0,0,0,0.13); box-shadow: 0 1px 3px rgba(0,0,0,0.13); }
                        h1 { border-bottom: 1px solid #dadada; color: #666; font-size: 24px; margin: 30px 0 0 0; padding: 0 0 7px 0; }
                        p { font-size: 14px; line-height: 1.5; margin: 25px 0 20px; }
                </style>
            </head>
            <body>
                <div class="wp-die-message">%2$s</div>
            </body>
            </html>',
            esc_html($title),
            $display_message
        );

        echo $html_output; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
        exit();

    } else {
        if (!headers_sent()) {
            header('Cache-Control: no-cache, must-revalidate, max-age=0');
            header('Pragma: no-cache');
            header('Expires: Wed, 11 Jan 1984 05:00:00 GMT');
            status_header(403);
        }

        wp_die(wp_kses_post($display_message), esc_html($title), ['response' => 403]);
    }
}

        public function desbloquear_ip( $entry_to_unblock, $skip_htaccess_update = false ) {
        if ( ! $this->is_valid_ip_or_range( $entry_to_unblock ) ) {
            return;
        }
        
        global $wpdb;
        $table_name = $wpdb->prefix . 'advaipbl_blocked_ips';
        $is_single_ip = filter_var($entry_to_unblock, FILTER_VALIDATE_IP);

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->delete($table_name, ['ip_range' => $entry_to_unblock]);
        
        // También borrar de la tabla de reportes pendientes para evitar falsos positivos
        $table_reports = $wpdb->prefix . 'advaipbl_pending_reports';
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->delete($table_reports, ['ip' => $entry_to_unblock]);
        
        $this->clear_blocked_ips_cache();

        // Limpiar todos los transients asociados
        if ($is_single_ip) {
            delete_transient('advaipbl_blocked_ip_' . md5($entry_to_unblock));
            $definitions = $this->get_all_block_type_definitions();
            foreach ($definitions as $type => $def) {
                if ($def['uses_transient']) {
                    delete_transient("advaipbl_bloqueo_{$type}_" . md5($entry_to_unblock));
                }
                if (in_array($type, ['404', '403', 'login'])) {
                    delete_transient("advaipbl_errores_{$type}_" . md5($entry_to_unblock));
                }
            }
        }
        
        // Limpiar caché de ubicación y resetear puntuación
        if ($is_single_ip) {
            $location_cache = $this->get_from_custom_cache(ADVAIPBL_USM_LOCATION_CACHE_KEY);
            if (is_array($location_cache) && isset($location_cache[$entry_to_unblock])) {
                unset($location_cache[$entry_to_unblock]);
                $this->set_in_custom_cache(ADVAIPBL_USM_LOCATION_CACHE_KEY, $location_cache, ADVAIPBL_USM_LOCATION_CACHE_TTL);
            }
            if (!empty($this->options['enable_threat_scoring'])) {
                $this->threat_score_manager->reset_score($entry_to_unblock);
            }
        }

        // Actualizar Htaccess solo si NO se solicita omitirlo
        if ( ! $skip_htaccess_update && ! empty( $this->options['enable_htaccess_write'] ) ) {
            $this->htaccess_manager->update_htaccess();
        }
		
        if ( ! empty( $this->options['enable_cloudflare'] ) ) {
             // Intentamos desbloquear en Cloudflare siempre, por si acaso estaba allí.
             $this->cloudflare_manager->unblock_ip( $entry_to_unblock );
        }

        /* translators: %1$s: IP, %2$s: Username */
        $this->log_event( sprintf( __( 'Entry %1$s manually unblocked by %2$s.', 'advanced-ip-blocker' ), $entry_to_unblock, $this->get_current_admin_username() ) );
    }

        /**
     * Desbloquea TODAS las IPs de la tabla de bloqueo y limpia todos los transients relacionados.
     * Es una acción masiva y destructiva.
     *
     * @param string $source La fuente de la acción (e.g., 'WP-CLI', 'Admin Action').
     */
    public function unblock_all_ips($source = 'Unknown Action') {
        global $wpdb;
        $table_name_blocked = $wpdb->prefix . 'advaipbl_blocked_ips';

        // 1. Vaciar la tabla de IPs bloqueadas.
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $wpdb->query("TRUNCATE TABLE `{$table_name_blocked}`");
        
        // También vaciar la tabla de reportes pendientes
        $table_reports = $wpdb->prefix . 'advaipbl_pending_reports';
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $wpdb->query("TRUNCATE TABLE `{$table_reports}`");

        // 2. Limpiar la caché de objetos para el contador.
        $this->clear_blocked_ips_cache();
		if ( !empty($this->options['enable_htaccess_write']) ) {
            $this->htaccess_manager->update_htaccess();
        }
        
        // 3. Limpiar todos los transients de bloqueo de la base de datos.
        // Esto incluye los contadores de errores (404, login, etc.) y los flags de bloqueo.
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->query(
            $wpdb->prepare(
                "DELETE FROM {$wpdb->options} WHERE 
                 `option_name` LIKE %s OR 
                 `option_name` LIKE %s OR
                 `option_name` LIKE %s OR
                 `option_name` LIKE %s",
                $wpdb->esc_like('_transient_advaipbl_bloqueo_') . '%',
                $wpdb->esc_like('_transient_timeout_advaipbl_bloqueo_') . '%',
                $wpdb->esc_like('_transient_advaipbl_errores_') . '%',
                $wpdb->esc_like('_transient_timeout_advaipbl_errores_') . '%'
            )
        );

        // 4. Limpiar reglas [AIB] de Cloudflare si está activo (ASÍNCRONO).
        if ( ! empty( $this->options['enable_cloudflare'] ) ) {
             // Programamos tarea en segundo plano para no bloquear la UI
             wp_schedule_single_event( time(), 'advaipbl_cloudflare_cleanup_event' );
        }

        // 5. Registrar el evento.
        $this->log_event(sprintf('All blocked IPs have been unblocked. Action via %s.', $source), 'critical');
    }

    public function limpiar_ips_expiradas() {
        global $wpdb;
        $table_name = $wpdb->prefix . 'advaipbl_blocked_ips';
        $now = time();

        // 1. Obtener todas las IPs que van a expirar
        // Aumentamos el límite a 100 para procesar en lotes razonables y evitar timeouts masivos
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $expiring_ips = $wpdb->get_results($wpdb->prepare(
            "SELECT ip_range, block_type FROM {$table_name} WHERE expires_at < %d AND expires_at > 0 LIMIT 100",
            $now
        ));

        if (empty($expiring_ips)) {
            return;
        }
        
        $cf_enabled = !empty($this->options['enable_cloudflare']);

        foreach ($expiring_ips as $entry) {
            $ip = $entry->ip_range;
            $type = $entry->block_type;
            
            // Borrar de DB una a una para asegurar consistencia
            $wpdb->delete($table_name, ['ip_range' => $ip]);

            // Loguear el desbloqueo
			/* translators: 1: The IP address. 2: The block type (e.g. manual, 404). */
            $this->log_event( sprintf( __('IP %1$s automatically unblocked (expired %2$s).', 'advanced-ip-blocker'), $ip, $type ), 'info' );
            
            // Limpiar transients
            delete_transient('advaipbl_blocked_ip_' . md5($ip));
            delete_transient("advaipbl_bloqueo_{$type}_" . md5($ip));
            
            if ($type === 'threat_score' && isset($this->threat_score_manager)) {
                $this->threat_score_manager->reset_score($ip);
            }

            if ( $cf_enabled ) {
                // Hacemos la llamada. Si falla, no pasa nada, el cron volverá a ejecutarse.
                // Pero como ya borramos de la DB, no lo reintentará.
                // Es un compromiso aceptable para no bloquear el cron.
                $this->cloudflare_manager->unblock_ip($ip);
            }
        }
        
        $this->clear_blocked_ips_cache();

        // Actualizar Htaccess en bloque al final
        if ( !empty($this->options['enable_htaccess_write']) ) {
            $this->htaccess_manager->update_htaccess();
        }
    }
    
	    /**
    * Re-sincroniza los transients de bloqueo con las listas persistentes.
    * Se ejecuta al activar el plugin para prevenir desbloqueos accidentales tras una actualización.
    */
    public function resync_block_transients() {
        $definitions = $this->get_all_block_type_definitions();
        $now = time();

        foreach ($definitions as $type => $def) {
            if (empty($def['option_key']) || empty($def['duration_key']) || !$def['uses_transient']) {
                continue;
            }

            $duration_minutes = (int) ($this->options[$def['duration_key']] ?? 1440);
            if ($duration_minutes <= 0) continue;

            $list = get_option($def['option_key'], []);
            if (!is_array($list) || empty($list)) continue;

            $duration_seconds = $duration_minutes * 60;

            foreach ($list as $ip_or_range => $block_data) {
                if (!filter_var($ip_or_range, FILTER_VALIDATE_IP)) {
                    continue;
                }

                $timestamp = is_array($block_data) && isset($block_data['timestamp']) ? (int)$block_data['timestamp'] : 0;
                if ($timestamp === 0) continue;

                $time_left = ($timestamp + $duration_seconds) - $now;

                if ($time_left > 0) {
                    // Resincroniza el transient específico
                    if (false === get_transient("advaipbl_bloqueo_{$type}_" . md5($ip_or_range))) {
                        set_transient("advaipbl_bloqueo_{$type}_" . md5($ip_or_range), true, $time_left);
                    }
                    // AÑADIR TRANSIENT MAESTRO ---
                    if (false === get_transient('advaipbl_blocked_ip_' . md5($ip_or_range))) {
                        set_transient('advaipbl_blocked_ip_' . md5($ip_or_range), true, $time_left);
                    }
                }
            }
        }
    }

    /**
     * Se engancha a wp_login para añadir automáticamente la IP de un administrador a la lista blanca.
     *
     * @param string  $user_login El login del usuario.
     * @param WP_User $user       El objeto del usuario.
     */
    public function auto_whitelist_admin_on_login($user_login, $user) {
        if (empty($this->options['auto_whitelist_admin']) || '1' !== $this->options['auto_whitelist_admin']) {
            return;
        }

        // Asegurarnos de que es un administrador
        if (is_a($user, 'WP_User') && in_array('administrator', (array) $user->roles)) {
            $ip = $this->get_client_ip();

            // Solo actuar si la IP es válida y no está ya en la lista blanca
            if (filter_var($ip, FILTER_VALIDATE_IP) && !$this->is_whitelisted($ip)) {
                $detail = sprintf(
				/* translators: %1$s: Username, %2$s: Email */
                    __('Auto-whitelisted admin: %1$s (%2$s)', 'advanced-ip-blocker'),
                    $user->user_login,
                    $user->user_email
                );
                $this->add_to_whitelist_and_unblock($ip, $detail);
            }
        }
    }

    public function get_default_settings() {
    $default_exclusions_404_403 = [
        'wc-ajax=get_refreshed_fragments', '?wc-ajax=', 'undefinedjetpack',
        '/wp-cron.php', '.js.map', '.css.map', '/favicon.ico', '/.well-known/traffic-advice',
    ];

    $default_waf_exclusions = [
        '# WooCommerce Payment Gateway Webhooks & AJAX Calls',
        'wc-ajax=wc_stripe_save_appearance', // Stripe Appearance Saver
        'wc-ajax=wc_stripe_get_cart_details', // Stripe Cart Details
        'wc-ajax=ppc-create-order',          // PayPal Create Order
        'wc-ajax=ppc-capture-order',         // PayPal Capture Order
        '?wc-api=wc_gateway_stripe',         // Stripe Webhook Endpoint
        '?wc-api=wc_gateway_paypal',         // PayPal IPN/Webhook Endpoint
    ];

    return [
        // Reglas de bloqueo
        'threshold_404' => 10, 'duration_404' => 360, 'transient_expiration_404' => 60,
        'threshold_403' => 5, 'duration_403' => 60, 'transient_expiration_403' => 30,
        'threshold_login' => 5, 'duration_login' => 360, 'transient_expiration_login' => 60,
        'duration_geoblock' => 1440, 'duration_honeypot' => 1440, 'duration_user_agent' => 1440,
		'duration_waf' => 1440, 'duration_rate_limit' => 30, 'duration_xmlrpc_block' => 1440,
        'duration_asn' => 1440,
		
		// Endpoint Lockdown
        'enable_xmlrpc_lockdown'      => '0',
        'xmlrpc_lockdown_threshold'   => 10,
        'xmlrpc_lockdown_window'      => 15,
        'xmlrpc_lockdown_duration'    => 60,
		'enable_login_lockdown'       => '0',
        'login_lockdown_event_threshold' => 50,
        'login_lockdown_ip_threshold' => 10,
        'login_lockdown_window'       => 5, 
        'login_lockdown_duration'     => 60,
		
        // Protección de Login y Módulos
        'disable_user_enumeration' => '1', 'prevent_author_scanning' => '1', 'restrict_login_page' => '0',
		'auto_whitelist_admin' => '0',
		'enable_waf' => '0', 'rate_limiting_enable' => '1', 'rate_limiting_limit' => 120,
        'rate_limiting_window' => 60, 'xmlrpc_protection_mode' => 'smart',
        'enable_geoblocking' => '1', 'enable_honeypot_blocking' => '1', 'enable_user_agent_blocking' => '1',
        'enable_spamhaus_asn' => '1',
        'enable_manual_asn' => '1',
		'enable_bot_verification' => '1',
		'enable_geo_challenge' => '0',
        'geo_challenge_countries' => [],
        'geo_challenge_cookie_duration' => 24,

        // Ajustes generales
        'enable_logging' => '1',
		'log_retention_days' => 30,
		'log_timezone' => wp_timezone_string(),
        'custom_block_message' => '<h1>' . esc_html__('Access Restricted', 'advanced-ip-blocker') . '</h1><br>' . esc_html__('Your request was blocked by the security firewall.', 'advanced-ip-blocker'),
		'excluded_error_urls' => implode( "\n", $default_exclusions_404_403 ),
        'waf_excluded_urls' => implode("\n", $default_waf_exclusions),
        'rows_per_page' => 20, 'delete_data_on_uninstall' => '0', 'show_admin_bar_menu' => '1',
		'trusted_proxies'    => "# Cloudflare\nAS13335\nAS209242\n# Local Nginx/Varnish Proxy\n127.0.0.1\n::1",
		
        // Notificaciones
        'enable_email_notifications' => '0', 'notification_frequency' => 'disabled', 'notification_email' => '',
        'enable_push_notifications' => '0',
        'push_webhook_urls' => '',
        'push_critical_only' => '0',
		'push_mentions' => '',
        
        // Smart 404/403 Distributed Lockdown
    'enable_404_lockdown'            => '0',
    'lockdown_404_event_threshold'   => 50,
    'lockdown_404_ip_threshold'      => 5,
    'lockdown_404_window'            => 10,
    'lockdown_404_duration'          => 60,

    'enable_403_lockdown'            => '0',
    'lockdown_403_event_threshold'   => 50,
    'lockdown_403_ip_threshold'      => 5,
    'lockdown_403_window'            => 10,
    'lockdown_403_duration'          => 60,

        // APIs Externas
        'geolocation_provider' => 'ip-api.com', 'api_key_ipapicom' => '', 'api_key_ipstackcom' => '',
        'api_key_ipinfocom' => '', 'api_key_ip_apicom' => '', 'geolocation_method' => 'api',
        'maxmind_license_key' => '',
		
		'enable_community_network' => '0', // Por defecto 0 hasta que el usuario acepte o complete el Wizard
		
		// AIB Community Network
        'enable_community_blocking' => '1',
        'community_blocking_action' => 'block',
		'duration_aib_network' => 1440,
		
		// AbuseIPDB Integration
        'enable_abuseipdb' => '0',
        'abuseipdb_api_key' => '',
        'abuseipdb_threshold' => 90,
        'duration_abuseipdb' => 1440,
		'abuseipdb_action' => 'block',
		
		// Htaccess Firewall
        'enable_htaccess_write' => '0',
		'enable_htaccess_ip_blocking' => '0',
		'enable_htaccess_all_ips' => '0',
        'htaccess_protect_system_files' => '0',
        'htaccess_protect_wp_config' => '0',
        'htaccess_protect_readme' => '0',
        
        // Geobloqueo
        'geoblock_countries' => [],
        
        // Ajustes de reCAPTCHA
        'recaptcha_enable' => '0', 'recaptcha_version' => 'v3', 'recaptcha_site_key' => '',
        'recaptcha_secret_key' => '', 'recaptcha_score_threshold' => 0.5,
		
		// CLAVES 2FA 
		'enable_2fa' => '0',       
        'tfa_force_roles' => [],
        'prevent_login_hinting' => '1',		
		
		// Telemetría
        'allow_telemetry' => '0',
		
            // Sistema de Puntuación de Amenaza (IP Trust System)
            'enable_threat_scoring'     => '0', 
            'threat_score_threshold'    => 100,
            'duration_threat_score'     => 1440,
            'score_404'                 => 5,
            'score_403'                 => 10,
            'score_login'               => 15,
            'score_user_agent'          => 100,
            'score_waf'                 => 100,
            'score_honeypot'            => 100,
            'score_asn'                 => 100,
			'score_impersonation'       => 100,
			'score_decay_points'        => 1,
            'score_decay_frequency'     => 1,
			'enable_signature_engine'   => '0',
			'enable_signature_analysis'     => '0',
            'signature_ip_threshold'        => 5,
            'signature_analysis_window'     => 1,
            'signature_rule_ttl'            => 24,
			'enable_signature_blocking'   => '0',
			'trusted_signature_hashes'    => '',
			// Cloudflare Integration
        'enable_cloudflare' => '0',
        'cf_api_token' => '',
        'cf_zone_id' => '',
        'cf_sync_manual' => '0', // Sincronizar bloqueos manuales
        'cf_sync_temporary' => '0', // Sincronizar bloqueos temporales (WAF, Login, etc)
        
        // Site Scanner Automation
        'enable_scheduled_scans'   => '0',
        'scan_frequency'           => 'weekly',
        'scan_notification_email'  => '',
        
        // Granular Scanner Checks
        'scan_check_ssl'           => '1',
        'scan_check_updates'       => '1',
        'scan_check_php'           => '1',
        'scan_check_wp'            => '1',
        'scan_check_debug'         => '1',

        // Audit Log
        'enable_audit_log' => '1',

        // File Integrity Monitor (FIM)
        'enable_fim' => '0',
    ];
		
}

/**
     * Devuelve la lista por defecto de User-Agents maliciosos para el asistente.
     * @return array
     */
    public function get_default_user_agents() {
        return [
            '# === Vulnerability Scanners & Pentesting Tools ===',
            'Acunetix', 'Arachni', 'Burp', 'Dirb', 'DirBuster', 'Feroxbuster', 'Go-http-client', 'Havij', 'Nessus', 'Nikto', 'Nmap', 'Netsparker', 'OpenVAS', 'Photon/1.0', 'sqlmap', 'Vega', 'Wfuzz', 'WhatWeb', 'WPScan', 'WPSec', 'ZAP/', 'masscan', 'ScanNG', 'PressVuln', 'PostmanRuntime', 'CensysInspect', 'Expanse', 'internet-measurement', 'JSScanner/',
            '# === Generic Bots & Scripting Libraries ===',
            '#curl', 'HTTrack', '#Java/', 'okhttp', 'perl', 'php/', 'Python', 'python-requests', 'Scrapy', 'wget', 'libwww', 'ruby',
            '# === Aggressive Scrapers & Black Hat SEO Bots ===',
            '#AhrefsBot', 'Bytespider', 'contabot', 'dataprovider', 'DigExt', '#DotBot', 'EmailCollector', 'ExtractorPro', 'MegaIndex', '#MJ12bot', 'SemrushBot', 'WebCollector', 'WebCopier', 'AliyunSecBot', 'AwarioBot', 'BW/', '#GoogleOther', 'IonCrawl', 'ISSCyberRiskCrawler',
            '# === Spam, Low-Quality AI & Comment Bots ===',
            '#Applebot-Extended', 'ClaudeBot', 'Diffbot', '#FacebookBot', 'FriendlyCrawler', '#Google-Extended', 'ImagesiftBot', 'Image2dataset', '#Meta-ExternalAgent', 'omgili', 'Timpibot', 'omgilibot', 'AcoonBot/', 'anthropic-ai', 'BoardReader', 'CCBot', '#ChatGPT-User', 'Claude-Web', 'DataForSeoBot', '#GPTBot', 'PerplexityBot', '#petalbot', '#YandexBot', 'ZmEu',
            '# === Aggressive Regional Crawlers (optional) ===',
            'Baiduspider', 'Baiduspider-image', 'Baiduspider-news', 'Barkrowler', 'msnbot-media', 'SeznamBot', 'Sogou', 'YisouSpider', 'BLEXBot', 'news-please', 'Orbbot', 'peer39_crawler', 'VelenPublicWebCrawler', '#wp_is_mobile', 'Zoominfobot',
            '# === Suspicious or Malformed User-Agents ===',
            'Dalvik/', 'morfeus', 'ShellBot', 'zgrab', 'Chrome/45', 'Mozilla/4.0', 'Empty', 'Mozlila', 'GRequests/'
        ];
    }

    /**
     * Devuelve la lista por defecto de URLs Honeypot para el asistente.
     * @return array
     */
    public function get_default_honeypot_urls() {
        return [
            '/.env',
            '/wp-config.php',
            '/.git/',
            '/phpinfo.php',
            '/shell.php',
            '/wso.php',
            '/wordpress.zip',
            '/phpunit',
            '/eval-stdin.php'
        ];
    }

    /**
     * Devuelve la lista por defecto de reglas WAF para el asistente.
     * @return array
     */
    public function get_default_waf_rules() {
        return [
            '# === SQL Injection (SQLi) ===',
            'union\s+select',
            'information_schema\.',
            '# === Cross-Site Scripting (XSS) ===',
            '<\s*script',
            'on(error|load|click|mouseover)\s*=',
            'javascript:', // Añadido: Protocolo peligroso en inputs
            '# === Path Traversal & LFI ===',
            '\.\.\/',
            '/etc/passwd',
            'php://input',
            '# === Sensitive Files & Backups ===',
            '/(wp-config\.php|\.env)',
            '\.sql$',
            '\.log$'
        ];
    }
	
    public static function activate_plugin() {
    // 1. Obtener la instancia del plugin SIEMPRE al principio.
    // Esto asegura que $instance siempre exista y que las propiedades (como $options) estén cargadas.
    $instance = self::get_instance();

    // 2. Lógica de la base de datos.
    self::setup_database_tables();

    if ( ! wp_next_scheduled( 'advaipbl_purge_old_logs_event' ) ) {
        wp_schedule_event( time(), 'daily', 'advaipbl_purge_old_logs_event' );
    }
	
	if ( ! wp_next_scheduled( 'advaipbl_update_geoip_db_event' ) ) {
         wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', 'advaipbl_update_geoip_db_event' );
     }
	if ( ! wp_next_scheduled( 'advaipbl_cleanup_expired_cache_event' ) ) {
         wp_schedule_event( time(), 'daily', 'advaipbl_cleanup_expired_cache_event' );
     } 
    
    // 3. Crear los ajustes por defecto SOLO si no existen.
    if ( false === get_option( self::OPTION_SETTINGS ) ) {
        $defaults = $instance->get_default_settings();
        update_option( self::OPTION_SETTINGS, $defaults );
    }
    
    // 4. Programar los crons de notificación (usando la instancia).
    $notification_frequency = $instance->options['notification_frequency'] ?? 'disabled';
    if ( 'disabled' !== $notification_frequency && 'instant' !== $notification_frequency ) {
        if ( ! wp_next_scheduled( 'advaipbl_send_summary_email' ) ) {
            $instance->schedule_notification_cron();
        }
    }
    
    // 5. Re-sincronizar transients (ahora $instance siempre existe).
    $instance->resync_block_transients();
    
    // 6. Añadir las demás opciones si no existen.
    add_option( self::OPTION_BLOCKED_UAS, [], '', 'no' );
    add_option( self::OPTION_WHITELISTED_UAS, [], '', 'no' );
    add_option( self::OPTION_WHITELIST, [], '', 'no' );
    add_option( self::OPTION_BLOCKED_MANUAL, [], '', 'no' );
    add_option( self::OPTION_BLOCKED_HONEYPOT, [], '', 'no' );
    add_option( self::OPTION_BLOCKED_USER_AGENT, [], '', 'no' );
    add_option( self::OPTION_BLOCKED_GEO, [], '', 'no' );
    add_option( ADVAIPBL_USM_OPTION_PER_PAGE, ADVAIPBL_USM_DEFAULT_PER_PAGE, '', 'no' );
    add_option( self::OPTION_HONEYPOT_URLS, [], '', 'no' );
	
	// --- Safe ASN List ---
    $default_safe_asns = [
        'AS15169', // Google LLC
        'AS8075',  // Microsoft Corporation
        'AS2635',  // Automattic Inc.
        'AS32934', // Facebook, Inc.
        'AS5091',  // Stripe, Inc.
        'AS394562', // Stripe, Inc.
        'AS17012'  // PayPal, Inc.
    ];
    add_option( self::OPTION_WHITELISTED_ASNS, $default_safe_asns, '', 'no' );
    
    // 7. Inicializar los triggers de activación.
    add_option( self::OPTION_ADMIN_IP_TRIGGER, 'yes', '', 'no' );
}


    /**
* Comprueba si estamos en una de las páginas de nuestro plugin y, si es así,
* elimina todos los demás avisos de administrador para una interfaz limpia.
*/
public function conditionally_remove_admin_notices() {
    // phpcs:ignore WordPress.Security.NonceVerification.Recommended
    $current_page_slug = isset($_GET['page']) ? sanitize_key($_GET['page']) : '';
    $plugin_pages = [
        'advaipbl_settings_page',
        'advaipbl-setup-wizard' 
    ];

    // Comprobamos si el slug de la página actual es o empieza por uno de nuestros slugs.
    foreach ($plugin_pages as $page_slug) {
        if (strpos($current_page_slug, $page_slug) === 0) {
            remove_all_actions('admin_notices');
            remove_all_actions('all_admin_notices');
            // Una vez que encontramos una coincidencia y limpiamos, no necesitamos seguir.
            return;
        }
    }
}

public function admin_menu() {
    $blocked_count = $this->get_blocked_count();
    $bubble_html = $blocked_count > 0 ? ' <span class="awaiting-mod"><span class="pending-count">' . number_format_i18n($blocked_count) . '</span></span>' : '';
    
    // Slug base para la página principal. Es buena práctica tenerlo en una variable.
    $main_page_slug = 'advaipbl_settings_page';

    // 1. Menú Principal de Nivel Superior
    add_menu_page(
        __('Advanced IP Blocker', 'advanced-ip-blocker'),
        __('Security', 'advanced-ip-blocker') . $bubble_html,
        'manage_options',
        $main_page_slug,
        [$this, 'settings_page_content'],
        'dashicons-shield',
        '80.123'
    );

    // 2. Submenús

    // El primer submenú (Dashboard) usa el mismo slug que el padre para ser la página por defecto.
    // Al hacer clic en "Security", se cargará esta página.
    add_submenu_page(
        $main_page_slug,
        __('Dashboard', 'advanced-ip-blocker'),
        __('Dashboard', 'advanced-ip-blocker'),
        'manage_options',
        $main_page_slug, // Slug = padre. Correcto.
        [$this, 'settings_page_content']
    );

    // Para los demás submenús, usamos slugs únicos y simples.
    // WordPress generará automáticamente los enlaces correctos, por ejemplo:
    // admin.php?page=advaipbl_settings_page-settings
    
    add_submenu_page(
        $main_page_slug,
        __('Settings', 'advanced-ip-blocker'),
        __('Settings', 'advanced-ip-blocker'),
        'manage_options',
        $main_page_slug . '-settings', // Slug único
        [$this, 'settings_page_content']
    );

    add_submenu_page(
        $main_page_slug,
        __('Security Headers', 'advanced-ip-blocker'),
        __('Security Headers', 'advanced-ip-blocker'),
        'manage_options',
        $main_page_slug . '-security-headers', // Slug único
        [$this, 'settings_page_content']
    );

    add_submenu_page(
        $main_page_slug,
        __('Blocking Rules', 'advanced-ip-blocker'),
        __('Blocking Rules', 'advanced-ip-blocker'),
        'manage_options',
        $main_page_slug . '-rules', // Slug único
        [$this, 'settings_page_content']
    );

    add_submenu_page(
        $main_page_slug,
        __('IP Management', 'advanced-ip-blocker'),
        __('IP Management', 'advanced-ip-blocker') . $bubble_html,
        'manage_options',
        $main_page_slug . '-ip-management', // Slug único
        [$this, 'settings_page_content']
    );
	
	add_submenu_page(
        $main_page_slug,
        __('Site Scanner', 'advanced-ip-blocker'),
        __('Site Scanner', 'advanced-ip-blocker'),
        'manage_options',
        $main_page_slug . '-scanner', // Slug único
        [$this, 'settings_page_content']
    );

    add_submenu_page(
        $main_page_slug,
        __('Logs & Sessions', 'advanced-ip-blocker'),
        __('Logs & Sessions', 'advanced-ip-blocker'),
        'manage_options',
        $main_page_slug . '-logs', // Slug único
        [$this, 'settings_page_content']
    );
    
    add_submenu_page(
        $main_page_slug,
        __('About', 'advanced-ip-blocker'),
        __('About', 'advanced-ip-blocker'),
        'manage_options',
        $main_page_slug . '-about', // Slug único
        [$this, 'settings_page_content']
    );
	
    // Registrar la página oculta para el asistente de configuración.
    // 1. Registramos la página COMO HIJA DEL MENÚ PRINCIPAL (No null)
    // Esto hace que WordPress sepa su título.
    add_submenu_page(
        $main_page_slug, // Usamos la variable $main_page_slug que definiste arriba
        __( 'Setup Wizard', 'advanced-ip-blocker' ),
        __( 'Setup Wizard', 'advanced-ip-blocker' ),
        'manage_options',
        'advaipbl-setup-wizard',
        [ $this->admin_pages, 'render_setup_wizard_page' ]
    );
    
    // 2. IMPORTANTE: NO usamos remove_submenu_page aquí. Lo ocultaremos con CSS.
    // Esto asegura que la página siga existiendo en el sistema de menús de WP.
}

    /**
     * Removes all admin notices from other plugins and WordPress core
     * ONLY on this plugin's settings page.
     */
    public function remove_all_other_admin_notices() {
        // Esta es la técnica que sugeriste, es perfecta.
        remove_all_actions( 'admin_notices' );
        remove_all_actions( 'all_admin_notices' );
    }

    public function display_admin_notice() {
        // --- DECAY STRATEGY (v8.9.4+) ---
        // Notice about AIB Network falling back to degraded tier
        if (get_option('advaipbl_network_degraded')) {
            echo '<div class="notice notice-warning is-dismissible"><p>';
            printf(
                wp_kses(
                    /* translators: %s: URL to the plugin settings page. */
                    __('<strong>Advanced IP Blocker:</strong> You are receiving a limited community threat feed (50,000 IPs). To increase your protection level to 100,000+ IPs, please go to the plugin settings and <a href="%s">Register the AIB Network Integration</a>.', 'advanced-ip-blocker'),
                    array('strong' => array(), 'a' => array('href' => array()))
                ),
                esc_url(admin_url('admin.php?page=advaipbl_settings_page-settings&sub-tab=threat_intelligence#advaipbl-community-network-card'))
            );
            echo '</p></div>';
        }

        // Primero, llamamos a la función que decide si mostrar el aviso de telemetría.
        $this->display_telemetry_notice();

        // Después, mostramos cualquier otro aviso de éxito/error que esté en el transient.
        $notice = get_transient('advaipbl_admin_notice');
        if ( $notice ) {
            $type = ( 'success' === $notice['type'] ) ? 'success' : 'error';
            
            printf(
                '<div class="notice notice-%1$s is-dismissible"><p>%2$s</p></div>',
                esc_attr( $type ),
                esc_html( $notice['message'] )
            );
            
            delete_transient('advaipbl_admin_notice');
        }
    }

    /**
 * Validates if a string is a valid IP, CIDR range, or hyphenated range.
 *
 * @param string $input The string to validate.
 * @return bool
 */
public function is_valid_ip_or_range($input) {
    $input = trim($input);
    
    // Check for single IP
    if (filter_var($input, FILTER_VALIDATE_IP)) {
        return true;
    }

    // Check for CIDR
    if (strpos($input, '/') !== false) {
        list($subnet, $bits) = explode('/', $input, 2);
        if (!filter_var($subnet, FILTER_VALIDATE_IP)) {
            return false;
        }
        if (!is_numeric($bits) || $bits < 0) {
            return false;
        }
        // Validate bits based on IP version
        $max_bits = (filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) ? 128 : 32;
        return $bits <= $max_bits;
    }

    // Check for hyphenated range
    if (strpos($input, '-') !== false) {
        list($start_ip, $end_ip) = explode('-', $input, 2);
        return filter_var(trim($start_ip), FILTER_VALIDATE_IP) && filter_var(trim($end_ip), FILTER_VALIDATE_IP);
    }
    
    return false;
}

        /**
 * Checks if a given IP address is from a trusted proxy source.
 * This is the core function for the Trusted Proxies feature. It checks against
 * a user-defined list of IPs, CIDR ranges, and ASNs.
 *
 * @param string $ip_to_check The IP address to verify (usually REMOTE_ADDR).
 * @return bool True if the IP is from a trusted source, false otherwise.
 */
private function is_source_trusted($ip_to_check) {
    // Si no hay IP para comprobar, no puede ser de confianza.
    if (empty($ip_to_check)) {
        return false;
    }

    $raw_trusted_list = $this->options['trusted_proxies'] ?? '';
    if (empty($raw_trusted_list)) {
        return false;
    }

    $trusted_list = array_filter(array_map('trim', explode("\n", $raw_trusted_list)));
    if (empty($trusted_list)) {
        return false;
    }

    // Dividimos la lista en IPs/CIDRs y ASNs para un procesamiento eficiente.
    $trusted_ips_cidrs = [];
    $trusted_asns = [];
    foreach ($trusted_list as $entry) {
        if (strpos(strtoupper($entry), 'AS') === 0) {
            $trusted_asns[] = strtoupper($entry);
        } else {
            $trusted_ips_cidrs[] = $entry;
        }
    }

    // 1. Comprobación directa de IP/CIDR (la más rápida).
    foreach ($trusted_ips_cidrs as $trusted_entry) {
        if ($this->is_ip_in_range($ip_to_check, $trusted_entry)) {
            return true;
        }
    }

    // 2. Si no hubo coincidencia de IP y hay ASNs para comprobar, procedemos con la búsqueda de ASN.
    if (!empty($trusted_asns)) {
        // Aprovechamos nuestro gestor de geolocalización y su caché.
        $location_data = $this->geolocation_manager->fetch_location($ip_to_check);
        $source_asn = $this->asn_manager->extract_asn_from_data($location_data);

        if ($source_asn && in_array(strtoupper($source_asn), $trusted_asns, true)) {
            return true;
        }
    }

    return false;
}

/**
 * Finds the first valid, public IP address from a comma-separated string of IPs.
 *
 * @param string $ip_string The string from a proxy header (e.g., X-Forwarded-For).
 * @return string|null The first valid public IP, or null if none are found.
 */
private function get_first_public_ip_from_string($ip_string) {
    $ips = array_map('trim', explode(',', $ip_string));
    foreach ($ips as $ip) {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            return $ip;
        }
    }
    return null;
}

    //public function handle_admin_actions() {}

   public function settings_page_content() {
    $this->admin_pages->settings_page_content();
}

    /**
     * Imprime una cabecera de columna de tabla HTML que permite ordenar.
     */
    public function print_sortable_header($label, $column_key, $orderby, $order) {
        $next_order = ($orderby === $column_key && 'asc' === $order) ? 'desc' : 'asc';
        $arrow_class = ($orderby === $column_key) ? 'sorted ' . $order : 'sortable desc';
        
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $filter_type_sanitized = isset($_GET['filter_type']) ? sanitize_key(wp_unslash($_GET['filter_type'])) : 'all';

        $url = add_query_arg([
            'orderby'     => $column_key,
            'order'       => $next_order,
            'filter_type' => $filter_type_sanitized,
        ]);
        echo '<th scope="col" class="manage-column column-primary ' . esc_attr($arrow_class) . '"><a href="' . esc_url($url) . '"><span>' . esc_html($label) . '</span><span class="sorting-indicator"></span></a></th>';
    }

    /**
     * Renders a dropdown to select the number of items per page.
     *
     * @param int $current_per_page The currently selected number of items per page.
     */
    public function render_per_page_selector( $current_per_page ) {
        $per_page_options = [ 20, 50, 100, 200 ];
        ?>
        <label for="advaipbl-per-page-selector" class="screen-reader-text"><?php esc_html_e( 'Rows per page', 'advanced-ip-blocker' ); ?></label>
          <select name="advaipbl_per_page" class="advaipbl-per-page-selector bulkactions">
            <?php foreach ( $per_page_options as $option ) : ?>
                <option value="<?php echo esc_attr( $option ); ?>" <?php selected( $current_per_page, $option ); ?>>
                    <?php
                    /* translators: %s: Number of items. */
                    printf( esc_html__( '%s per page', 'advanced-ip-blocker' ), esc_html( $option ) );
                    ?>
                </option>
            <?php endforeach; ?>
        </select>
        <?php
    }

    public function print_log_sortable_header($label, $column_key, $orderby, $order) {
    $next_order = ($orderby === $column_key && 'asc' === $order) ? 'desc' : 'asc';
    $arrow_class = ($orderby === $column_key) ? 'sorted ' . $order : 'sortable desc';
    
    // Obtenemos los parámetros de la URL actual para mantenerlos al ordenar
    // phpcs:ignore WordPress.Security.NonceVerification.Recommended
    $current_params = $_GET;
    $url_params = array_merge($current_params, [
        'orderby' => $column_key,
        'order'   => $next_order,
    ]);

    $url = add_query_arg($url_params, admin_url('admin.php'));
    
    echo '<th scope="col" class="manage-column column-primary ' . esc_attr($arrow_class) . '"><a href="' . esc_url($url) . '"><span>' . esc_html($label) . '</span><span class="sorting-indicator"></span></a></th>';
}

    /**
     * Devuelve una matriz completa con las definiciones para todos los tipos de bloqueo.
     * Esta es la ÚNICA FUENTE DE VERDAD para la configuración de cada tipo de bloqueo.
     *
     * @return array
     */
    public function get_all_block_type_definitions() {
        return [
            // El 'key' es el identificador técnico, usado en logs, transients, etc.
            'geoblock' => [
                'label'         => __('Geoblock', 'advanced-ip-blocker'),
                'option_key'    => self::OPTION_BLOCKED_GEO,
                'duration_key'  => 'duration_geoblock',
                'uses_transient'=> true
            ],
			'geo_challenge' => [
                'label'         => __('Geo-Challenge', 'advanced-ip-blocker'),
                'option_key'    => null, 'duration_key' => null, 'uses_transient' => false
            ],
            'honeypot' => [
                'label'         => __('Honeypot', 'advanced-ip-blocker'),
                'option_key'    => self::OPTION_BLOCKED_HONEYPOT,
                'duration_key'  => 'duration_honeypot',
                'uses_transient'=> true
            ],
            'user_agent' => [
                'label'         => __('User-Agent', 'advanced-ip-blocker'),
                'option_key'    => self::OPTION_BLOCKED_USER_AGENT,
                'duration_key'  => 'duration_user_agent',
                'uses_transient'=> true
            ],
            'manual' => [
                'label'         => __('Manual Block', 'advanced-ip-blocker'),
                'option_key'    => self::OPTION_BLOCKED_MANUAL,
                'duration_key'  => null, // Permanente
                'uses_transient'=> false // No necesita transient, se comprueba siempre
            ],
            'bulk_import' => [
                'label'         => __('Bulk Import', 'advanced-ip-blocker'),
                'option_key'    => null, // Managed just like manual blocks, but conceptually separated.
                'duration_key'  => null,
                'uses_transient'=> false
            ],
            '404' => [
                'label'         => __('404 Error', 'advanced-ip-blocker'),
                'option_key'    => self::OPTION_BLOCKED_404,
                'duration_key'  => 'duration_404',
                'uses_transient'=> true
            ],
            '403' => [
                'label'         => __('403 Error', 'advanced-ip-blocker'),
                'option_key'    => self::OPTION_BLOCKED_403,
                'duration_key'  => 'duration_403',
                'uses_transient'=> true
            ],
            'login' => [
                'label'         => __('Login Failure', 'advanced-ip-blocker'),
                'option_key'    => self::OPTION_BLOCKED_LOGIN,
                'duration_key'  => 'duration_login',
                'uses_transient'=> true
            ],
            'waf' => [
                'label'         => __('WAF Block', 'advanced-ip-blocker'),
                'option_key'    => self::OPTION_BLOCKED_WAF,
                'duration_key'  => 'duration_waf',
                'uses_transient'=> true
            ],
            'rate_limit' => [
                'label'         => __('Rate Limit', 'advanced-ip-blocker'),
                'option_key'    => self::OPTION_BLOCKED_RATE_LIMIT,
                'duration_key'  => 'duration_rate_limit',
                'uses_transient'=> true
            ],
            'asn' => [
                'label'         => __('ASN Block', 'advanced-ip-blocker'),
                'option_key'    => self::OPTION_BLOCKED_ASN,
                'duration_key'  => 'duration_asn',
                'uses_transient'=> true
            ],
            'xmlrpc_block' => [
                'label'         => __('XML-RPC Block', 'advanced-ip-blocker'),
                'option_key'    => self::OPTION_BLOCKED_XMLRPC,
                'duration_key'  => 'duration_xmlrpc_block',
                'uses_transient'=> true
            ],
            'threat_score' => [
                'label'         => __('Threat Score', 'advanced-ip-blocker'),
                'option_key'    => self::OPTION_BLOCKED_THREAT_SCORE,
                'duration_key'  => 'duration_threat_score',
                'uses_transient'=> true
            ],
            // Tipos de log que no son bloqueos persistentes
            'signature_challenge' => [
                'label'         => __('Signature Challenge', 'advanced-ip-blocker'),
                'option_key'    => null, 'duration_key' => null, 'uses_transient' => false
            ],
            'signature_flagged' => [
                'label'         => __('Signature Flagged', 'advanced-ip-blocker'),
                'option_key'    => null, 'duration_key' => null, 'uses_transient' => false
            ],
            'endpoint_challenge' => [
                'label'         => __('Endpoint Challenge', 'advanced-ip-blocker'),
                'option_key'    => null, 'duration_key' => null, 'uses_transient' => false
            ],
			// En get_all_block_type_definitions()
            'impersonation' => [
                'label'         => __('Bot Impersonation', 'advanced-ip-blocker'),
                'option_key'    => null, 
                'duration_key'  => 'duration_user_agent', // <-- Reutiliza la duración de User-Agent
                'uses_transient' => true 
            ],
			'abuseipdb' => [
                'label'         => __('AbuseIPDB', 'advanced-ip-blocker'),
                'option_key'    => null, // No es una lista persistente de IPs
                'duration_key'  => 'duration_abuseipdb', // Usaremos una nueva opción de duración
                'uses_transient'=> true
            ],
            'abuseipdb_challenge' => [
                'label'         => __('AbuseIPDB Challenge', 'advanced-ip-blocker'),
                'option_key'    => null, 'duration_key' => null, 'uses_transient' => false
            ],
			'aib_network' => [
                'label'         => __('AIB Community Block', 'advanced-ip-blocker'),
                'option_key'    => null, 
                'duration_key'  => 'duration_aib_network',
                'uses_transient'=> true
            ],
			'aib_network_challenge' => [
                'label'         => __('AIB Community Challenge', 'advanced-ip-blocker'),
                'option_key'    => null,
                'duration_key'  => null,
                'uses_transient'=> false
            ],
			'advanced_rule' => [
                'label'         => __('Advanced Rule', 'advanced-ip-blocker'),
                'option_key'    => null, // No usa una opción de wp_options, usa su propia tabla/lógica.
                'duration_key'  => null, // La duración es por regla, no global.
                'uses_transient'=> true   // Un bloqueo es un bloqueo, debe tener un transient.
            ],
			    'advanced_rule_allow' => [
                'label'         => __('Advanced Rule (Allow)', 'advanced-ip-blocker'),
                'option_key'    => null, 'duration_key' => null, 'uses_transient' => false
            ],
        ];
    }        
    
    /**
     * Limpia la entrada de la caché de objetos para la lista de IPs bloqueadas.
     * Debe ser llamada cada vez que la tabla _advaipbl_blocked_ips es modificada.
     */
    private function clear_blocked_ips_cache() {
        wp_cache_delete('advaipbl_all_blocked_entries', 'advaipbl');
    }

    public function get_all_blocked_entries() {
        // Clave única para la caché de esta petición.
        $cache_key = 'advaipbl_all_blocked_entries';
        // Grupo para nuestra caché, una buena práctica.
        $cache_group = 'advaipbl';

        // 1. Intentar obtener los datos de la caché de memoria RAM primero.
        $cached_entries = wp_cache_get($cache_key, $cache_group);
        if (false !== $cached_entries) {
            // ¡Éxito! Los datos ya estaban en la caché. Los devolvemos directamente.
            return $cached_entries;
        }

        // 2. Si no estaban en la caché, los generamos desde la base de datos.
        global $wpdb;
        $table_name = $wpdb->prefix . 'advaipbl_blocked_ips';
        $definitions = $this->get_all_block_type_definitions();

        $table_name = $wpdb->prefix . 'advaipbl_blocked_ips';
        $definitions = $this->get_all_block_type_definitions();
        
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $results = $wpdb->get_results("SELECT * FROM {$table_name}", ARRAY_A);

        $all_blocked = [];
        if (!empty($results)) {
            foreach ($results as $row) {
                $all_blocked[] = [
                    'ip'         => $row['ip_range'],
                    'type'       => $row['block_type'],
                    'type_label' => $definitions[$row['block_type']]['label'] ?? ucwords(str_replace('_', ' ', $row['block_type'])),
                    'timestamp'  => $row['timestamp'],
                    'detail'     => $row['reason'],
                ];
            }
        }
        
        // 3. Antes de devolver los datos, los guardamos en la caché de memoria
        wp_cache_set($cache_key, $all_blocked, $cache_group);

        return $all_blocked;
    }
    	
	/**
	 * Sanitizes the reCAPTCHA v3 score threshold.
	 *
	 * @param mixed $input The input value.
	 * @return float The sanitized score, clamped between 0.1 and 1.0.
	 */
	public function sanitize_score_threshold($input) {
    $score = (float) $input;
    if ($score < 0.1) { return 0.1; }
    if ($score > 1.0) { return 1.0; }
    return $score;
    }
	
    /**
     * Devuelve una lista de países (Código => Nombre).
     * @return array
     */
    public function get_country_list() {
        // Esta lista se puede expandir o mover a un archivo separado si se desea.
        return [
            	'AF' => 'Afghanistan',
	'AX' => 'Aland Islands',
	'AL' => 'Albania',
	'DZ' => 'Algeria',
	'AS' => 'American Samoa',
	'AD' => 'Andorra',
	'AO' => 'Angola',
	'AI' => 'Anguilla',
	'AQ' => 'Antarctica',
	'AG' => 'Antigua And Barbuda',
	'AR' => 'Argentina',
	'AM' => 'Armenia',
	'AW' => 'Aruba',
	'AU' => 'Australia',
	'AT' => 'Austria',
	'AZ' => 'Azerbaijan',
	'BS' => 'Bahamas',
	'BH' => 'Bahrain',
	'BD' => 'Bangladesh',
	'BB' => 'Barbados',
	'BY' => 'Belarus',
	'BE' => 'Belgium',
	'BZ' => 'Belize',
	'BJ' => 'Benin',
	'BM' => 'Bermuda',
	'BT' => 'Bhutan',
	'BO' => 'Bolivia',
	'BA' => 'Bosnia And Herzegovina',
	'BW' => 'Botswana',
	'BV' => 'Bouvet Island',
	'BR' => 'Brazil',
	'IO' => 'British Indian Ocean Territory',
	'BN' => 'Brunei Darussalam',
	'BG' => 'Bulgaria',
	'BF' => 'Burkina Faso',
	'BI' => 'Burundi',
	'KH' => 'Cambodia',
	'CM' => 'Cameroon',
	'CA' => 'Canada',
	'CV' => 'Cape Verde',
	'KY' => 'Cayman Islands',
	'CF' => 'Central African Republic',
	'TD' => 'Chad',
	'CL' => 'Chile',
	'CN' => 'China',
	'CX' => 'Christmas Island',
	'CC' => 'Cocos (Keeling) Islands',
	'CO' => 'Colombia',
	'KM' => 'Comoros',
	'CG' => 'Congo',
	'CD' => 'Congo, Democratic Republic',
	'CK' => 'Cook Islands',
	'CR' => 'Costa Rica',
	'CI' => 'Cote D\'Ivoire',
	'HR' => 'Croatia',
	'CU' => 'Cuba',
	'CY' => 'Cyprus',
	'CZ' => 'Czech Republic',
	'DK' => 'Denmark',
	'DJ' => 'Djibouti',
	'DM' => 'Dominica',
	'DO' => 'Dominican Republic',
	'EC' => 'Ecuador',
	'EG' => 'Egypt',
	'SV' => 'El Salvador',
	'GQ' => 'Equatorial Guinea',
	'ER' => 'Eritrea',
	'EE' => 'Estonia',
	'ET' => 'Ethiopia',
	'FK' => 'Falkland Islands (Malvinas)',
	'FO' => 'Faroe Islands',
	'FJ' => 'Fiji',
	'FI' => 'Finland',
	'FR' => 'France',
	'GF' => 'French Guiana',
	'PF' => 'French Polynesia',
	'TF' => 'French Southern Territories',
	'GA' => 'Gabon',
	'GM' => 'Gambia',
	'GE' => 'Georgia',
	'DE' => 'Germany',
	'GH' => 'Ghana',
	'GI' => 'Gibraltar',
	'GR' => 'Greece',
	'GL' => 'Greenland',
	'GD' => 'Grenada',
	'GP' => 'Guadeloupe',
	'GU' => 'Guam',
	'GT' => 'Guatemala',
	'GG' => 'Guernsey',
	'GN' => 'Guinea',
	'GW' => 'Guinea-Bissau',
	'GY' => 'Guyana',
	'HT' => 'Haiti',
	'HM' => 'Heard Island & Mcdonald Islands',
	'VA' => 'Holy See (Vatican City State)',
	'HN' => 'Honduras',
	'HK' => 'Hong Kong',
	'HU' => 'Hungary',
	'IS' => 'Iceland',
	'IN' => 'India',
	'ID' => 'Indonesia',
	'IR' => 'Iran, Islamic Republic Of',
	'IQ' => 'Iraq',
	'IE' => 'Ireland',
	'IM' => 'Isle Of Man',
	'IL' => 'Israel',
	'IT' => 'Italy',
	'JM' => 'Jamaica',
	'JP' => 'Japan',
	'JE' => 'Jersey',
	'JO' => 'Jordan',
	'KZ' => 'Kazakhstan',
	'KE' => 'Kenya',
	'KI' => 'Kiribati',
	'KR' => 'Korea',
	'KW' => 'Kuwait',
	'KG' => 'Kyrgyzstan',
	'LA' => 'Lao People\'s Democratic Republic',
	'LV' => 'Latvia',
	'LB' => 'Lebanon',
	'LS' => 'Lesotho',
	'LR' => 'Liberia',
	'LY' => 'Libyan Arab Jamahiriya',
	'LI' => 'Liechtenstein',
	'LT' => 'Lithuania',
	'LU' => 'Luxembourg',
	'MO' => 'Macao',
	'MK' => 'Macedonia',
	'MG' => 'Madagascar',
	'MW' => 'Malawi',
	'MY' => 'Malaysia',
	'MV' => 'Maldives',
	'ML' => 'Mali',
	'MT' => 'Malta',
	'MH' => 'Marshall Islands',
	'MQ' => 'Martinique',
	'MR' => 'Mauritania',
	'MU' => 'Mauritius',
	'YT' => 'Mayotte',
	'MX' => 'Mexico',
	'FM' => 'Micronesia, Federated States Of',
	'MD' => 'Moldova',
	'MC' => 'Monaco',
	'MN' => 'Mongolia',
	'ME' => 'Montenegro',
	'MS' => 'Montserrat',
	'MA' => 'Morocco',
	'MZ' => 'Mozambique',
	'MM' => 'Myanmar',
	'NA' => 'Namibia',
	'NR' => 'Nauru',
	'NP' => 'Nepal',
	'NL' => 'Netherlands',
	'AN' => 'Netherlands Antilles',
	'NC' => 'New Caledonia',
	'NZ' => 'New Zealand',
	'NI' => 'Nicaragua',
	'NE' => 'Niger',
	'NG' => 'Nigeria',
	'NU' => 'Niue',
	'NF' => 'Norfolk Island',
	'MP' => 'Northern Mariana Islands',
	'NO' => 'Norway',
	'OM' => 'Oman',
	'PK' => 'Pakistan',
	'PW' => 'Palau',
	'PS' => 'Palestinian Territory, Occupied',
	'PA' => 'Panama',
	'PG' => 'Papua New Guinea',
	'PY' => 'Paraguay',
	'PE' => 'Peru',
	'PH' => 'Philippines',
	'PN' => 'Pitcairn',
	'PL' => 'Poland',
	'PT' => 'Portugal',
	'PR' => 'Puerto Rico',
	'QA' => 'Qatar',
	'RE' => 'Reunion',
	'RO' => 'Romania',
	'RU' => 'Russian Federation',
	'RW' => 'Rwanda',
	'BL' => 'Saint Barthelemy',
	'SH' => 'Saint Helena',
	'KN' => 'Saint Kitts And Nevis',
	'LC' => 'Saint Lucia',
	'MF' => 'Saint Martin',
	'PM' => 'Saint Pierre And Miquelon',
	'VC' => 'Saint Vincent And Grenadines',
	'WS' => 'Samoa',
	'SM' => 'San Marino',
	'ST' => 'Sao Tome And Principe',
	'SA' => 'Saudi Arabia',
	'SN' => 'Senegal',
	'RS' => 'Serbia',
	'SC' => 'Seychelles',
	'SL' => 'Sierra Leone',
	'SG' => 'Singapore',
	'SK' => 'Slovakia',
	'SI' => 'Slovenia',
	'SB' => 'Solomon Islands',
	'SO' => 'Somalia',
	'ZA' => 'South Africa',
	'GS' => 'South Georgia And Sandwich Isl.',
	'ES' => 'Spain',
	'LK' => 'Sri Lanka',
	'SD' => 'Sudan',
	'SR' => 'Suriname',
	'SJ' => 'Svalbard And Jan Mayen',
	'SZ' => 'Swaziland',
	'SE' => 'Sweden',
	'CH' => 'Switzerland',
	'SY' => 'Syrian Arab Republic',
	'TW' => 'Taiwan',
	'TJ' => 'Tajikistan',
	'TZ' => 'Tanzania',
	'TH' => 'Thailand',
	'TL' => 'Timor-Leste',
	'TG' => 'Togo',
	'TK' => 'Tokelau',
	'TO' => 'Tonga',
	'TT' => 'Trinidad And Tobago',
	'TN' => 'Tunisia',
	'TR' => 'Turkey',
	'TM' => 'Turkmenistan',
	'TC' => 'Turks And Caicos Islands',
	'TV' => 'Tuvalu',
	'UG' => 'Uganda',
	'UA' => 'Ukraine',
	'AE' => 'United Arab Emirates',
	'GB' => 'United Kingdom',
	'US' => 'United States',
	'UM' => 'United States Outlying Islands',
	'UY' => 'Uruguay',
	'UZ' => 'Uzbekistan',
	'VU' => 'Vanuatu',
	'VE' => 'Venezuela',
	'VN' => 'Viet Nam',
	'VG' => 'Virgin Islands, British',
	'VI' => 'Virgin Islands, U.S.',
	'WF' => 'Wallis And Futuna',
	'EH' => 'Western Sahara',
	'YE' => 'Yemen',
	'ZM' => 'Zambia',
	'ZW' => 'Zimbabwe',
        ];
    }


	     
     /**
     * Muestra el aviso para solicitar el consentimiento de telemetría.
     */
    public function display_telemetry_notice() {
        // Condición 1: Solo mostrar en las páginas de nuestro plugin.
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $page = isset($_GET['page']) ? sanitize_text_field(wp_unslash($_GET['page'])) : '';
        if (strpos($page, 'advaipbl_settings_page') === false) {
            return;
        }

        // Condición 2: Si el usuario ya ha activado la telemetría, no mostrar.
        if (!empty($this->options['allow_telemetry']) && '1' === $this->options['allow_telemetry']) {
            return;
        }
        
        // Condición 3: Si el usuario ya ha descartado el aviso, no mostrar.
        // get_option devolverá 'false' si no existe, lo cual es correcto.
        if (get_option('advaipbl_telemetry_notice_dismissed')) {
            return;
        }
        ?>
        <div class="notice notice-info is-dismissible advaipbl-telemetry-notice">
            <p style="font-size: 14px; line-height: 1.6;">
                <strong><?php esc_html_e('Help Improve Advanced IP Blocker!', 'advanced-ip-blocker'); ?></strong><br>
                <?php esc_html_e('Allow us to collect anonymous usage data to understand how the plugin is used and make it better. We do not collect any sensitive or personal data.', 'advanced-ip-blocker'); ?>
                <a href="https://advaipbl.com/privacy-policy/" target="_blank"><?php esc_html_e('Learn More', 'advanced-ip-blocker'); ?></a>
            </p>
            <p>
                <button class="button button-primary" id="advaipbl-allow-telemetry"><?php esc_html_e('Allow & Continue', 'advanced-ip-blocker'); ?></button>
                <button class="button button-secondary" id="advaipbl-dismiss-telemetry-notice" style="margin-left: 10px;"><?php esc_html_e('Do not allow', 'advanced-ip-blocker'); ?></button>
            </p>
        </div>
        <?php
    }
	
	 /**
     * Recopila y envía datos de telemetría anónimos a un endpoint de API REST.
     * Se ejecuta a través de una tarea de WP-Cron.
     */
    /**
     * Genera el payload de telemetría de uso del plugin.
     * @return array
     */
    private function get_telemetry_payload() {
        global $wpdb;
        $is_woocommerce_active = class_exists('WooCommerce');
        
        $telemetry_data = [
            'site_url'       => home_url(),
            'plugin_version' => ADVAIPBL_VERSION,
            'wp_version'     => get_bloginfo('version'),
            'php_version'    => PHP_VERSION,
            'is_multisite'   => is_multisite(),
            'site_locale'    => get_locale(),
            'server_country' => 'N/A',
            'store_country'  => 'N/A',
            'user_count'     => count_users()['total_users'] ?? 0,
            'is_woo_active'  => $is_woocommerce_active,
            'geo_provider'   => $this->options['geolocation_provider'] ?? 'N/A',
            'geolocation_method' => $this->options['geolocation_method'] ?? 'api',
        ];

        if ($is_woocommerce_active) {
            $woo_country = get_option('woocommerce_default_country');
            if ($woo_country) {
                $country_parts = explode(':', $woo_country);
                $telemetry_data['store_country'] = $country_parts[0];
            }
        }
        
        // Array de settings completo que refleja todos los módulos principales.
        $telemetry_data['settings'] = [
            'enable_waf'                  => !empty($this->options['enable_waf']),
            'rate_limiting_enable'        => !empty($this->options['rate_limiting_enable']),
            'enable_geoblocking'          => !empty($this->options['enable_geoblocking']),
            'enable_honeypot_blocking'    => !empty($this->options['enable_honeypot_blocking']),
            'enable_user_agent_blocking'  => !empty($this->options['enable_user_agent_blocking']),
            'enable_spamhaus_asn'         => !empty($this->options['enable_spamhaus_asn']),
            'enable_manual_asn'           => !empty($this->options['enable_manual_asn']),
            'enable_abuseipdb'            => !empty($this->options['enable_abuseipdb']),
            'xmlrpc_protection_mode'      => $this->options['xmlrpc_protection_mode'] ?? 'smart',
            'recaptcha_enable'            => !empty($this->options['recaptcha_enable']),
            'enable_push_notifications'   => !empty($this->options['enable_push_notifications']),
            'enable_threat_scoring'       => !empty($this->options['enable_threat_scoring']),
            'auto_whitelist_admin'        => !empty($this->options['auto_whitelist_admin']),
            'disable_user_enumeration'    => !empty($this->options['disable_user_enumeration']),
            'prevent_author_scanning'     => !empty($this->options['prevent_author_scanning']),
            'restrict_login_page'         => !empty($this->options['restrict_login_page']),
            'prevent_login_hinting'       => !empty($this->options['prevent_login_hinting']),
            'enable_email_notifications'  => !empty($this->options['enable_email_notifications']),
            'enable_signature_engine'     => !empty($this->options['enable_signature_engine']),
            'enable_signature_analysis'   => !empty($this->options['enable_signature_analysis']),
            'enable_signature_blocking'   => !empty($this->options['enable_signature_blocking']),
            'enable_2fa'                  => !empty($this->options['enable_2fa']),
            'enable_xmlrpc_lockdown'      => !empty($this->options['enable_xmlrpc_lockdown']),
            'enable_login_lockdown'       => !empty($this->options['enable_login_lockdown']),
            'enable_404_lockdown'         => !empty($this->options['enable_404_lockdown']),
            'enable_403_lockdown'         => !empty($this->options['enable_403_lockdown']),
            'enable_cloudflare'           => !empty($this->options['enable_cloudflare']),
            'enable_scheduled_scans'      => !empty($this->options['enable_scheduled_scans']),
            'enable_audit_log'            => !empty($this->options['enable_audit_log']),
            'enable_fim'                  => !empty($this->options['enable_fim']),
            'enable_bot_verification'     => !empty($this->options['enable_bot_verification']),
            'enable_geo_challenge'        => !empty($this->options['enable_geo_challenge']),
            'htaccess_write'              => !empty($this->options['enable_htaccess_write']),
            'htaccess_sync_ips'           => !empty($this->options['enable_htaccess_ip_blocking']),
            'htaccess_include_temps'      => !empty($this->options['enable_htaccess_all_ips']),
            'htaccess_hardening_system'   => !empty($this->options['htaccess_protect_system_files']),
            'htaccess_hardening_config'   => !empty($this->options['htaccess_protect_wp_config']),
            'htaccess_hardening_readme'   => !empty($this->options['htaccess_protect_readme']),
            'cloudflare_enabled'          => !empty($this->options['enable_cloudflare']),
            'cloudflare_sync_manual'      => !empty($this->options['cf_sync_manual']),
            'cloudflare_sync_temp'        => !empty($this->options['cf_sync_temporary']),
            'aib_network_join'            => !empty($this->options['enable_community_network']),
            'aib_network_block'           => !empty($this->options['enable_community_blocking']),            
        ];

        $seven_days_ago = gmdate('Y-m-d H:i:s', strtotime('-7 days'));
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $blocks_by_type_results = $wpdb->get_results( $wpdb->prepare(
            "SELECT log_type, COUNT(log_id) as count FROM {$wpdb->prefix}advaipbl_logs WHERE level = 'critical' AND timestamp >= %s GROUP BY log_type",
            $seven_days_ago
        ), ARRAY_A);

        $blocks_by_type_7d = [];
        foreach ($blocks_by_type_results as $row) {
            $blocks_by_type_7d[$row['log_type']] = (int) $row['count'];
        }

        $telemetry_data['stats'] = [
            'whitelist_count'         => count(get_option(self::OPTION_WHITELIST, [])),
            'manual_block_count'      => count(get_option(self::OPTION_BLOCKED_MANUAL, [])),
            'waf_rules_count'         => count(array_filter(explode("\n", get_option(self::OPTION_WAF_RULES, '')))),
            'honeypot_urls_count'     => count(get_option(self::OPTION_HONEYPOT_URLS, [])),
            'blocked_user_agents_count' => count(get_option(self::OPTION_BLOCKED_UAS, [])),
            'manual_asn_count'        => count(get_option(self::OPTION_BLOCKED_ASNS, [])),
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            'total_blocks_7d'         => (int) $wpdb->get_var($wpdb->prepare("SELECT COUNT(log_id) FROM {$wpdb->prefix}advaipbl_logs WHERE level = 'critical' AND timestamp >= %s", $seven_days_ago)),
            'blocks_by_type_7d'       => $blocks_by_type_7d,
            'geoblock_country_count'  => count($this->options['geoblock_countries'] ?? []),
            'active_blocks_count'     => $this->get_blocked_count(),
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            'ips_with_active_score'   => (int) $wpdb->get_var("SELECT COUNT(id) FROM {$wpdb->prefix}advaipbl_ip_scores"),
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            'active_malicious_signatures' => (int) $wpdb->get_var($wpdb->prepare("SELECT COUNT(id) FROM {$wpdb->prefix}advaipbl_malicious_signatures WHERE expires_at > %d", time())),
            'geo_challenge_country_count' => count($this->options['geo_challenge_countries'] ?? []),
        ];

        $server_ip = $this->get_server_ip();
        if ($server_ip) {
            $location = $this->geolocation_manager->fetch_location($server_ip);
            if ($location && empty($location['error']) && !empty($location['country_code'])) {
                $telemetry_data['server_country'] = $location['country_code'];
            }
        }
        
        return $telemetry_data;
    }

    /**
     * Recopila y envía datos de telemetría anónimos a un endpoint de API REST.
     * Se ejecuta a través de una tarea de WP-Cron.
     */
    public function send_telemetry_data() {
        if (empty($this->options['allow_telemetry']) || '1' !== $this->options['allow_telemetry']) {
            return;
        }

        // Si tenemos V3 y participamos en la red comunitaria, la telemetría viaja incrustada
        // en 'execute_community_report' para ahorrar envíos. Se anula el envío V2 aislado.
        if (!empty($this->options['api_token_v3']) && !empty($this->options['enable_community_network'])) {
            return;
        }

        $telemetry_data = $this->get_telemetry_payload();

        $endpoint_url = 'https://advaipbl.com/wp-json/telemetry/v2/submit';
        $secret_key   = 'yV.vZRp|g6E{zJ,DI7WcMIiGDejmH($$~<0-I$$Bd7Y) D5Z65M/*P:h>w:/E<D<';

        $headers = [
            'Content-Type'    => 'application/json',
            'X-Telemetry-Key' => $secret_key
        ];

        // Incluir Token V3 como fallback si llegara aquí, aunque V3 debe saltar arriba.
        if (!empty($this->options['api_token_v3'])) {
            $headers['Authorization'] = 'Bearer ' . $this->options['api_token_v3'];
        }

        wp_remote_post($endpoint_url, [
            'timeout'   => 15,
            'blocking'  => false,
            'headers'   => $headers,
            'body'      => wp_json_encode($telemetry_data),
        ]);
    }
	 
public function handle_export_settings_ajax() {
    try {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( ['message' => 'Permission denied.'] );
            return;
        }
        check_ajax_referer( 'advaipbl_export_nonce', 'nonce' );

        $export_type_raw = isset( $_POST['export_type'] ) ? sanitize_text_field(wp_unslash($_POST['export_type'])) : 'template';
        $export_type = in_array( $export_type_raw, ['template', 'full_backup'] ) ? $export_type_raw : 'template';

        global $wpdb;
        $settings_to_export = [];

        // 1. Exportar todas las opciones del plugin de la tabla wp_options
        $options = $wpdb->get_results( "SELECT option_name, option_value FROM {$wpdb->options} WHERE option_name LIKE 'advaipbl_%'" );
        foreach ($options as $option) {
            $settings_to_export[$option->option_name] = maybe_unserialize($option->option_value);
        }

        // 2. Exportar la tabla de IPs bloqueadas
        $table_name = $wpdb->prefix . 'advaipbl_blocked_ips';
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $blocked_ips_data = $wpdb->get_results("SELECT ip_range, block_type, timestamp, expires_at, reason FROM {$table_name}", ARRAY_A);
        if (!empty($blocked_ips_data)) {
            $settings_to_export['blocked_ips_table'] = $blocked_ips_data;
        }

        // 3. Si es una plantilla, eliminar claves sensibles
        if ($export_type === 'template' && isset($settings_to_export[self::OPTION_SETTINGS])) {
            $sensitive_keys = [
                'recaptcha_site_key', 'recaptcha_secret_key', 
                'api_key_ipapicom', 'api_key_ipstackcom', 'api_key_ipinfocom', 
                'api_key_ip_apicom', 'maxmind_license_key', 'push_webhook_urls',
                'cf_api_token', 'cf_zone_id', 'abuseipdb_api_key', 'api_token_v3'
            ];
            foreach ($sensitive_keys as $sensitive_key) {
                if (isset($settings_to_export[self::OPTION_SETTINGS][$sensitive_key])) {
                    $settings_to_export[self::OPTION_SETTINGS][$sensitive_key] = '';
                }
            }
        }

        $this->log_event( sprintf( 'Plugin settings prepared for export as \'%1$s\' by %2$s.', $export_type, $this->get_current_admin_username() ), 'info' );

        wp_send_json_success( ['settings' => $settings_to_export, 'type' => $export_type] );

    } catch (Throwable $e) {
        $this->log_event( 'An unexpected error occurred during settings export: ' . $e->getMessage(), 'critical' );
        wp_send_json_error(['message' => 'An unexpected server error occurred. Please check the plugin logs.']);
    }
}

public function handle_import_settings() {
    if ( ! isset( $_POST['advaipbl_import_nonce_field'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['advaipbl_import_nonce_field'] ) ), 'advaipbl_import_nonce' ) ) {
        wp_die( 'Security check failed.', 'Error', ['response' => 403] );
    }
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( 'Permission denied.', 'Error', ['response' => 403] );
    }

    $message = '';
    $type = 'error';

    $file_error = isset($_FILES['advaipbl_import_file']['error']) ? (int) $_FILES['advaipbl_import_file']['error'] : UPLOAD_ERR_NO_FILE;
    if ( isset( $_FILES['advaipbl_import_file'] ) && UPLOAD_ERR_OK === $file_error ) {
        $file_name = isset( $_FILES['advaipbl_import_file']['name'] ) ? sanitize_file_name(wp_unslash($_FILES['advaipbl_import_file']['name'])) : '';
        if ( 'json' !== pathinfo( $file_name, PATHINFO_EXTENSION ) ) {
            $message = __( 'Error: The uploaded file is not a .json file.', 'advanced-ip-blocker' );
            $this->log_event( sprintf( 'A failed settings import was attempted by %s (invalid file type).', $this->get_current_admin_username() ), 'error' );
        } else {
            $tmp_name = isset( $_FILES['advaipbl_import_file']['tmp_name'] ) ? sanitize_text_field(wp_unslash($_FILES['advaipbl_import_file']['tmp_name'])) : '';
            if (empty($tmp_name)) {
                return;
            }
            $file_content = file_get_contents( $tmp_name );
            $settings_to_import = json_decode( $file_content, true );

            if ( JSON_ERROR_NONE === json_last_error() && is_array( $settings_to_import ) ) {
                // Compatibilidad: Si el JSON tiene la estructura moderna {'settings': ..., 'type': ...}, extraemos 'settings'.
                if ( isset( $settings_to_import['settings'] ) && is_array( $settings_to_import['settings'] ) ) {
                    $settings_to_import = $settings_to_import['settings'];
                }

                $imported_options_count = 0;
                $imported_ips_count = 0;

                // 1. Procesar las opciones y la tabla
                foreach ( $settings_to_import as $key => $value ) {
                    // Importar solo opciones que empiecen con nuestro prefijo
                    if (strpos($key, 'advaipbl_') === 0) {
                        update_option( $key, $value );
                        $imported_options_count++;
                    } 
                    // Lógica especial para la tabla de IPs
                    elseif ($key === 'blocked_ips_table' && is_array($value)) {
                        global $wpdb;
                        $table_name = $wpdb->prefix . 'advaipbl_blocked_ips';
                        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
                        $wpdb->query("TRUNCATE TABLE `{$table_name}`");
                        
                        foreach ($value as $row) {
                            $data_to_insert = [
                                'ip_range'   => isset($row['ip_range']) ? sanitize_text_field($row['ip_range']) : null,
                                'block_type' => isset($row['block_type']) ? sanitize_key($row['block_type']) : 'manual',
                                'timestamp'  => isset($row['timestamp']) ? absint($row['timestamp']) : time(),
                                'expires_at' => isset($row['expires_at']) ? absint($row['expires_at']) : 0,
                                'reason'     => isset($row['reason']) ? sanitize_textarea_field($row['reason']) : '',
                            ];
                            if ($data_to_insert['ip_range'] !== null) {
                                $wpdb->insert($table_name, $data_to_insert);
                                $imported_ips_count++;
                            }
                        }
                        $this->clear_blocked_ips_cache();
                    }
                }
                
                if ($imported_options_count > 0 || $imported_ips_count > 0) {
                     $message = sprintf(/* translators: %1$d: Number of restored options. %2$d: Number of blocked IPs. */
                         __('Settings imported successfully. Restored %1$d option groups and %2$d blocked IP entries.', 'advanced-ip-blocker'),
                         $imported_options_count,
                         $imported_ips_count
                     );
                     $type = 'success';
					 /* translators: %s: Admin Username. */
                     $this->log_event( sprintf( 'Plugin settings successfully imported by %s.', $this->get_current_admin_username() ), 'warning' );

                     // Check if maxmind key was imported and reschedule cron to run almost instantly (1 minute).
                     $imported_settings = get_option(self::OPTION_SETTINGS, []);
                     if (!empty($imported_settings['maxmind_license_key'])) {
                         wp_clear_scheduled_hook('advaipbl_update_geoip_db_event');
                         wp_schedule_event(time() + 60, 'advaipbl_3_days', 'advaipbl_update_geoip_db_event');
                     }

                } else {
                     $message = __( 'Error: The imported file did not contain any valid settings for this plugin.', 'advanced-ip-blocker' );
                     $type = 'error';
					 /* translators: %s: Admin Username. */
                     $this->log_event( sprintf( 'A failed settings import was attempted by %s (no valid keys found).', $this->get_current_admin_username() ), 'error' );
                }

            } else {
                $message = __( 'Error: The uploaded file is not a valid JSON file.', 'advanced-ip-blocker' );
				/* translators: %s: Admin Username. */
                $this->log_event( sprintf( 'A failed settings import was attempted by %s (invalid JSON file).', $this->get_current_admin_username() ), 'error' );
            }
        }
    } else {
        $message = __( 'Error: No file was uploaded or an error occurred during upload.', 'advanced-ip-blocker' );
		/* translators: %s: Admin Username. */
        $this->log_event( sprintf( 'A failed settings import was attempted by %s (file upload error).', $this->get_current_admin_username() ), 'error' );
    }

    set_transient( self::TRANSIENT_ADMIN_NOTICE, ['message' => $message, 'type' => $type], 30 );
    wp_safe_redirect( admin_url( 'admin.php?page=advaipbl_settings_page-settings&sub-tab=import_export' ) );
    exit;
}

        /**
     * Muestra la sección de configuración de 2FA en la página de perfil del usuario.
     *
     * @param WP_User $user El objeto del usuario cuyo perfil se está editando.
     */
        public function display_2fa_section_in_profile( $user ) {
        // 1. Comprobamos si la funcionalidad 2FA está activada globalmente.
        if ( empty( $this->options['enable_2fa'] ) || '1' !== $this->options['enable_2fa'] ) {
            return; // Si no está activado, no mostramos nada y salimos.
        }

        // 2. Nos aseguramos de que el manager de 2FA esté cargado (relevante para CLI).
        if ( ! $this->tfa_manager ) {
            return;
        }
        
        if ( ! current_user_can( 'edit_user', $user->ID ) ) {
            return;
        }

        $is_enabled = $this->tfa_manager->is_2fa_enabled_for_user( $user->ID );
        ?>
        <div id="advaipbl-2fa-section-wrapper">
            <h2><?php esc_html_e( 'Two-Factor Authentication (2FA)', 'advanced-ip-blocker' ); ?></h2>
            <table class="form-table" id="advaipbl-2fa-section" data-user-id="<?php echo esc_attr( $user->ID ); ?>">
                <tbody>
                    <tr>
                        <th><label><?php esc_html_e( 'Status', 'advanced-ip-blocker' ); ?></label></th>
                        <td>
                            <?php if ( $is_enabled ) : ?>
                                <p><span class="dashicons dashicons-yes-alt" style="color: #46b450;"></span> <strong><?php esc_html_e( 'Active', 'advanced-ip-blocker' ); ?></strong></p>
                                <p class="description">
                                    <?php 
                                    $enabled_time = get_user_meta( $user->ID, ADVAIPBL_2fa_Manager::META_ENABLED_AT, true );
									/* translators: $s: Enabled ago. */
                                    printf( esc_html__( 'Enabled %s.', 'advanced-ip-blocker' ), esc_html( human_time_diff( $enabled_time ) ) . ' ' . esc_html__('ago', 'advanced-ip-blocker') );
                                    ?>
                                </p>
                                <button type="button" id="advaipbl-2fa-deactivate-btn" class="button" data-nonce="<?php echo esc_attr( wp_create_nonce( 'advaipbl_2fa_deactivate_nonce' ) ); ?>">
                                    <?php esc_html_e( 'Deactivate 2FA', 'advanced-ip-blocker' ); ?>
                                </button>
                            <?php else : ?>
                                <p><span class="dashicons dashicons-no-alt" style="color: #dc3232;"></span> <strong><?php esc_html_e( 'Inactive', 'advanced-ip-blocker' ); ?></strong></p>
                                <p class="description"><?php esc_html_e( 'Secure your account by enabling two-factor authentication.', 'advanced-ip-blocker' ); ?></p>
                                <button type="button" id="advaipbl-2fa-activate-btn" class="button button-primary" data-nonce="<?php echo esc_attr( wp_create_nonce( 'advaipbl_2fa_generate_nonce' ) ); ?>">
                                    <?php esc_html_e( 'Set Up 2FA', 'advanced-ip-blocker' ); ?>
                                </button>
                            <?php endif; ?>
                        </td>
                    </tr>
                </tbody>
            </table>
            
            <!-- Contenedor para el proceso de configuración (inicialmente oculto) -->
            <div id="advaipbl-2fa-setup-container" style="display: none; margin-top: 1.5em; max-width: 700px;">
                <div class="advaipbl-loader-wrapper" style="text-align: center; padding: 20px;">
                    <div class="advaipbl-loader"></div>
                    <p><?php esc_html_e('Generating your secure codes...', 'advanced-ip-blocker'); ?></p>
                </div>
                
                <div class="advaipbl-setup-content" style="display: none;">
                    <p><strong><?php esc_html_e( 'Step 1: Scan the QR Code', 'advanced-ip-blocker' ); ?></strong></p>
                    <p><?php esc_html_e( 'Use an authenticator app (like Google Authenticator, Authy, or 1Password) to scan this QR code.', 'advanced-ip-blocker' ); ?></p>
                    <div id="advaipbl-qr-code-wrapper"></div>
                    <p><?php esc_html_e( "Can't scan the code? You can manually enter this secret key:", 'advanced-ip-blocker' ); ?><br>
                    <code id="advaipbl-secret-key" style="font-size: 1.2em; padding: 5px; background: #f0f0f1; border-radius: 4px;"></code></p>
                    <hr>
                    <p><strong><?php esc_html_e( 'Step 2: Save Your Backup Codes', 'advanced-ip-blocker' ); ?></strong></p>
                    <div class="notice notice-warning inline"><p><strong><?php esc_html_e( 'IMPORTANT:', 'advanced-ip-blocker' ); ?></strong> <?php esc_html_e( 'Treat these codes like a password. Store them in a safe place. If you lose your phone, these codes are the only way to access your account.', 'advanced-ip-blocker' ); ?></p></div>
                    <div id="advaipbl-backup-codes-wrapper"></div>
                    <hr>
                    <p><strong><?php esc_html_e( 'Step 3: Verify and Activate', 'advanced-ip-blocker' ); ?></strong></p>
                    <p><?php esc_html_e( 'Enter the 6-digit code from your authenticator app to complete the setup.', 'advanced-ip-blocker' ); ?></p>
                    <p>
                        <label for="advaipbl-2fa-verify-code"><?php esc_html_e( 'Verification Code', 'advanced-ip-blocker' ); ?></label><br>
                        <input type="text" id="advaipbl-2fa-verify-code" name="advaipbl_2fa_verify_code" class="regular-text" style="width: 150px;" autocomplete="off" placeholder="123456" maxlength="6">
                    </p>
                    <div class="advaipbl-2fa-actions">
                        <button type="button" id="advaipbl-2fa-finalize-btn" class="button button-primary" data-nonce="<?php echo esc_attr( wp_create_nonce( 'advaipbl_2fa_activate_nonce' ) ); ?>">
                            <?php esc_html_e( 'Activate', 'advanced-ip-blocker' ); ?>
                        </button>
                        <button type="button" id="advaipbl-2fa-cancel-btn" class="button button-secondary">
                            <?php esc_html_e( 'Cancel', 'advanced-ip-blocker' ); ?>
                        </button>
                        <span id="advaipbl-2fa-feedback"></span>
                    </div>
                </div>
            </div>
        </div>
        <style>
            #advaipbl-qr-code-wrapper { background: white; padding: 15px; display: inline-block; border: 1px solid #ccd0d4; }
            #advaipbl-backup-codes-wrapper { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; background: #f9f9f9; border: 1px dashed #ccd0d4; padding: 15px; border-radius: 4px; }
            #advaipbl-backup-codes-wrapper code { font-size: 1.1em; letter-spacing: 1px; padding: 5px; }
            .advaipbl-2fa-actions { display: flex; align-items: center; gap: 10px; }
            #advaipbl-2fa-feedback { font-weight: bold; }
        </style>
        <?php
    }
	
        /**
     * Se ejecuta al inicio de la carga del formulario de login.
     * Su única misión es verificar el código si se envía desde nuestro formulario del paso 2.
     */
    public function handle_login_action() {
        if ( ! isset( $_POST['advaipbl_2fa_login_step'] ) ) { return; }
        $step = sanitize_text_field(wp_unslash($_POST['advaipbl_2fa_login_step']));
        $user_id = isset( $_POST['user_id'] ) ? absint( $_POST['user_id'] ) : 0;
        $code = isset( $_POST['advaipbl_2fa_code'] ) ? trim( sanitize_text_field( wp_unslash($_POST['advaipbl_2fa_code']) ) ) : '';
        $nonce = isset($_POST['_wpnonce']) ? sanitize_text_field(wp_unslash($_POST['_wpnonce'])) : '';
        $user = get_user_by( 'id', $user_id );
        if ( ! $user ) { wp_die( 'Authentication error: Invalid user.' ); }
        $is_valid = false;
        $nonce_action = '';
        $error_action_redirect = '';
        if ( '2' === $step ) {
            $nonce_action = 'advaipbl-2fa-verify-' . $user_id;
            $error_action_redirect = 'advaipbl_validate_2fa';
            if ( wp_verify_nonce( $nonce, $nonce_action ) ) {
                $is_valid = $this->tfa_manager->verify_code( $user->ID, $code );
            }
        } elseif ( 'backup' === $step ) {
            $nonce_action = 'advaipbl-2fa-verify-backup-' . $user_id;
            $error_action_redirect = 'advaipbl_validate_2fa_backup';
            if ( wp_verify_nonce( $nonce, $nonce_action ) ) {
                $is_valid = $this->tfa_manager->is_valid_backup_code( $user->ID, $code );
            }
        }
        if ( $is_valid ) {
            wp_set_auth_cookie( $user->ID, isset( $_POST['rememberme'] ) );
            $redirect_to = (isset( $_REQUEST['redirect_to'] ) && !empty($_REQUEST['redirect_to'])) ? sanitize_text_field(wp_unslash( $_REQUEST['redirect_to'] )) : admin_url();
            wp_safe_redirect( $redirect_to );
            exit;
        } else {
            // Guardamos el tipo de error en una cookie que dura solo unos segundos
            $error_message = ( 'backup' === $step ) 
                ? __( '<strong>ERROR</strong>: The recovery code is incorrect or has already been used.', 'advanced-ip-blocker' )
                : __( '<strong>ERROR</strong>: The verification code is incorrect.', 'advanced-ip-blocker' );
            setcookie( 'advaipbl_login_error', $error_message, time() + 30, COOKIEPATH, COOKIE_DOMAIN );
            
            $redirect_url = add_query_arg([
                'action' => $error_action_redirect,
                'user_id' => $user->ID,
                'wp_auth_nonce' => wp_create_nonce( 'advaipbl-2fa-interim-' . $user->ID ),
                'redirect_to' => isset($_REQUEST['redirect_to']) ? sanitize_text_field(wp_unslash($_REQUEST['redirect_to'])) : '',
            ], site_url( 'wp-login.php', 'login' ) );
            wp_safe_redirect( $redirect_url );
            exit;
        }
    }
	
	    /**
     * Intercepta el login normal (Paso 1). Si el usuario y contraseña son correctos y necesita 2FA,
     * redirige a nuestra pantalla del Paso 2 en lugar de iniciar sesión.
     */
        public function intercept_login_step_1( $user, $username, $password ) {
        if ( is_wp_error( $user ) || ! $user instanceof WP_User ) {
            return $user;
        }

        // Allow Application Passwords (API) to bypass 2FA
        if ( isset( $user->is_application_password ) && $user->is_application_password ) {
            return $user;
        }

        // XML-RPC requests cannot handle web-based 2FA redirects.
        if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
            return $user;
        }
        
        $global_2fa_enabled = ! empty( $this->options['enable_2fa'] ) && '1' === $this->options['enable_2fa'];
        // Ensure tfa_manager is valid and has the method (it is stdClass in some contexts)
        if ( ! $global_2fa_enabled || ! $this->tfa_manager || ! method_exists($this->tfa_manager, 'is_2fa_enabled_for_user') ) {
            return $user;
        }

        $user_has_2fa_setup = $this->tfa_manager->is_2fa_enabled_for_user( $user->ID );
        $user_is_forced = $this->tfa_manager->is_2fa_forced_for_user( $user );
        
        // Si el usuario tiene 2FA configurado, le redirigimos al paso 2.
        if ( $user_has_2fa_setup ) {
            $redirect_url = add_query_arg([
                'action' => 'advaipbl_validate_2fa',
                'user_id' => $user->ID,
                'wp_auth_nonce' => wp_create_nonce( 'advaipbl-2fa-interim-' . $user->ID ),
                // phpcs:ignore WordPress.Security.NonceVerification.Recommended
                'redirect_to' => isset($_REQUEST['redirect_to']) ? sanitize_text_field(wp_unslash($_REQUEST['redirect_to'])) : '',
                // phpcs:ignore WordPress.Security.NonceVerification.Recommended
                'rememberme' => isset($_REQUEST['rememberme']) ? sanitize_text_field(wp_unslash($_REQUEST['rememberme'])) : '',
            ], site_url( 'wp-login.php', 'login' ) );
            wp_safe_redirect( $redirect_url );
            exit;
        }

        // Si el usuario NO tiene 2FA, pero está OBLIGADO a tenerlo...
        if ( ! $user_has_2fa_setup && $user_is_forced ) {
            update_user_meta( $user->ID, '_advaipbl_2fa_setup_required', true );
        }

        // En todos los demás casos (no tiene 2FA y no está obligado), el login es normal.
        return $user;
    }
	
	    /**
     * Muestra nuestro formulario personalizado para el Paso 2 de 2FA.
     */
        public function display_2fa_login_form_step_2() {
        $user_id = isset( $_GET['user_id'] ) ? absint( $_GET['user_id'] ) : 0;
        $nonce = isset($_GET['wp_auth_nonce']) ? sanitize_text_field(wp_unslash($_GET['wp_auth_nonce'])) : '';

        if ( ! $user_id || ! wp_verify_nonce( $nonce, 'advaipbl-2fa-interim-' . $user_id ) ) {
            wp_die( 'Invalid 2FA request.' );
        }

        $message = '';
        if ( isset( $_COOKIE['advaipbl_login_error'] ) ) {
            $message = '<div id="login_error" class="notice notice-error">' . wp_kses_post( wp_unslash($_COOKIE['advaipbl_login_error']) ) . '</div>';
            // Borramos la cookie para que no se muestre de nuevo
            unset( $_COOKIE['advaipbl_login_error'] );
            setcookie( 'advaipbl_login_error', '', time() - 3600, COOKIEPATH, COOKIE_DOMAIN );
        } else {
            $message = '<p class="message">' . esc_html__( 'Enter the code generated by your authenticator app.', 'advanced-ip-blocker' ) . '</p>';
        }
        
        add_filter( 'login_message', function( $original_message ) use ( $message ) {
            return $message;
        });
        
        login_header( __( 'Enter Verification Code', 'advanced-ip-blocker' ) );
        ?>
        <form name="advaipbl_validate_2fa_form" id="loginform" action="<?php echo esc_url( site_url( 'wp-login.php', 'login_post' ) ); ?>" method="post">
            <p>
                <label for="advaipbl_2fa_code"><?php esc_html_e( 'Authentication Code:', 'advanced-ip-blocker' ); ?></label>
                <input type="text" name="advaipbl_2fa_code" id="advaipbl_2fa_code" class="input" value="" size="20" pattern="[0-9]*" inputmode="numeric" autocomplete="one-time-code" placeholder="123 456" />
            </p>
            <input type="hidden" name="user_id" value="<?php echo esc_attr( $user_id ); ?>" />
            <input type="hidden" name="redirect_to" value="<?php echo esc_attr( isset($_REQUEST['redirect_to']) ? sanitize_text_field(wp_unslash($_REQUEST['redirect_to'])) : '' ); ?>" />
            <input type="hidden" name="rememberme" value="<?php echo esc_attr( isset($_REQUEST['rememberme']) ? sanitize_text_field(wp_unslash($_REQUEST['rememberme'])) : '' ); ?>" />
            <input type="hidden" name="advaipbl_2fa_login_step" value="2" />
            <?php wp_nonce_field( 'advaipbl-2fa-verify-' . $user_id ); ?>
            <p class="submit">
                <input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="<?php esc_attr_e( 'Verify', 'advanced-ip-blocker' ); ?>" />
            </p>
        </form>
		<div style="margin-top: 16px; padding: 0 24px;">
            <p style="text-align: center;">
                <a href="<?php
                    echo esc_url( add_query_arg([
                        'action' => 'advaipbl_validate_2fa_backup',
                        'user_id' => $user_id,
                        'wp_auth_nonce' => $nonce,
                        'redirect_to' => isset($_REQUEST['redirect_to']) ? sanitize_text_field(wp_unslash($_REQUEST['redirect_to'])) : '',
                    ], site_url( 'wp-login.php', 'login' ) ) );
                ?>">
                    <?php esc_html_e( 'Use a recovery code', 'advanced-ip-blocker' ); ?>
                </a>
            </p>
        </div>
        <?php
        login_footer();
        exit;
    }
	
	    /**
     * Muestra nuestro formulario personalizado para introducir un código de respaldo.
     */
        public function display_2fa_backup_code_form() {
        $user_id = isset( $_GET['user_id'] ) ? absint( $_GET['user_id'] ) : 0;
        $nonce = isset($_GET['wp_auth_nonce']) ? sanitize_text_field(wp_unslash($_GET['wp_auth_nonce'])) : '';

        if ( ! $user_id || ! wp_verify_nonce( $nonce, 'advaipbl-2fa-interim-' . $user_id ) ) {
            wp_die( 'Invalid recovery code request.' );
        }
        
        $message = '';
        if ( isset( $_COOKIE['advaipbl_login_error'] ) ) {
            $message = '<div id="login_error" class="notice notice-error">' . wp_kses_post( wp_unslash($_COOKIE['advaipbl_login_error']) ) . '</div>';
            unset( $_COOKIE['advaipbl_login_error'] );
            setcookie( 'advaipbl_login_error', '', time() - 3600, COOKIEPATH, COOKIE_DOMAIN );
        } else {
            $message = '<p class="message">' . esc_html__( 'Please enter one of your recovery codes.', 'advanced-ip-blocker' ) . '</p>';
        }

        add_filter( 'login_message', function( $original_message ) use ( $message ) {
            return $message;
        });

        login_header( __( 'Enter Recovery Code', 'advanced-ip-blocker' ) );
        ?>
        <form name="advaipbl_validate_2fa_backup_form" id="loginform" action="<?php echo esc_url( site_url( 'wp-login.php', 'login_post' ) ); ?>" method="post">
            <p>
                <label for="advaipbl_2fa_code"><?php esc_html_e( 'Recovery Code', 'advanced-ip-blocker' ); ?></label>
                <input type="text" name="advaipbl_2fa_code" id="advaipbl_2fa_code" class="input" value="" size="20" autocomplete="off" placeholder="XXXXX-XXXXX" />
            </p>
            <input type="hidden" name="user_id" value="<?php echo esc_attr( $user_id ); ?>" />
            <input type="hidden" name="redirect_to" value="<?php echo esc_attr( isset($_REQUEST['redirect_to']) ? sanitize_text_field(wp_unslash($_REQUEST['redirect_to'])) : '' ); ?>" />
            <input type="hidden" name="rememberme" value="<?php echo esc_attr( isset($_REQUEST['rememberme']) ? sanitize_text_field(wp_unslash($_REQUEST['rememberme'])) : '' ); ?>" />
            <input type="hidden" name="advaipbl_2fa_login_step" value="backup" />
            <?php wp_nonce_field( 'advaipbl-2fa-verify-backup-' . $user_id ); ?>
            <p class="submit">
                <input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="<?php esc_attr_e( 'Verify', 'advanced-ip-blocker' ); ?>" />
            </p>
        </form>
        <div style="margin-top: 16px; padding: 0 24px;">
            <p style="text-align: center;">
                <a href="<?php
                    echo esc_url( add_query_arg([
                        'action' => 'advaipbl_validate_2fa',
                        'user_id' => $user_id,
                        'wp_auth_nonce' => $nonce,
                        'redirect_to' => isset($_REQUEST['redirect_to']) ? sanitize_text_field(wp_unslash($_REQUEST['redirect_to'])) : '',
                    ], site_url( 'wp-login.php', 'login' ) ) );
                ?>">
                    <?php esc_html_e( 'Use an authenticator app code', 'advanced-ip-blocker' ); ?>
                </a>
            </p>
        </div>
        <?php
        login_footer();
        exit;
    }
	
	    /**
     * Imprime el HTML de los modales en el footer de las páginas de administración.
     * Esto asegura que el HTML esté disponible para el JavaScript.
     */
        public function print_modal_html_in_footer() {
        ?>
        <div id="advaipbl-general-confirm-modal" class="advaipbl-modal-overlay" style="display: none;">
            <div class="advaipbl-modal-content" style="max-width: 500px;">
                <h3 class="advaipbl-modal-title" id="advaipbl-confirm-title"><?php esc_html_e('Confirmation Required', 'advanced-ip-blocker'); ?></h3>
                
                <div class="advaipbl-modal-body">
                    <p id="advaipbl-confirm-message"></p>
                </div>

                <div class="advaipbl-modal-footer">
                    <button class="button advaipbl-modal-cancel"><?php esc_html_e('Cancel', 'advanced-ip-blocker'); ?></button>
                    <button id="advaipbl-confirm-action-btn" class="button button-primary"><?php esc_html_e('Confirm', 'advanced-ip-blocker'); ?></button>
                </div>
            </div>
        </div>
        <div id="mapModal" class="advaipbl-modal-overlay" style="display: none;">
             <div class="advaipbl-modal-content" style="width: 80%; height: 80%;">
                  <div id="mapModalHeader" style="text-align: right; margin-bottom: 10px;">
                       <button id="closeModalBtn" class="button"><?php esc_html_e( 'Close', 'advanced-ip-blocker' ); ?></button>
                  </div>
                  <iframe id="mapModalFrame" loading="lazy" style="width: 100%; height: 100%; border: none;"></iframe>
             </div>
        </div>
        <div id="advaipbl-clear-log-modal" class="advaipbl-modal-overlay" style="display: none;">
            <form id="advaipbl-clear-log-form" method="post" action="">
                <input type="hidden" name="action_type" value="clear_specific_logs">
                <?php wp_nonce_field('advaipbl_admin_nonce_action', 'advaipbl_admin_nonce_action'); ?>
                
                <div class="advaipbl-modal-content">
                    <h3 class="advaipbl-modal-title"><?php esc_html_e('Clear Security Logs', 'advanced-ip-blocker'); ?></h3>
                    <div class="advaipbl-modal-body">
                        <p><?php esc_html_e('Please select the types of security logs you want to permanently delete. This action cannot be undone.', 'advanced-ip-blocker'); ?></p>
                        <div id="advaipbl-log-types-checkboxes"></div>
                    </div>
                    <div class="advaipbl-modal-footer">
                        <button type="button" class="button-secondary advaipbl-modal-cancel"><?php esc_html_e('Cancel', 'advanced-ip-blocker'); ?></button>
                        <button type="submit" class="button-primary"><?php esc_html_e('Delete Selected Logs', 'advanced-ip-blocker'); ?></button>
                    </div>
                </div>
            </form>
        </div>
		<div id="advaipbl-lockdown-details-modal" class="advaipbl-modal-overlay" style="display: none;">
            <div class="advaipbl-modal-content" style="max-width: 700px;">
                <h3 class="advaipbl-modal-title"></h3>
                <div class="advaipbl-modal-body">
                    <div class="advaipbl-loader-wrapper" style="text-align: center; padding: 20px;">
                        <div class="advaipbl-loader"></div>
                    </div>
                    <div class="details-content" style="display: none; max-height: 400px; overflow-y: auto;"></div>
                </div>
                <div class="advaipbl-modal-footer">
                    <button class="button advaipbl-modal-cancel"><?php esc_html_e( 'Close', 'advanced-ip-blocker' ); ?></button>
                </div>
            </div>
        </div>
        <?php
    }
	
	    /**
     * Muestra un aviso de administrador persistente si el 2FA es obligatorio y no está configurado.
     */
    public function display_force_2fa_setup_notice() {
        if ( ! is_user_logged_in() || ! $this->tfa_manager ) {
            return;
        }

        $user_id = get_current_user_id();
        
        // Solo continuamos si la marca existe.
        if ( get_user_meta( $user_id, '_advaipbl_2fa_setup_required', true ) ) {
            
            $user = wp_get_current_user();
            $global_2fa_enabled = ! empty( $this->options['enable_2fa'] ) && '1' === $this->options['enable_2fa'];
            $user_is_forced = $this->tfa_manager->is_2fa_forced_for_user( $user );
            $user_has_2fa_setup = $this->tfa_manager->is_2fa_enabled_for_user( $user_id );

            // CONDICIONES PARA MOSTRAR EL AVISO:
            // 1. 2FA debe estar activado globalmente.
            // 2. El rol del usuario debe estar en la lista de forzados.
            // 3. El usuario NO debe tener 2FA configurado todavía.
            if ( $global_2fa_enabled && $user_is_forced && ! $user_has_2fa_setup ) {
                $profile_url = get_edit_profile_url( $user_id );
                ?>
                <div class="notice notice-error is-dismissible advaipbl-force-2fa-notice">
                    <p>
                        <strong><?php esc_html_e( 'Action Required:', 'advanced-ip-blocker' ); ?></strong>
                        <?php 
                        printf(
                            wp_kses(
                                /* translators: %s is a link to the user's profile page. */
                                __( 'Your administrator requires you to set up Two-Factor Authentication. Please <a href="%s">go to your profile</a> to configure it now.', 'advanced-ip-blocker' ),
                                [ 'a' => [ 'href' => [] ] ]
                            ),
                            esc_url( $profile_url )
                        );
                        ?>
                    </p>
                </div>
                <?php
            } else {
                // Si alguna de las condiciones no se cumple (ej. el admin desactivó el forzado para este rol),
                // el aviso ya no es necesario. Borramos la marca.
                delete_user_meta( $user_id, '_advaipbl_2fa_setup_required' );
            }
        }
    }
	
	    /**
     * Envía una notificación por email relacionada con un evento de 2FA.
     *
     * @param string  $event El tipo de evento ('activated', 'deactivated', 'reset', 'backup_used').
     * @param WP_User $user  El objeto del usuario afectado.
     * @param array   $data  Datos adicionales (ej. número de códigos de respaldo restantes).
     */
    public function send_2fa_notification_email( $event, $user, $data = [] ) {
        // Solo enviar si las notificaciones por email están activadas globalmente.
        if ( empty( $this->options['enable_email_notifications'] ) || '1' !== $this->options['enable_email_notifications'] ) {
            return;
        }

        $to = $user->user_email;
        $site_name = get_bloginfo( 'name' );
        $subject = '';
        $template_title = '';
        $content_html = '';

        switch ( $event ) {
            case 'activated':
			/* translators: $s: Site name. */
                $subject = sprintf( __( '[%s] Two-Factor Authentication Activated', 'advanced-ip-blocker' ), $site_name );
                $template_title = __( '2FA Activated', 'advanced-ip-blocker' );
                $content_html = '<p style="font-size: 16px; line-height: 1.6;">' . sprintf(/* translators: %s: Username. */ esc_html__( 'Hello %s,', 'advanced-ip-blocker' ), esc_html( $user->display_name ) ) . '</p>'
                              . '<p style="font-size: 16px; line-height: 1.6;">' . esc_html__( 'This is a confirmation that two-factor authentication has been successfully activated on your account. Your account is now more secure.', 'advanced-ip-blocker' ) . '</p>'
                              . '<p style="font-size: 14px; color: #555; margin-top: 20px;">' . esc_html__( 'If you did not perform this action, please contact the site administrator immediately.', 'advanced-ip-blocker' ) . '</p>';
                break;

            case 'deactivated':
			/* translators: $s: Site name. */
                $subject = sprintf( __( '[%s] SECURITY ALERT: Two-Factor Authentication Deactivated', 'advanced-ip-blocker' ), $site_name );
                $template_title = __( 'Security Alert: 2FA Deactivated', 'advanced-ip-blocker' );
                $content_html = '<p style="font-size: 16px; line-height: 1.6;">' . sprintf(/* translators: %s: Username. */ esc_html__( 'Hello %s,', 'advanced-ip-blocker' ), esc_html( $user->display_name ) ) . '</p>'
                              . '<p style="font-size: 16px; line-height: 1.6;">' . esc_html__( 'This is a notification that two-factor authentication has been deactivated on your account. Your account is now less secure.', 'advanced-ip-blocker' ) . '</p>'
                              . '<p style="font-size: 14px; color: #d63638; font-weight: bold; margin-top: 20px;">' . esc_html__( 'If you did not perform this action, please reset your password and contact the site administrator immediately.', 'advanced-ip-blocker' ) . '</p>';
                break;
            
            case 'reset':
			/* translators: $s: Site name. */
                $subject = sprintf( __( '[%s] Your Two-Factor Authentication has been Reset', 'advanced-ip-blocker' ), $site_name );
                $template_title = __( '2FA Reset by Administrator', 'advanced-ip-blocker' );
                $content_html = '<p style="font-size: 16px; line-height: 1.6;">' . sprintf(/* translators: %s: Username. */ esc_html__( 'Hello %s,', 'advanced-ip-blocker' ), esc_html( $user->display_name ) ) . '</p>'
                              . '<p style="font-size: 16px; line-height: 1.6;">' . esc_html__( 'A site administrator has reset the two-factor authentication configuration for your account. You can now log in using only your username and password.', 'advanced-ip-blocker' ) . '</p>'
                              . '<p style="font-size: 14px; color: #555; margin-top: 20px;">' . esc_html__( 'We strongly recommend you set up 2FA again from your profile page as soon as possible.', 'advanced-ip-blocker' ) . '</p>';
                break;

            case 'backup_used':
			/* translators: $s: Site name. */
                $subject = sprintf( __( '[%s] SECURITY NOTICE: A Recovery Code was Used', 'advanced-ip-blocker' ), $site_name );
                $template_title = __( 'Security Notice', 'advanced-ip-blocker' );
                $remaining_codes = $data['remaining_codes'] ?? 0;
                $content_html = '<p style="font-size: 16px; line-height: 1.6;">' . sprintf(/* translators: %s: Username. */ esc_html__( 'Hello %s,', 'advanced-ip-blocker' ), esc_html( $user->display_name ) ) . '</p>'
                              . '<p style="font-size: 16px; line-height: 1.6;">' . esc_html__( 'A recovery code was used to access your account.', 'advanced-ip-blocker' ) . '</p>'
                              . '<p style="font-size: 14px; color: #555; margin-top: 20px;">' . sprintf(/* translators: %d: Number of recovery codes. */ esc_html__( 'You have %d recovery codes remaining.', 'advanced-ip-blocker' ), $remaining_codes ) . '</p>'
                              . '<p style="font-size: 14px; color: #d63638; font-weight: bold; margin-top: 20px;">' . esc_html__( 'If you did not perform this action, please reset your password immediately.', 'advanced-ip-blocker' ) . '</p>';
                break;
        }

        if ( ! empty( $content_html ) ) {
            $body = $this->get_html_email_template( $template_title, $content_html );
            add_filter( 'wp_mail_content_type', [$this, 'set_html_mail_content_type'] );
            wp_mail( $to, $subject, $body );
            remove_filter( 'wp_mail_content_type', [$this, 'set_html_mail_content_type'] );
        }
    }
	
	    /**
     * Previene la enumeración de usuarios a través del endpoint oEmbed de la API REST.
     * Elimina los datos del autor de la respuesta si la protección está activada.
     *
     * @param array   $data   The response data.
     * @param WP_Post $post   The post object.
     * @param int     $width  The requested width.
     * @param int     $height The requested height.
     * @return array The modified response data.
     */
    public function prevent_user_enumeration_via_oembed( $data, $post, $width, $height ) {
        // Solo actuar si la opción de protección está activada.
        if ( ! empty( $this->options['disable_user_enumeration'] ) ) {
            // Eliminamos las claves que podrían revelar información del autor.
            unset( $data['author_name'] );
            unset( $data['author_url'] );
        }
        return $data;
    }
	
	    /**
     * Previene la enumeración de usuarios a través de los feeds RSS.
     * Si la protección de escaneo de autor está activada, reemplaza el login del autor
     * con su nombre público (display name) en los feeds.
     *
     * @param string $author_login El login del autor.
     * @return string El login del autor o su nombre público.
     */
    public function prevent_user_enumeration_via_feeds( $author_login ) {
        // Solo actuar si la opción está activada y estamos en un feed.
        if ( ! empty( $this->options['prevent_author_scanning'] ) && is_feed() ) {
            $author = get_user_by( 'login', $author_login );
            if ( $author ) {
                // Devolvemos el nombre público en lugar del login.
                return $author->display_name;
            }
        }
        return $author_login;
    }
	
	    /**
     * Previene el "login hinting" interceptando los errores de autenticación
     * y reemplazándolos por un mensaje genérico.
     *
     * @param WP_User|WP_Error|null $user El objeto de usuario o error.
     * @return WP_User|WP_Error
     */
    public function prevent_login_hinting( $user ) {
        // Solo actuar si la opción está activada.
        if ( empty( $this->options['prevent_login_hinting'] ) || '1' !== $this->options['prevent_login_hinting'] ) {
            return $user;
        }

        // Solo nos interesa modificar los errores, no los inicios de sesión correctos.
        if ( ! is_wp_error( $user ) ) {
            return $user;
        }

        // Lista de códigos de error que queremos ocultar.
        $error_codes_to_hide = [
            'invalid_username',
            'invalid_email',
            'incorrect_password',
        ];

        // Comprobamos si el error actual es uno de los que dan pistas.
        $has_hinting_error = false;
        foreach ( $error_codes_to_hide as $code ) {
            if ( $user->get_error_code() === $code ) {
                $has_hinting_error = true;
                break;
            }
        }

        if ( $has_hinting_error ) {

            return new WP_Error(
                'advaipbl_generic_login_error',
                __( '<strong>ERROR</strong>: Your login details are incorrect. Please try again.', 'advanced-ip-blocker' )
            );
        }

        // Si no es un error de los que queremos ocultar (ej. el de 2FA), lo dejamos pasar.
        return $user;
    }
		
	    /**
     * Guarda los cambios de la sección 2FA en el perfil de usuario.
     * Este hook es necesario para WordPress. Nuestra lógica de activación/desactivación
     * se maneja principalmente vía AJAX para una mejor experiencia de usuario.
     *
     * @param int $user_id El ID del usuario que se está actualizando.
     */
    public function save_2fa_section_in_profile( $user_id ) {
        // No se requiere ninguna acción aquí, ya que el JS maneja las acciones de 2FA.
        // La función debe existir para que el hook 'personal_options_update' no cause un error fatal.
        if ( ! current_user_can( 'edit_user', $user_id ) ) {
            return;
        }
        // No hay nada que hacer, pero la función está aquí para evitar el error.
    }

	 /**
  * Tarea programada para actualizar las bases de datos de GeoIP.
  */
 public function execute_geoip_db_update() {
     // Solo se ejecuta si el método es 'local_db' y hay una clave de licencia.
     if (
         isset($this->options['geolocation_method']) && $this->options['geolocation_method'] === 'local_db' &&
         !empty($this->options['maxmind_license_key']) && $this->geoip_manager
     ) {
         // Increase limits for large file download/extraction
         // phpcs:ignore Squiz.PHP.DiscouragedFunctions.Discouraged
         if (function_exists('set_time_limit')) { @set_time_limit(300); }
         // phpcs:ignore Squiz.PHP.DiscouragedFunctions.Discouraged
         @ini_set('memory_limit', '256M');
         
         $this->log_event('Starting scheduled GeoIP database update.', 'info');
         $result = $this->geoip_manager->download_and_unpack_databases();
         if (!$result['success']) {
             $this->log_event('Scheduled GeoIP database update failed: ' . $result['message'], 'error');
         } else {
             $this->log_event('Scheduled GeoIP database update completed successfully.', 'info');
         }
     }
 }
 
     /**
     * Comprueba si una IP está actualmente bajo un bloqueo activo de cualquier tipo.
     * Esta función es una comprobación de alto rendimiento que prioriza los transients.
     *
     * @param string $ip La dirección IP a comprobar.
     * @return bool True si la IP está activamente bloqueada, false en caso contrario.
     */
        public function is_ip_actively_blocked($ip) {
        $definitions = $this->get_all_block_type_definitions();

        // 1. Comprobación de transients para todos los tipos que los usan.
        foreach ($definitions as $type => $def) {
            if ($def['uses_transient'] && get_transient('advaipbl_bloqueo_' . $type . '_' . md5($ip))) {
                return true;
            }
        }

        // 2. Comprobación específica para bloqueos manuales (que son permanentes).
        $manual_blocks = get_option(self::OPTION_BLOCKED_MANUAL, []);
        if (!empty($manual_blocks)) {
            foreach (array_keys($manual_blocks) as $entry) {
                if ($this->is_ip_in_range($ip, $entry)) {
                    return true;
                }
            }
        }

        return false;
    }
	
	    /**
     * Comprueba si la IP del visitante actual está activamente bloqueada.
     * Utiliza un caché estático por petición para un rendimiento máximo,
     * ya que esta función puede ser llamada varias veces durante una misma ejecución.
     *
     * @return bool True si la IP está bloqueada, false en caso contrario.
     */
    private function is_visitor_actively_blocked() {

        static $is_blocked = null;
        if ( null !== $is_blocked ) {
            return $is_blocked;
        }

        $ip = $this->get_client_ip();

        if ( get_transient( 'advaipbl_blocked_ip_' . md5( $ip ) ) ) {
            $is_blocked = true;
            return true;
        }

        global $wpdb;
        $table_name = $wpdb->prefix . 'advaipbl_blocked_ips';
        
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $is_blocked_in_db = $wpdb->get_var( $wpdb->prepare(
            "SELECT id FROM {$table_name} WHERE ip_range = %s AND (expires_at = 0 OR expires_at > %d)",
            $ip,
            time()
        ) );
        
        if ( $is_blocked_in_db ) {
            $is_blocked = true;
            return true;
        }
        
        $is_blocked = false;
        return false;
    }
	
	    /**
     * Revisa y actualiza el estado de 'autoload' para las opciones del plugin que pueden
     * crecer mucho en tamaño, mejorando el rendimiento general del sitio.
     * Se ejecuta automáticamente una vez gracias a un sistema de versionado.
     */
    public function update_option_autoload_states() {
        if ( get_option('advaipbl_autoload_version') === self::AUTOLOAD_OPTIMIZATION_VERSION ) {
            return;
        }

        global $wpdb;

        $options_to_optimize = [
            self::OPTION_WHITELIST,
            self::OPTION_BLOCKED_MANUAL,
            self::OPTION_BLOCKED_404,
            self::OPTION_BLOCKED_403,
            self::OPTION_BLOCKED_LOGIN,
            self::OPTION_BLOCKED_GEO,
            self::OPTION_BLOCKED_HONEYPOT,
            self::OPTION_BLOCKED_USER_AGENT,
            self::OPTION_BLOCKED_WAF,
            self::OPTION_BLOCKED_THREAT_SCORE,
            self::OPTION_BLOCKED_RATE_LIMIT,
            self::OPTION_BLOCKED_ASN,
            self::OPTION_BLOCKED_XMLRPC,
            self::OPTION_HONEYPOT_URLS,
            self::OPTION_BLOCKED_UAS,
            self::OPTION_WHITELISTED_UAS,
            self::OPTION_WAF_RULES,
            self::OPTION_BLOCKED_ASNS,
            self::OPTION_WHITELISTED_ASNS,
            'advaipbl_spamhaus_asn_list',
            self::OPTION_ADMIN_IP_TRIGGER,
            'advaipbl_spamhaus_last_update',
        ];

        foreach ($options_to_optimize as $option_name) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->query( $wpdb->prepare( 
                "UPDATE {$wpdb->options} SET `autoload` = 'no' WHERE `option_name` = %s", 
                $option_name 
            ) );
        }
        
        update_option('advaipbl_autoload_version', self::AUTOLOAD_OPTIMIZATION_VERSION);
        $this->log_event('Successfully optimized database option autoloading for performance.', 'info');
    }
	
	    /**
     * Obtiene y sanea la URI de la petición actual.
     * Cachea el resultado para evitar trabajo repetido en una misma petición.
     *
     * @return string La URI de la petición saneada.
     */
    public function get_current_request_uri() {
        static $request_uri = null;

        if ( is_null($request_uri) ) {
            $request_uri = esc_url_raw(wp_unslash($_SERVER['REQUEST_URI'] ?? ''));
        }

        return $request_uri;
    }
	
	/**
 * Checks if the current request URI is in the global exclusion list.
 *
 * @return bool True if the URI should be excluded, false otherwise.
 */
	public function is_request_uri_excluded() {
    $excluded_urls = $this->options['excluded_error_urls'] ?? '';
    if (empty($excluded_urls)) {
        return false;
    }

    $excluded_list = array_filter(array_map('trim', explode("\n", $excluded_urls)));
    $current_url = $this->get_current_request_uri();

    foreach ($excluded_list as $excluded_item) {

        if (!empty($excluded_item) && stripos($current_url, $excluded_item) !== false) {
            return true;
        }
    }

    return false;
}

    /**
     * Obtiene y sanea el User Agent de la petición actual.
     * @return string El User Agent de la petición, saneado.
     */
    public function get_user_agent() {
        static $user_agent = null;
        if (is_null($user_agent)) {
            $user_agent = sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'] ?? ''));
        }
        return $user_agent;
    }

    /**
     * Obtiene y sanea el método de la petición actual.
     * @return string
     */
    public function get_request_method() {
        static $request_method = null;
        if (is_null($request_method)) {
            // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
            $request_method_raw = isset($_SERVER['REQUEST_METHOD']) ? wp_unslash($_SERVER['REQUEST_METHOD']) : 'GET';
            $request_method = sanitize_text_field($request_method_raw);
        }
        return $request_method;
    }

    /**
     * Obtiene y sanea el Referer de la petición actual.
     * @return string
     */
    public function get_http_referer() {
        static $http_referer = null;
        if (is_null($http_referer)) {
            $http_referer = sanitize_text_field(wp_unslash($_SERVER['HTTP_REFERER'] ?? ''));
        }
        return $http_referer;
    }

    /**
     * Obtiene y sanea la IP de la conexión directa (REMOTE_ADDR).
     * @return string
     */
    public function get_remote_addr() {
        static $remote_addr = null;
        if (is_null($remote_addr)) {
            $remote_addr_raw = isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '';
            $remote_addr = filter_var($remote_addr_raw, FILTER_VALIDATE_IP) ?: '';
        }
        return $remote_addr;
    }
	
	    /**
     * Incrementa el contador de un endpoint para el sistema de Lockdown.
     * Si el contador supera el umbral, activa el modo Lockdown.
     *
     * @param string $endpoint_key La clave del endpoint (ej. 'xmlrpc').
     */
        private function increment_lockdown_counter($endpoint_key) {
        $threshold = (int) ($this->options[$endpoint_key . '_lockdown_threshold'] ?? 10);
        $window_minutes = (int) ($this->options[$endpoint_key . '_lockdown_window'] ?? 15);
        $duration_minutes = (int) ($this->options[$endpoint_key . '_lockdown_duration'] ?? 60);

        if ($threshold <= 0 || $window_minutes <= 0) {
            return;
        }

        $cache_key = 'advaipbl_lockdown_trigger_' . $endpoint_key;
        
        // Obtenemos los datos actuales de la caché, que ahora serán un array.
        $trigger_data = $this->get_from_custom_cache($cache_key);
        if (!is_array($trigger_data)) {
            $trigger_data = ['count' => 0, 'ips' => []];
        }

        $trigger_data['count']++;
        $ip = $this->get_client_ip();
        // Guardamos las últimas ~15 IPs para tener contexto.
        $trigger_data['ips'][] = $ip;
        if (count($trigger_data['ips']) > 15) {
            $trigger_data['ips'] = array_slice($trigger_data['ips'], -15);
        }
        $trigger_data['ips'] = array_unique($trigger_data['ips']);

        // Volvemos a guardar en la caché.
        $ttl = $this->get_from_custom_cache($cache_key, true)['expires_at'] ?? (time() + $window_minutes * MINUTE_IN_SECONDS);
        $this->set_in_custom_cache($cache_key, $trigger_data, $ttl - time());

        if ($trigger_data['count'] >= $threshold) {
            global $wpdb;
            $lockdowns_table = $wpdb->prefix . 'advaipbl_endpoint_lockdowns';

            $now = time();
            $reason = sprintf(
			    /* translators: 1: The number of blocks. 2: The number of minutes in the detection window. */
                __('Exceeded threshold: %1$d blocks in %2$d minutes.', 'advanced-ip-blocker'),
                $trigger_data['count'],
                $window_minutes
            );
            $details = wp_json_encode(['triggering_ip_hashes' => $trigger_data['ips']]);

            // Insertamos el lockdown en nuestra nueva tabla.
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $wpdb->insert(
                $lockdowns_table,
                [
                    'endpoint_key' => $endpoint_key,
                    'reason'       => $reason,
                    'created_at'   => $now,
                    'expires_at'   => $now + ($duration_minutes * MINUTE_IN_SECONDS),
                    'details'      => $details,
                ]
            );

            // Limpiamos el contador de la caché, ya que el lockdown está activo.
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->delete($wpdb->prefix . 'advaipbl_cache', ['cache_key' => $cache_key]);

            $this->log_event(sprintf('Endpoint Lockdown activated for "%s" for %d minutes due to %d suspicious blocks.', $endpoint_key, $duration_minutes, $trigger_data['count']), 'critical');
            $this->send_lockdown_notification($endpoint_key, $duration_minutes, $threshold);
        }
    }
	
	    /**
     * Incrementa el contador de fallos de login para el sistema de Lockdown de wp-login.php.
     * Activa el lockdown si se superan los umbrales de eventos y de IPs únicas.
     */
    private function increment_login_lockdown_counter() {
        // Obtenemos los umbrales desde los ajustes (los añadiremos más tarde).
        // Por ahora, usamos valores por defecto razonables.
        $event_threshold = (int) ($this->options['login_lockdown_event_threshold'] ?? 50);
        $ip_threshold = (int) ($this->options['login_lockdown_ip_threshold'] ?? 10);
        $window_minutes = (int) ($this->options['login_lockdown_window'] ?? 5);
        $duration_minutes = (int) ($this->options['login_lockdown_duration'] ?? 60);

        if ($event_threshold <= 0 || $ip_threshold <= 0 || $window_minutes <= 0) {
            return;
        }

        $endpoint_key = 'login';
        $cache_key = 'advaipbl_lockdown_trigger_' . $endpoint_key;
        
        // Obtenemos los datos actuales de la caché.
        $trigger_data = $this->get_from_custom_cache($cache_key);
        if (!is_array($trigger_data) || !isset($trigger_data['event_count'])) {
            $trigger_data = ['event_count' => 0, 'ip_hashes' => []];
        }

        $trigger_data['event_count']++;
        $ip_hash = hash('sha256', $this->get_client_ip());
        if (!in_array($ip_hash, $trigger_data['ip_hashes'])) {
            $trigger_data['ip_hashes'][] = $ip_hash;
        }

        // Guardamos los datos actualizados en la caché.
        $ttl_info = $this->get_from_custom_cache($cache_key, true);
        $ttl = $ttl_info ? $ttl_info['expires_at'] - time() : $window_minutes * MINUTE_IN_SECONDS;
        if ($ttl > 0) {
            $this->set_in_custom_cache($cache_key, $trigger_data, $ttl);
        }

        // Comprobamos si se han superado ambos umbrales.
        if ($trigger_data['event_count'] >= $event_threshold && count($trigger_data['ip_hashes']) >= $ip_threshold) {
            global $wpdb;
            $lockdowns_table = $wpdb->prefix . 'advaipbl_endpoint_lockdowns';

            // Verificamos que no haya ya un lockdown activo para este endpoint para evitar duplicados.
            // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $is_already_active = $wpdb->get_var($wpdb->prepare(
                "SELECT id FROM {$lockdowns_table} WHERE endpoint_key = %s AND expires_at > %d",
                $endpoint_key, time()
            ));

            if (!$is_already_active) {
                $now = time();
                $reason = sprintf(
				    /* translators: 1: The number of failed logins. 2: The number of unique IPs. 3: The number of minutes in the detection window. */
                    __('Exceeded threshold: %1$d failed logins from %2$d unique IPs in %3$d minutes.', 'advanced-ip-blocker'),
                    $trigger_data['event_count'],
                    count($trigger_data['ip_hashes']),
                    $window_minutes
                );
                $details = wp_json_encode(['triggering_ip_hashes' => $trigger_data['ip_hashes']]);

                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
                $wpdb->insert(
                    $lockdowns_table,
                    [
                        'endpoint_key' => $endpoint_key,
                        'reason'       => $reason,
                        'created_at'   => $now,
                        'expires_at'   => $now + ($duration_minutes * MINUTE_IN_SECONDS),
                        'details'      => $details,
                    ]
                );

                $this->log_event(sprintf('Endpoint Lockdown activated for "%s" for %d minutes.', $endpoint_key, $duration_minutes), 'critical');
                $this->send_lockdown_notification($endpoint_key, $duration_minutes, $event_threshold);
            }
            
            // Limpiamos el contador de la caché, ya que el lockdown está activo.
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->delete($wpdb->prefix . 'advaipbl_cache', ['cache_key' => $cache_key]);
        }
    }
	
	        /**
     * Comprueba si un endpoint crítico está bajo "Lockdown" y sirve un desafío si es necesario.
     * Se ejecuta en un hook temprano para interceptar el tráfico antes que otras comprobaciones.
     */
    public function check_for_endpoint_lockdown() {
		
		if ($this->is_request_uri_excluded()) { return; }
        if (empty($this->options['enable_xmlrpc_lockdown']) && empty($this->options['enable_login_lockdown'])) {
            return;
        }
		// Si el usuario acaba de pasar un desafío, le damos un pase de gracia de 15s.
        if (get_transient('advaipbl_grace_pass_' . md5($this->get_client_ip()))) {
           return;
        }
        if ($this->request_is_asn_whitelisted) { return; }
        
        // Procesa la respuesta del desafío si es para este tipo.
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        if (isset($_POST['_advaipbl_challenge_type']) && $_POST['_advaipbl_challenge_type'] === 'endpoint') {
            // Un pase de 1 hora es suficiente para un endpoint crítico.
            $this->js_challenge_manager->verify_challenge('advaipbl_js_verified', 1 * HOUR_IN_SECONDS);
        }

        // Si ya está verificado, no hacer nada.
        if (isset($_COOKIE['advaipbl_js_verified']) && $_COOKIE['advaipbl_js_verified'] === '1') {
            return;
        }        
        
        $request_uri = $this->get_current_request_uri();
        $endpoint_key = '';
        $is_xmlrpc_request = strpos($request_uri, 'xmlrpc.php') !== false;
        $is_login_request = strpos($request_uri, 'wp-login.php') !== false;

        if ($is_xmlrpc_request && !empty($this->options['enable_xmlrpc_lockdown'])) {
            $endpoint_key = 'xmlrpc';
        } elseif ($is_login_request && !empty($this->options['enable_login_lockdown'])) {
            $endpoint_key = 'login';
        }

        if (empty($endpoint_key)) {
            return;
        }

        global $wpdb;
        $lockdowns_table = $wpdb->prefix . 'advaipbl_endpoint_lockdowns';
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $is_lockdown_active = $wpdb->get_var($wpdb->prepare(
            "SELECT id FROM {$lockdowns_table} WHERE endpoint_key = %s AND expires_at > %d",
            $endpoint_key,
            time()
        ));

        if ($is_lockdown_active) {
            $ip = $this->get_client_ip();
            if ($this->is_whitelisted($ip)) {
                return;
            }

            $user_agent = $this->get_user_agent();
            $is_trusted_service = false;
            if ('xmlrpc' === $endpoint_key) {
                $automattic_ua_patterns = [ '/^WordPress\/\d+\.\d+/i', '/jetpack by wordpress\.com/i', '/woocommerce/i' ];
                foreach ($automattic_ua_patterns as $pattern) {
                    if (preg_match($pattern, $user_agent)) {
                        $is_trusted_service = true;
                        break;
                    }
                }
            }
            
            if (!$is_trusted_service) {
                $this->log_specific_error('endpoint_challenge', $ip, ['endpoint' => $endpoint_key, 'reason' => ucfirst($endpoint_key) . ' Lockdown Mode Active', 'uri' => $request_uri], 'warning');
                // AIB Community Network Reporting
       if ( ! empty( $this->options['enable_community_network'] ) ) {
           $report_type = ($endpoint_key === 'xmlrpc') ? 'xmlrpc_block' : 'login_lockdown';
           $this->reporter_manager->queue_report( $ip, $report_type, ['uri' => $request_uri] );
       }

       $mode = $this->options[$endpoint_key . '_lockdown_challenge_mode'] ?? 'managed';
       $this->js_challenge_manager->serve_challenge('endpoint', $mode);
            }
        }
    }
	
	    /**
     * Envía notificaciones (Email/Push) cuando el modo Lockdown se activa para un endpoint.
     *
     * @param string $endpoint_key   La clave del endpoint (ej. 'xmlrpc').
     * @param int    $duration_minutes La duración del lockdown.
     * @param int    $threshold      El umbral de bloqueos que lo activó.
     */
    public function send_lockdown_notification($endpoint_key, $duration_minutes, $threshold) {
        if ( isset($this->notification_manager) ) {
            $this->notification_manager->send_lockdown_notification($endpoint_key, $duration_minutes, $threshold);
        }
    }
	
	/**
 * Comprueba la bandera de activación y redirige al asistente si es necesario.
 * Se ejecuta en admin_init.
 */
public function maybe_redirect_to_wizard() {
    if ( get_option( 'advaipbl_run_setup_wizard' ) ) {
        
        // Evitar bucles infinitos en servidores con Object Caches muy lentos (ej. LiteSpeed)
        // comprobando si YA estamos en la ruta de destino.
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $is_already_on_wizard = ( isset( $_GET['page'] ) && $_GET['page'] === 'advaipbl-setup-wizard' );
        
        delete_option( 'advaipbl_run_setup_wizard' ); 
        
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        if ( $is_already_on_wizard || ( defined( 'DOING_AJAX' ) && DOING_AJAX ) || isset( $_GET['activate-multi'] ) ) {
            // Si es activación masiva, volvemos a poner para mostrar mensaje.
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            if ( isset( $_GET['activate-multi'] ) ) {
                add_option( 'advaipbl_run_setup_wizard', true );
            }
            return;
        }

        wp_safe_redirect( admin_url( 'admin.php?page=advaipbl-setup-wizard' ) );
        exit;
    }
}

/**
 * Muestra un aviso en el panel de administración si el asistente de configuración no se ha completado.
 */
public function display_setup_wizard_notice() {
    // Solo mostrar el aviso si la bandera existe, el usuario puede gestionar opciones, y no estamos ya en el asistente.
    // phpcs:ignore WordPress.Security.NonceVerification.Recommended
    if ( get_option( 'advaipbl_run_setup_wizard' ) && current_user_can( 'manage_options' ) && ( ! isset( $_GET['page'] ) || $_GET['page'] !== 'advaipbl-setup-wizard' ) ) {
        $wizard_url = admin_url( 'admin.php?page=advaipbl-setup-wizard' );
        ?>
        <div class="notice notice-info is-dismissible advaipbl-wizard-notice">
            <p>
                <strong><?php esc_html_e( 'Welcome to Advanced IP Blocker!', 'advanced-ip-blocker' ); ?></strong><br>
                <?php 
                printf(
                    wp_kses(
                        /* translators: %s is the link to the setup wizard. */
                        __( 'To get started, please run the <a href="%s">setup wizard</a> to apply the recommended security settings.', 'advanced-ip-blocker' ),
                        [ 'a' => [ 'href' => [] ] ]
                    ),
                    esc_url( $wizard_url )
                );
                ?>
            </p>
        </div>
        <?php
    }
}

/**
 * Comprueba la reputación de la IP del visitante con AbuseIPDB.
 * Se ejecuta temprano en el hook 'init' para bloquear proactivamente a los malos actores conocidos.
 */
public function check_ip_with_abuseipdb() {
			
    if ($this->is_request_uri_excluded()) {
        return;
    }

    if (empty($this->options['enable_abuseipdb']) || empty($this->options['abuseipdb_api_key'])) {
        return;
    }
    
    // Explicitly allowed by Advanced Rules? Skip.
    if ($this->is_advanced_rule_allowed) {
        return;
    }

    $ip = $this->get_client_ip();

    if ($this->request_is_asn_whitelisted || (isset($_COOKIE['advaipbl_js_verified']) && $_COOKIE['advaipbl_js_verified'] === '1') || get_transient('advaipbl_grace_pass_' . md5($ip))) {
        return;
    }
    if ($this->is_whitelisted($ip)) {
        return;
    }

    $result = $this->abuseipdb_manager->check_ip($ip);
    if ($result === false) {
        return;
    }

    $threshold = (int) ($this->options['abuseipdb_threshold'] ?? 90);
    if ($result['score'] >= $threshold) {

        $action_to_take = $this->options['abuseipdb_action'] ?? 'block'; // 'block' es el valor por defecto

        $log_data = [
            'abuse_score' => $result['score'],
            'uri'         => $this->get_current_request_uri()
        ];

        if (strpos($action_to_take, 'challenge') !== false) {
            // Si la acción es 'challenge' o 'challenge_automatic', registramos el evento y mostramos el desafío.
            $this->log_specific_error('abuseipdb_challenge', $ip, $log_data, 'warning');
            
            $mode = ($action_to_take === 'challenge_automatic') ? 'automatic' : 'managed';
            $this->js_challenge_manager->serve_challenge('abuseipdb', $mode); // El tipo y modo son importantes
        } else {
            // Si no, procedemos con el bloqueo como antes.
            $reason = sprintf(
			       /* translators: %d: The abuse confidence score from AbuseIPDB. */
                __('Blocked by AbuseIPDB with a confidence score of %d%%.', 'advanced-ip-blocker'),
                $result['score']
            );
			
			if ( isset($this->reporter_manager) ) {
                    $this->reporter_manager->queue_report( $ip, 'abuseipdb', $log_data );
                }
			
            $this->block_ip_instantly($ip, 'abuseipdb', $reason, $log_data);
        }
    }
}

/**
 * Envía una notificación por email al administrador cuando se alcanza el límite de la API de AbuseIPDB.
 * Se asegura de enviar solo una notificación por día.
 */
    public function send_abuseipdb_limit_email() {
        if ( isset($this->notification_manager) ) {
            $this->notification_manager->send_abuseipdb_limit_email();
        }
    }
 
    /**
     * Generic monitor for distributed attacks (Lockdown Mode).
     * Used for 404, 403, and potentially others.
     */
    private function monitor_distributed_attack($type) {
        $prefix = 'lockdown_' . $type; // e.g., lockdown_404
        
        // Settings
        $event_threshold = (int) ($this->options[$prefix . '_event_threshold'] ?? 50);
        $ip_threshold    = (int) ($this->options[$prefix . '_ip_threshold'] ?? 5);
        $window_minutes  = (int) ($this->options[$prefix . '_window'] ?? 10);
        $duration_minutes= (int) ($this->options[$prefix . '_duration'] ?? 60);

        if ($event_threshold <= 0 || $ip_threshold <= 0 || $window_minutes <= 0) {
            return;
        }

        $endpoint_key = $type; // '404' or '403'
        $cache_key = 'advaipbl_lockdown_trigger_' . $endpoint_key;
        
        // Get current trigger data
        $trigger_data = $this->get_from_custom_cache($cache_key);
        if (!is_array($trigger_data) || !isset($trigger_data['event_count'])) {
            $trigger_data = ['event_count' => 0, 'ip_hashes' => [], 'samples' => []];
        }

        $trigger_data['event_count']++;
        $ip_hash = hash('sha256', $this->get_client_ip());
        if (!in_array($ip_hash, $trigger_data['ip_hashes'])) {
            $trigger_data['ip_hashes'][] = $ip_hash;
        }
        
        // Capture Sample Data (Request URI + User Agent) - Keep last 20
        $sample_entry = [
            'time' => current_time('mysql'),
            'uri'  => substr($this->get_current_request_uri(), 0, 150),
            'ua'   => substr($this->get_user_agent(), 0, 150),
            'ip_partial' => substr($ip_hash, 0, 8) . '...'
        ];
        if (!isset($trigger_data['samples'])) { $trigger_data['samples'] = []; }
        $trigger_data['samples'][] = $sample_entry;
        if (count($trigger_data['samples']) > 20) {
            array_shift($trigger_data['samples']); // Keep only recent
        }

        // Update cache with TTL
        $ttl_info = $this->get_from_custom_cache($cache_key, true);
        $ttl = $ttl_info ? $ttl_info['expires_at'] - time() : $window_minutes * MINUTE_IN_SECONDS;
        if ($ttl > 0) {
            $this->set_in_custom_cache($cache_key, $trigger_data, $ttl);
        }

        // Check Thresholds
        if ($trigger_data['event_count'] >= $event_threshold && count($trigger_data['ip_hashes']) >= $ip_threshold) {
             global $wpdb;
             $lockdowns_table = $wpdb->prefix . 'advaipbl_endpoint_lockdowns';
             
             // Check if already active
             // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
             $is_active = $wpdb->get_var($wpdb->prepare(
                 "SELECT id FROM {$lockdowns_table} WHERE endpoint_key = %s AND expires_at > %d",
                 $endpoint_key, time()
             ));

             if (!$is_active) {
                 $now = time();
                 $reason = sprintf(
                     /* translators: 1: Event count, 2: Unique IPs, 3: Minutes, 4: Error type */
                     __('Exceeded threshold: %1$d %4$s errors from %2$d unique IPs in %3$d minutes.', 'advanced-ip-blocker'),
                     $trigger_data['event_count'],
                     count($trigger_data['ip_hashes']),
                     $window_minutes,
                     $type
                 );
                 
                 // Include samples in details
                 $details_array = [
                     'triggering_ip_hashes' => $trigger_data['ip_hashes'], 
                     'samples' => $trigger_data['samples']
                 ];
                 $details = wp_json_encode($details_array);

                 // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
                 $wpdb->insert(
                     $lockdowns_table,
                     [
                         'endpoint_key' => $endpoint_key,
                         'reason'       => $reason,
                         'created_at'   => $now,
                         'expires_at'   => $now + ($duration_minutes * MINUTE_IN_SECONDS),
                         'details'      => $details,
                     ]
                 );
                 
                 $this->log_event(sprintf('Distributed Lockdown activated for %s errors (%d mins).', $type, $duration_minutes), 'critical');
                 $this->send_lockdown_notification($type, $duration_minutes, $event_threshold);
             }
             
             // Clear cache as lockdown is now active
             // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
             $wpdb->delete($wpdb->prefix . 'advaipbl_cache', ['cache_key' => $cache_key]);
        }
    }

    /**
     * Check if a specific lockdown is active in the DB.
     */
    private function is_lockdown_active_for_type($type) {
         global $wpdb;
         $lockdowns_table = $wpdb->prefix . 'advaipbl_endpoint_lockdowns';
         // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
         return $wpdb->get_var($wpdb->prepare(
             "SELECT id FROM {$lockdowns_table} WHERE endpoint_key = %s AND expires_at > %d",
             $type, time()
         ));
    }


    /**
     * Ejecuta el envío de reportes a la API central.
     */
    public function execute_community_report() {
        // 1. Obtener el lote de bloqueos (solo si participa en AIB Network)
        $payload = [
            'site_hash' => hash('sha256', home_url()),
            'version'   => ADVAIPBL_VERSION,
            'reports'   => []
        ];
        
        global $wpdb;
        if ( empty($this->options['enable_community_network']) ) {
            // Si no participa en red, no enviamos reportes de amenazas (pero la telemetria puede enviarse abajo)
            // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
            $wpdb->query("TRUNCATE TABLE {$wpdb->prefix}advaipbl_pending_reports");
        } else {
            $gathered_payload = $this->reporter_manager->get_batch_for_api(100);
            if (!empty($gathered_payload)) {
                $payload = $gathered_payload;
            }
        }

        $has_reports = !empty($payload['reports']);
        
        $has_v3_token = !empty($this->options['api_token_v3']);

        // 3. Fallback a V2 si no hay token V3 (V2 no agrupa telemetría, aborta si no hay reportes)
        if (!$has_v3_token && !$has_reports) {
            return; 
        }

        // Asegurar site_hash para Rate Limiting V2 o info cruda
        $payload_data = $payload;
        $payload_data['site_hash'] = $payload['site_hash'] ?? hash('sha256', get_site_url());

        // 4. Parámetros de envío
        if ($has_v3_token) {
            $api_url = 'https://advaipbl.com/wp-json/aib-api/v3/report';
            $headers = [
                'Content-Type'  => 'application/json',
                'Authorization' => 'Bearer ' . $this->options['api_token_v3']
            ];
            
            // En V3 inyectamos la telemetría general en el mismo paquete para ahorrar recursos del cliente y servidor
            if (!empty($this->options['allow_telemetry']) && '1' === $this->options['allow_telemetry']) {
                $payload_data['telemetry'] = $this->get_telemetry_payload();
            } else {
                $payload_data['telemetry'] = [];
            }
            
            // Si después de intentarlo no hay ni amenazas locales ni métricas permitidas, no saturamos la red
            if (!$has_reports && empty($payload_data['telemetry'])) {
                return;
            }
            
        } else {
            // Configuración V2 (Asegurar que nunca llegamos aquí si !$has_reports por la comprobación anterior)
            $api_url = 'https://advaipbl.com/wp-json/aib-network/v2/report';
            $headers = [
                'Content-Type'    => 'application/json',
                'X-AIB-Site-Hash' => $payload_data['site_hash'],
            ];
        }

        $response = wp_remote_post( $api_url, [
            'body'     => wp_json_encode($payload_data),
            'headers'  => $headers,
            'timeout'  => 5,
            'blocking' => false
        ]);
    }



    /**
     * Plugin Deactivation Hook.
     * Clears all scheduled cron jobs to prevent them from running when the plugin is inactive.
     */
    public static function deactivate_plugin() {
        $cron_hooks = [
            'advaipbl_purge_old_logs_event', 
            'advaipbl_send_summary_email',
            'advaipbl_update_spamhaus_list_event', 
            'advaipbl_send_telemetry_data_event',
            'advaipbl_threat_score_decay_event', 
            'advaipbl_signature_analysis_event',
            'advaipbl_update_geoip_db_event', 
            'advaipbl_update_geoip_db_event', 
            'advaipbl_cleanup_expired_cache_event',
            'advaipbl_scheduled_scan_event',
            'advaipbl_daily_fim_scan',
            'advaipbl_cloudflare_cleanup_event'
        ];
        
        foreach ($cron_hooks as $hook) {
            wp_clear_scheduled_hook($hook);
        }
    }
}