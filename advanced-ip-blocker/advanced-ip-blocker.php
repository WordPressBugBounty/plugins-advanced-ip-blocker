<?php
/*
Plugin Name: Advanced IP Blocker
Plugin URI: https://advaipbl.com/
Description: Your complete WordPress security firewall. Blocks IPs, bots & countries. Includes an intelligent WAF, Threat Scoring, and Two-Factor Authentication.
Version: 8.9.12
Author: IniLerm
Author URI: https://advaipbl.com/
Text Domain: advanced-ip-blocker
Domain Path: /languages
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html
Requires at least: 6.7
Requires PHP: 8.1
*/

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

define( 'ADVAIPBL_VERSION', '8.9.12' );
define( 'ADVAIPBL_PLUGIN_FILE', __FILE__ );

if (!defined('ADVAIPBL_PLUGIN_PATH')) {
    define('ADVAIPBL_PLUGIN_PATH', trailingslashit(plugin_dir_path(__FILE__)));
}
define( 'ADVAIPBL_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'ADVAIPBL_PLUGIN_NAME', 'advaipbl' );
define( 'ADVAIPBL_DB_VERSION', '2.4' );

define( 'ADVAIPBL_USM_LOCATION_CACHE_KEY', 'advaipbl_usm_user_session_locations' );
define( 'ADVAIPBL_USM_LOCATION_CACHE_TTL', 24 * 3600 );
define( 'ADVAIPBL_USM_OPTION_PER_PAGE', 'advaipbl_usm_sessions_per_page' );
define( 'ADVAIPBL_USM_DEFAULT_PER_PAGE', 10 );

spl_autoload_register(function ($class) {
    $modern_php_prefixes = [
        'RobThree\\Auth\\',
        'BaconQrCode\\',
        'DASPRiD\\Enum\\',
        'GeoIp2\\',
        'MaxMind\\Db\\',
    ];

    $is_modern_lib = false;
    foreach ($modern_php_prefixes as $prefix) {
        if (strpos($class, $prefix) === 0) {
            $is_modern_lib = true;
            break;
        }
    }

    if ($is_modern_lib && version_compare(PHP_VERSION, '8.1', '<')) {
        return;
    }
    
    $prefix_map = [
        'RobThree\\Auth\\' => ADVAIPBL_PLUGIN_PATH . 'includes/lib/RobThree/Auth/',
        'BaconQrCode\\'    => ADVAIPBL_PLUGIN_PATH . 'includes/lib/BaconQrCode/',
        'DASPRiD\\Enum\\'   => ADVAIPBL_PLUGIN_PATH . 'includes/lib/DASPRiD/Enum/',
		'GeoIp2\\'         => ADVAIPBL_PLUGIN_PATH . 'includes/lib/GeoIp2/',
		'MaxMind\\Db\\'     => ADVAIPBL_PLUGIN_PATH . 'includes/lib/MaxMind/Db/',
    ];

    foreach ($prefix_map as $prefix => $base_dir) {
        $len = strlen($prefix);
        if (strncmp($prefix, $class, $len) !== 0) {
            continue;
        }
        
        $relative_class = substr($class, $len);
        $file = rtrim($base_dir, '/') . '/' . str_replace('\\', '/', $relative_class) . '.php';

        if (file_exists($file)) {
            require $file;
            return;
        }
    }
});

require_once ADVAIPBL_PLUGIN_PATH . 'includes/class-advaipbl-geolocation-manager.php';
require_once ADVAIPBL_PLUGIN_PATH . 'includes/class-advaipbl-session-manager.php';
require_once ADVAIPBL_PLUGIN_PATH . 'includes/class-advaipbl-main.php';




function advaipbl_initialize() {
    // load_plugin_textdomain eliminado porque WP 4.6+ lo hace automático.
    
    ADVAIPBL_Main::get_instance();
}
add_action( 'after_setup_theme', 'advaipbl_initialize' );

function advaipbl_add_settings_link( $links ) {
    $settings_link = sprintf(
        '<a href="%s">%s</a>',
        esc_url( admin_url( 'admin.php?page=advaipbl_settings_page' ) ),
        esc_html__( 'Settings', 'advanced-ip-blocker' )
    );
    array_unshift( $links, $settings_link );
    return $links;
}
add_filter( 'plugin_action_links_' . plugin_basename( __FILE__ ), 'advaipbl_add_settings_link' );

function advaipbl_register_cli_commands() {
    if ( defined( 'WP_CLI' ) && WP_CLI ) {
        if ( version_compare( PHP_VERSION, '8.1', '>=' ) ) {
            require_once ADVAIPBL_PLUGIN_PATH . 'includes/lib/RobThree/Auth/TwoFactorAuth.php';
            require_once ADVAIPBL_PLUGIN_PATH . 'includes/class-advaipbl-2fa-manager.php';
        }
        
        require_once ADVAIPBL_PLUGIN_PATH . 'includes/class-advaipbl-cli.php';
        WP_CLI::add_command( 'advaipbl', 'ADVAIPBL_CLI' );
    }
}
add_action( 'plugins_loaded', 'advaipbl_register_cli_commands', 20 );

function advaipbl_activate_plugin() {
    // Ejecutar rutinas completas de activación (tablas BD, ajustes por defecto, transients)
    ADVAIPBL_Main::activate_plugin();
    
    // Disparar el asistente SOLO en instalaciones nuevas.
    if ( false === get_option( 'advaipbl_version_installed' ) ) {
        add_option( 'advaipbl_run_setup_wizard', true );
    }

    // Actualizar/establecer la versión instalada.
    update_option( 'advaipbl_version_installed', ADVAIPBL_VERSION );
	
    // Programar crons inmediatamente a través del manager
    $instance = ADVAIPBL_Main::get_instance();
    if ( isset( $instance->cron_manager ) ) {
        $instance->cron_manager->schedule_jobs();
    }
}
register_activation_hook( __FILE__, 'advaipbl_activate_plugin' );

function advaipbl_deactivate_plugin() {
    // Limpiar todos los crons programados
    $cron_hooks = [
        'advaipbl_purge_old_logs_event', 'advaipbl_send_summary_email',
        'advaipbl_send_signature_summary_email', 'advaipbl_update_spamhaus_list_event',
        'advaipbl_send_telemetry_data_event', 'advaipbl_threat_score_decay_event',
        'advaipbl_update_geoip_db_event', 'advaipbl_cleanup_expired_cache_event',
        'advaipbl_scheduled_scan_event', 'advaipbl_daily_fim_scan',
        'advaipbl_cloudflare_cleanup_event',
        'advaipbl_update_community_list_event',
        'advaipbl_community_report_event_v2'
    ];
    
    foreach ($cron_hooks as $hook) {
        wp_clear_scheduled_hook($hook);
    }
}
register_deactivation_hook( __FILE__, 'advaipbl_deactivate_plugin' );