<?php
/**
 * Fired when the plugin is uninstalled.
 * This script must be self-contained and not rely on any plugin code.
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

// Función auxiliar para borrado recursivo
// phpcs:disable WordPress.WP.AlternativeFunctions
function advaipbl_uninstall_recursive_rmdir( $dir ) {
    if (!is_dir($dir)) return;
    $files = array_diff( scandir( $dir ), array( '.', '..' ) );
    foreach ( $files as $file ) {
        ( is_dir( "$dir/$file" ) ) ? advaipbl_uninstall_recursive_rmdir( "$dir/$file" ) : unlink( "$dir/$file" );
    }
    rmdir( $dir );
}
// phpcs:enable WordPress.WP.AlternativeFunctions

// Función auxiliar simple para peticiones CF
if (!function_exists('advaipbl_uninstall_cf_req')) {
    function advaipbl_uninstall_cf_req($method, $endpoint, $token) {
        $url = 'https://api.cloudflare.com/client/v4/' . $endpoint;
        $args = [
            'method' => $method,
            'headers' => [
                'Authorization' => 'Bearer ' . $token,
                'Content-Type' => 'application/json',
            ],
            'timeout' => 15
        ];
        $resp = wp_remote_request($url, $args);
        if (is_wp_error($resp)) return false;
        return json_decode(wp_remote_retrieve_body($resp), true);
    }
}

// Función principal de limpieza para un sitio específico
function advaipbl_process_site_uninstallation() {
    global $wpdb;

    // Obtener la opción de borrado de forma segura
    // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
    $settings_option = get_option( 'advaipbl_settings' );
    
    // Verificamos si el valor de borrado está marcado (aceptando '1', 1, true, 'on', etc.)
    $should_delete = is_array( $settings_option ) && ! empty( $settings_option['delete_data_on_uninstall'] ) && in_array( $settings_option['delete_data_on_uninstall'], [ 1, '1', true, 'on', 'yes' ], true );

    if ( $should_delete ) {

        // --- 0. UNREGISTER FROM CENTRAL SERVER ---
        $advaipbl_api_token = $settings_option['api_token_v3'] ?? '';
        if (!empty($advaipbl_api_token)) {
            wp_remote_post('https://advaipbl.com/wp-json/aib-api/v3/unregister', [
                'headers' => [
                    'Authorization' => 'Bearer ' . $advaipbl_api_token,
                    'Content-Type'  => 'application/json',
                    'Accept'        => 'application/json'
                ],
                'timeout' => 10,
                'blocking' => false // No need to wait for response during uninstall
            ]);
        }

        // --- 1. Borrar Tablas Personalizadas ---
        // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
        $tables_to_drop = [
            'advaipbl_logs', 'advaipbl_notifications_queue', 'advaipbl_ip_scores',
            'advaipbl_request_log', 'advaipbl_malicious_signatures', 'advaipbl_cache',
            'advaipbl_blocked_ips', 'advaipbl_endpoint_lockdowns', 'advaipbl_pending_reports', 'advaipbl_community_ips',
            'advaipbl_activity_log' // All 11 tables included securely
        ];
        // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
        foreach ( $tables_to_drop as $table_name ) {
            $full_table_name = $wpdb->prefix . $table_name;
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.SchemaChange, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared
            $wpdb->query( "DROP TABLE IF EXISTS `{$full_table_name}`" );
        }

        // --- 1.5. Limpiar Cloudflare (Si está habilitado) ---
        if ( ! empty( $settings_option['enable_cloudflare'] ) && '1' === $settings_option['enable_cloudflare'] &&
             ! empty( $settings_option['cf_api_token'] ) && ! empty( $settings_option['cf_zone_id'] ) ) {
            
            $advaipbl_cf_token = $settings_option['cf_api_token'];
            $advaipbl_cf_zone  = $settings_option['cf_zone_id'];

            // Buscar reglas [AIB]
            $page = 1;
            $advaipbl_has_more = true;
            $advaipbl_rules_to_delete = [];

            while ($advaipbl_has_more) {
                $advaipbl_res = advaipbl_uninstall_cf_req('GET', "zones/{$advaipbl_cf_zone}/firewall/access_rules/rules?per_page=100&page={$page}", $advaipbl_cf_token);
                if (!$advaipbl_res || empty($advaipbl_res['result'])) {
                    $advaipbl_has_more = false;
                    break;
                }

                foreach ($advaipbl_res['result'] as $advaipbl_rule) {
                    if (isset($advaipbl_rule['notes']) && strpos($advaipbl_rule['notes'], '[AIB]') !== false) {
                        $advaipbl_rules_to_delete[] = $advaipbl_rule['id'];
                    }
                }

                $advaipbl_total_pages = $advaipbl_res['result_info']['total_pages'] ?? 1;
                if ($page >= $advaipbl_total_pages) $advaipbl_has_more = false;
                else $page++;
            }

            // Eliminar reglas
            foreach ($advaipbl_rules_to_delete as $advaipbl_rule_id) {
                advaipbl_uninstall_cf_req('DELETE', "zones/{$advaipbl_cf_zone}/firewall/access_rules/rules/{$advaipbl_rule_id}", $advaipbl_cf_token);
            }
        }

        // --- 2. Borrar Opciones de la Tabla `wp_options` ---
        // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
        $options_to_delete = [
            // Opciones principales y de configuración
            'advaipbl_settings',
            'advaipbl_waf_rules',
            'advaipbl_blocked_asns',
            'advaipbl_whitelisted_asns',
            'advaipbl_blocked_user_agents',
            'advaipbl_whitelisted_user_agents',
            'advaipbl_ips_whitelist',
            'advaipbl_honeypot_urls',
            'advaipbl_advanced_rules',
            
            // Opciones de sistema y estado
            'advaipbl_db_version',
            'advaipbl_version_installed',
            'advaipbl_run_setup_wizard',
            'advaipbl_admin_ip_whitelist_trigger',
            'advaipbl_usm_sessions_per_page',
            'advaipbl_telemetry_notice_dismissed',
            'advaipbl_ip_table_migration_complete',
            'advaipbl_legacy_options_cleaned',
            'advaipbl_autoload_version',
            'advaipbl_spamhaus_asn_list',
            'advaipbl_spamhaus_last_update',
            'advaipbl_spamhaus_drop_list',
            'advaipbl_ai_bot_ips',
            'advaipbl_bot_ips',
            'advaipbl_last_cron_ip',
            
            // Community Network
            'advaipbl_community_blocklist',
            'advaipbl_community_last_update',
            
            // Opciones de bloqueo (ahora obsoletas, para limpieza de instalaciones antiguas)
            'advaipbl_blocked_ips_manual',
            'advaipbl_blocked_ips_404',
            'advaipbl_blocked_ips_403',
            'advaipbl_blocked_ips_login',
            'advaipbl_blocked_ips_geoblock',
            'advaipbl_blocked_ips_honeypot',
            'advaipbl_blocked_ips_user_agent',
            'advaipbl_blocked_ips_waf',
            'advaipbl_blocked_ips_threat_score',
            'advaipbl_blocked_ips_rate_limit',
            'advaipbl_blocked_ips_asn',
            'advaipbl_blocked_ips_xmlrpc_block',
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

            // Opciones de legado con prefijo antiguo (con guion)
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
            
            // Internal Security
            'advaipbl_fim_baseline_hashes',
            'advaipbl_vip_salt_modifier',
            
            // Security Headers
            'advaipbl_security_headers',
            
            // System Flags
            'advaipbl_flush_firewalls_needed',
        ];
        
        // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
        foreach ( $options_to_delete as $option_name ) {
            delete_option( $option_name );
        }

        // --- 4. Borrar Transients ---
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE `option_name` LIKE %s OR `option_name` LIKE %s", $wpdb->esc_like( '_transient_advaipbl_' ) . '%', $wpdb->esc_like( '_transient_timeout_advaipbl_' ) . '%' ) );

        // --- 5. Borrar Metadatos de Usuario de 2FA ---
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->usermeta} WHERE `meta_key` LIKE %s", $wpdb->esc_like( '_advaipbl_2fa_' ) . '%' ) );
    }

    // --- Limpiar Tareas de Cron SIEMPRE (Incluso si no se borran datos) ---
    // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
    $cron_hooks = [
        'advaipbl_purge_old_logs_event', 'advaipbl_send_summary_email',
        'advaipbl_update_spamhaus_list_event', 'advaipbl_send_telemetry_data_event',
        'advaipbl_threat_score_decay_event', 'advaipbl_signature_analysis_event',
        'advaipbl_update_geoip_db_event', 'advaipbl_cleanup_expired_cache_event',
        'advaipbl_scheduled_scan_event', 'advaipbl_daily_fim_scan',
        'advaipbl_cloudflare_cleanup_event',
        'advaipbl_update_community_list_event',
        'advaipbl_community_report_event_v2',
        'advaipbl_cloudflare_sync_event',
        'advaipbl_clear_expired_blocks_event',
        'advaipbl_update_ai_bot_lists_event',
        'advaipbl_update_bot_lists_event',
        'advaipbl_send_signature_summary_email'
    ];
    // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
    foreach ($cron_hooks as $hook) {
        wp_clear_scheduled_hook($hook);
    }
}

// -----------------------------------------------------------------------------------------
// EJECUCIÓN PRINCIPAL DEL SCRIPT DE UNINSTALL
// -----------------------------------------------------------------------------------------

// 1. Procesar bases de datos (soporte completo para Multisite)
if ( is_multisite() ) {
    global $wpdb;
    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
    $blogs = $wpdb->get_results( "SELECT blog_id FROM {$wpdb->blogs}", ARRAY_A );
    if ( $blogs ) {
        // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
        foreach ( $blogs as $blog ) {
            switch_to_blog( $blog['blog_id'] );
            advaipbl_process_site_uninstallation();
            restore_current_blog();
        }
    }
} else {
    advaipbl_process_site_uninstallation();
}

// 2. Limpieza de Archivos y Directorios (Solo se hace una vez, a nivel global)
// Obtener la opción principal del sitio base para saber si borramos archivos físicos
// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
$global_settings = get_option( 'advaipbl_settings' );
if ( is_array($global_settings) && ! empty( $global_settings['delete_data_on_uninstall'] ) && in_array( $global_settings['delete_data_on_uninstall'], [ 1, '1', true, 'on', 'yes' ], true ) ) {
    
    // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
    $upload_dir = wp_upload_dir();
    
    // A. Directorio GeoIP
    // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
    $geoip_dir  = $upload_dir['basedir'] . '/advaipbl_geoip';
    if ( is_dir( $geoip_dir ) ) {
        advaipbl_uninstall_recursive_rmdir( $geoip_dir );
    }

    // B. Directorio de Backups Htaccess
    // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
    $backup_dir = $upload_dir['basedir'] . '/advaipbl-backups';
    if ( is_dir( $backup_dir ) ) {
        advaipbl_uninstall_recursive_rmdir( $backup_dir );
    }

    // C. Limpiar reglas del .htaccess (Borrado COMPLETO, no solo vaciar marcadores)
    if ( function_exists('get_home_path') ) {
        // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound   
        $htaccess_path = get_home_path() . '.htaccess';
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable
        if ( file_exists( $htaccess_path ) && is_writable( $htaccess_path ) ) {
            $advaipbl_content = file_get_contents($htaccess_path);
            if ($advaipbl_content !== false) {
                // Regex para eliminar todo el bloque, incluídos los marcadores.
                $advaipbl_new_content = preg_replace('/# BEGIN Advanced IP Blocker.*?# END Advanced IP Blocker\s*/s', '', $advaipbl_content);
                if ($advaipbl_new_content !== null && $advaipbl_new_content !== $advaipbl_content) {
                    file_put_contents($htaccess_path, $advaipbl_new_content);
                }
            }
        }
    }
}