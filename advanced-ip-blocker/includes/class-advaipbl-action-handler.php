<?php

if ( ! defined( 'ABSPATH' ) ) exit;

class ADVAIPBL_Action_Handler {

    /**
     * Instancia de la clase principal del plugin.
     * @var ADVAIPBL_Main
     */
    private $plugin;

    /**
     * Constructor.
     * @param ADVAIPBL_Main $plugin_instance La instancia de la clase principal.
     */
    public function __construct($plugin_instance = null) {
        if (is_null($plugin_instance)) {
            // Si por alguna razón se llama sin la instancia, la obtenemos.
            $this->plugin = ADVAIPBL_Main::get_instance();
        } else {
            $this->plugin = $plugin_instance;
        }
    }

    public function handle_admin_actions() {
        if ( isset( $_GET['action'] ) && $_GET['action'] === 'advaipbl_reset_2fa' && isset( $_GET['user_id'] ) ) {
            $user_id_to_reset = absint( $_GET['user_id'] );
            if ( isset( $_GET['advaipbl_2fa_nonce'] ) && wp_verify_nonce( sanitize_text_field( wp_unslash( $_GET['advaipbl_2fa_nonce'] ) ), 'advaipbl_reset_2fa_' . $user_id_to_reset ) ) {
                if ( current_user_can( 'edit_users' ) ) {
                    if ( $this->plugin->tfa_manager ) {
                        $this->plugin->tfa_manager->admin_reset_for_user( $user_id_to_reset );
                        $user_info = get_userdata($user_id_to_reset);
						/* translators: %s: Username. */
                        $message = sprintf( __( 'Two-Factor Authentication has been reset for user %s.', 'advanced-ip-blocker' ), $user_info->user_login );
                        set_transient( ADVAIPBL_Main::TRANSIENT_ADMIN_NOTICE, ['message' => $message, 'type' => 'success'], 30 );
                    }
                }
            }
            wp_safe_redirect( remove_query_arg( ['action', 'user_id', 'advaipbl_2fa_nonce'] ) );
            exit;
        }
		elseif ( isset( $_GET['action'] ) && $_GET['action'] === 'advaipbl_delete_lockdown' && isset( $_GET['lockdown_id'] ) ) {
            $lockdown_id = absint( $_GET['lockdown_id'] );
            $nonce = sanitize_text_field( wp_unslash( $_GET['_wpnonce'] ?? '' ) );

            if ( wp_verify_nonce( $nonce, 'advaipbl_delete_lockdown_' . $lockdown_id ) && current_user_can('manage_options') ) {
                global $wpdb;
                $lockdowns_table = $wpdb->prefix . 'advaipbl_endpoint_lockdowns';
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                $wpdb->delete($lockdowns_table, ['id' => $lockdown_id], ['%d']);

                $this->plugin->log_event(sprintf('Endpoint lockdown #%d was manually cancelled by %s.', $lockdown_id, $this->plugin->get_current_admin_username()), 'warning');
                set_transient( ADVAIPBL_Main::TRANSIENT_ADMIN_NOTICE, ['message' => __('The endpoint lockdown has been cancelled.', 'advanced-ip-blocker'), 'type' => 'success'], 30 );
            }
            wp_safe_redirect( remove_query_arg( ['action', 'lockdown_id', '_wpnonce'] ) );
            exit;
        }
	  
        $nonce = sanitize_text_field( wp_unslash( $_REQUEST['_wpnonce'] ?? '' ) );
        $action = isset( $_REQUEST['action'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['action'] ) ) : '';
        $action_type = isset( $_POST['action_type'] ) ? sanitize_text_field( wp_unslash( $_POST['action_type'] ) ) : '';

        $nonce_is_valid = false;
        if (!empty($action) && strpos($action, 'advaipbl_') === 0 && wp_verify_nonce($nonce, $action)) {
            $action_type = $action;
            $nonce_is_valid = true;
        } elseif (isset($_POST['advaipbl_admin_nonce_action']) && wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['advaipbl_admin_nonce_action'])), 'advaipbl_admin_nonce_action')) {
            $nonce_is_valid = true;
        }

        if (!$nonce_is_valid || !current_user_can('manage_options')) {
            return;
        }

        $bulk_action = isset( $_POST['bulk_action'] ) ? sanitize_text_field( wp_unslash( $_POST['bulk_action'] ) ) : ( isset( $_POST['bulk_action2'] ) ? sanitize_text_field( wp_unslash( $_POST['bulk_action2'] ) ) : '-1' );

        if ($bulk_action === 'unblock_all') {
            $this->plugin->unblock_all_ips('Admin Action (Bulk)');
            $message = __('All blocked IPs have been successfully unblocked.', 'advanced-ip-blocker');
        } elseif ($bulk_action === 'unblock' && isset($_POST['ips_to_process'])) {
            $ips_to_process = array_map('sanitize_text_field', (array) wp_unslash($_POST['ips_to_process']));
            $processed_count = 0;
            
            foreach ($ips_to_process as $ip_or_range) {
                if ($this->plugin->is_valid_ip_or_range($ip_or_range)) {
                    $this->plugin->desbloquear_ip($ip_or_range, true); // <-- TRUE AQUÍ
                    $processed_count++;
                }
            }
            
            if ( $processed_count > 0 && ! empty( $this->plugin->options['enable_htaccess_write'] ) ) {
                $this->plugin->htaccess_manager->update_htaccess();
            }

            if ($processed_count > 0) {
                /* translators: %d: Number of entries. */
                $message = sprintf(_n('%d entry has been unblocked.', '%d entries have been unblocked.', $processed_count, 'advanced-ip-blocker'), $processed_count);
            } else {
                $message = __('No valid entries were selected for unblocking.', 'advanced-ip-blocker');
                $type = 'warning';
            }        
        } elseif ($bulk_action === 'remove' && isset($_POST['entries_to_process'])) {
                // LÓGICA PARA LA WHITELIST
                $entries_to_remove = array_map('sanitize_text_field', (array) wp_unslash($_POST['entries_to_process']));
                $whitelist = get_option(ADVAIPBL_Main::OPTION_WHITELIST, []);
                $removed_count = 0;
                
                foreach ($entries_to_remove as $entry) {
                    if (array_key_exists($entry, $whitelist)) {
                        unset($whitelist[$entry]);
                        $removed_count++;
                    }
                }

                if ($removed_count > 0) {
                    update_option(ADVAIPBL_Main::OPTION_WHITELIST, $whitelist);
                    wp_cache_delete(ADVAIPBL_Main::OPTION_WHITELIST, 'options');
                    /* translators: %d: Number of entries. */
                    $message = sprintf(_n('%d entry removed from whitelist.', '%d entries removed from whitelist.', $removed_count, 'advanced-ip-blocker'), $removed_count);
                    $this->plugin->log_event(sprintf('%d entries were removed from the whitelist by %s.', $removed_count, $this->plugin->get_current_admin_username()), 'warning');
                } else {
                    $message = __('No valid entries were selected for removal.', 'advanced-ip-blocker');
                    $type = 'warning';
                }
            
        } elseif (!empty($action_type)) {
            $current_user_login = $this->plugin->get_current_admin_username();
            switch ($action_type) {
                case 'advaipbl_unblock_ip':
                    $ip_to_unblock = isset($_GET['ip']) ? sanitize_text_field(wp_unslash($_GET['ip'])) : '';
                    if ($this->plugin->is_valid_ip_or_range($ip_to_unblock)) {
                        $this->plugin->desbloquear_ip($ip_to_unblock);
						/* translators: $s: IP */
                        $message = sprintf(__('Entry %s has been unblocked.', 'advanced-ip-blocker'), $ip_to_unblock);
                    } else {
                        $message = __('Invalid entry provided for unblocking.', 'advanced-ip-blocker');
                        $type = 'error';
                    }
                    break;
                case 'unblock_all':
                    $this->plugin->unblock_all_ips('Admin Action');
                    $message = __('All blocked IPs have been successfully unblocked.', 'advanced-ip-blocker');
                    break;
                case 'save_user_agents':
                    $blocked_raw = isset($_POST['blocked_user_agents']) ? sanitize_textarea_field(wp_unslash($_POST['blocked_user_agents'])) : '';
                    update_option(ADVAIPBL_Main::OPTION_BLOCKED_UAS, array_filter(array_map('trim', explode("\n", $blocked_raw))));
                    $whitelisted_raw = isset($_POST['whitelisted_user_agents']) ? sanitize_textarea_field(wp_unslash($_POST['whitelisted_user_agents'])) : '';
                    update_option(ADVAIPBL_Main::OPTION_WHITELISTED_UAS, array_filter(array_map('trim', explode("\n", $whitelisted_raw))));
					/* translators: $s: Username. */
                    $this->plugin->log_event(sprintf(__('User-Agent lists updated by %s.', 'advanced-ip-blocker'), $current_user_login), 'info');
                    $message = __('User-Agent lists saved successfully.', 'advanced-ip-blocker');
                    break;
                case 'save_honeypot_urls':
                    $urls_raw = isset($_POST['honeypot_urls']) ? sanitize_textarea_field(wp_unslash($_POST['honeypot_urls'])) : '';
                    update_option(ADVAIPBL_Main::OPTION_HONEYPOT_URLS, array_filter(array_map('trim', explode("\n", $urls_raw))));
					/* translators: $s: Username. */
                    $this->plugin->log_event(sprintf(__('Honeypot URLs list updated by %s.', 'advanced-ip-blocker'), $current_user_login), 'info');
                    $message = __('Honeypot URLs list saved successfully.', 'advanced-ip-blocker');
                    break;
                case 'save_asn_lists':
    // Función auxiliar para procesar el contenido del textarea
    $process_asn_list = function($textarea_content) {
        $lines = explode("\n", $textarea_content);
        $processed_list = [];

        foreach ($lines as $line) {
            $trimmed_line = trim($line);

            if (empty($trimmed_line)) {
                continue; // Saltar líneas vacías
            }
            
            // Si es un comentario, lo guardamos tal cual
            if (strpos($trimmed_line, '#') === 0) {
                $processed_list[] = $trimmed_line;
                continue;
            }

            // Si es una línea con un ASN y un comentario, separamos las partes
            $parts = explode('#', $trimmed_line, 2);
            $asn = strtoupper(trim($parts[0]));
            $comment = isset($parts[1]) ? '# ' . trim($parts[1]) : '';
            
            // Validamos que la primera parte sea un ASN
            if (preg_match('/^AS\d+$/i', $asn)) {
                $line_to_save = $asn;
                if (!empty($comment)) {
                    $line_to_save .= ' ' . $comment;
                }
                $processed_list[] = $line_to_save;
            }
        }
        return $processed_list;
    };

    // Procesar y guardar la Blocklist
    $blocked_raw = isset($_POST['blocked_asns']) ? sanitize_textarea_field(wp_unslash($_POST['blocked_asns'])) : '';
    $final_blocked_list = $process_asn_list($blocked_raw);
    update_option(ADVAIPBL_Main::OPTION_BLOCKED_ASNS, $final_blocked_list);
    
    // Procesar y guardar la Whitelist
    $whitelisted_raw = isset($_POST['whitelisted_asns']) ? sanitize_textarea_field(wp_unslash($_POST['whitelisted_asns'])) : '';
    $final_whitelisted_list = $process_asn_list($whitelisted_raw);
    update_option(ADVAIPBL_Main::OPTION_WHITELISTED_ASNS, $final_whitelisted_list);

    /* translators: %s: Username. */
    $this->plugin->log_event(sprintf(__('ASN lists updated by %s.', 'advanced-ip-blocker'), $current_user_login), 'info');
    $message = __('ASN lists saved successfully.', 'advanced-ip-blocker');
    break;
				
                case 'clear_all_threat_scores':                
                global $wpdb;
                $table_name = $wpdb->prefix . 'advaipbl_ip_scores';
                // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
                $wpdb->query("TRUNCATE TABLE `{$table_name}`");
                /* translators: %s: Username. */
                $this->plugin->log_event(sprintf(__('All threat scores have been manually reset to 0 by %s.', 'advanced-ip-blocker'), $current_user_login), 'critical');
                $message = __('All active threat scores have been reset to 0.', 'advanced-ip-blocker');
                break;
				
				case 'clear_all_signatures':
                global $wpdb;
                $table_name = $wpdb->prefix . 'advaipbl_malicious_signatures';
                // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
                $wpdb->query("TRUNCATE TABLE `{$table_name}`");
                /* translators: %s: Username. */
                $this->plugin->log_event(sprintf(__('All malicious signatures have been manually deleted by %s.', 'advanced-ip-blocker'), $current_user_login), 'critical');
                $message = __('All active malicious signatures have been deleted.', 'advanced-ip-blocker');
                break;
				
                case 'clear_specific_logs':
                    global $wpdb;
                    $log_types_to_clear = isset($_POST['log_types_to_clear']) && is_array($_POST['log_types_to_clear']) ? array_map('sanitize_key', $_POST['log_types_to_clear']) : [];
                    if (!empty($log_types_to_clear)) {
                        $placeholders = implode(', ', array_fill(0, count($log_types_to_clear), '%s'));
                        
                        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
                        $wpdb->query($wpdb->prepare("DELETE FROM {$wpdb->prefix}advaipbl_logs WHERE log_type IN ({$placeholders})", $log_types_to_clear));
                        
                        $types_string = implode(', ', $log_types_to_clear);
                        /* translators: 1: The log type(s). 2: The admin username. */
                        $this->plugin->log_event(sprintf(__('Logs of type(s) [%1$s] manually deleted by %2$s.', 'advanced-ip-blocker'), $types_string, $current_user_login), 'warning');
                        /* translators: %s: The log type(s) that were deleted. */
						$message = sprintf(__('Selected logs (%s) have been deleted.', 'advanced-ip-blocker'), $types_string);
                    } else {
                        $message = __('No log types were selected to be deleted.', 'advanced-ip-blocker');
                        $type = 'warning';
                    }
                    break;
                case 'clear_all_logs':
                    global $wpdb;
                    // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
                    $wpdb->query("TRUNCATE TABLE `{$wpdb->prefix}advaipbl_logs`");
                    // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
                    $wpdb->query("TRUNCATE TABLE `{$wpdb->prefix}advaipbl_notifications_queue`");
					/* translators: %s: Username. */
                    $this->plugin->log_event(sprintf(__('All log records have been manually deleted by %s.', 'advanced-ip-blocker'), $current_user_login), 'critical');
                    $message = __('All logs have been deleted.', 'advanced-ip-blocker');
                    break;
                default:
                    $ip_or_range = isset($_POST['ip_address']) ? sanitize_text_field(wp_unslash($_POST['ip_address'])) : '';
                    if ($ip_or_range && !$this->plugin->is_valid_ip_or_range($ip_or_range)) {
                        $message = __('The entered value is not a valid IP, CIDR range, or IP range.', 'advanced-ip-blocker');
                        $type = 'error';
                    } elseif ($ip_or_range) {
                        switch ($action_type) {
                            case 'add_manual_block':
                                // Esta es la nueva lógica centralizada
                                global $wpdb;
                                $table_name = $wpdb->prefix . 'advaipbl_blocked_ips';
                                // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
                                $exists = $wpdb->get_var($wpdb->prepare("SELECT id FROM {$table_name} WHERE ip_range = %s", $ip_or_range));
                                
                                if ($exists) {
									/* translators: %s: IP. */
                                    $message = sprintf( __( 'Entry %s was already blocked.', 'advanced-ip-blocker' ), $ip_or_range );
                                    $type = 'info';
                                } else {
                                    $this->plugin->block_ip_instantly( $ip_or_range, 'manual', __('Manual Block', 'advanced-ip-blocker'), [], 'admin_action' );
                                    /* translators: %s: IP. */
									$message = sprintf( __( 'Entry %s has been blocked.', 'advanced-ip-blocker' ), $ip_or_range );
                                }
                                break;
                            case 'remove_block':
                                $this->plugin->desbloquear_ip($ip_or_range);
								/* translators: %s: IP. */
                                $message = sprintf( __( 'IP %s unblocked from all lists.', 'advanced-ip-blocker' ), $ip_or_range );
                                break;
                            case 'add_whitelist':
                                $success = $this->plugin->add_to_whitelist_and_unblock( $ip_or_range, __('Manually added via admin panel', 'advanced-ip-blocker') );
                                if ( $success ) {
									/* translators: %s: IP. */
                                    $message = sprintf( __( 'Entry %s added to whitelist and unblocked.', 'advanced-ip-blocker' ), $ip_or_range );
                                } else {
									/* translators: %s: IP. */
                                    $message = sprintf( __( 'Entry %s was already in the whitelist or is invalid.', 'advanced-ip-blocker' ), $ip_or_range ); $type = 'info';
                                }
                                break;
                            case 'remove_whitelist':
                                $list = get_option( ADVAIPBL_Main::OPTION_WHITELIST, [] );
                                if ( array_key_exists( $ip_or_range, $list ) ) {
                                    unset( $list[ $ip_or_range ] );
                                    update_option( ADVAIPBL_Main::OPTION_WHITELIST, $list );
                                    wp_cache_delete( ADVAIPBL_Main::OPTION_WHITELIST, 'options' );
									/* translators: 1: IP, 2: Username */
                                    $this->plugin->log_event( sprintf( __( 'IP %1$s removed from whitelist by %2$s.', 'advanced-ip-blocker' ), $ip_or_range, $current_user_login ), 'info', $ip_or_range );
                                    /* translators: %s: IP. */
									$message = sprintf( __( 'IP %s removed from whitelist.', 'advanced-ip-blocker' ), $ip_or_range );
                                }
                                break;
                        }
                    }
                    break;
            }
        }

        if ($message) {
            $type = isset($type) ? $type : 'success';
            set_transient(ADVAIPBL_Main::TRANSIENT_ADMIN_NOTICE, ['message' => $message, 'type' => $type], 30);
        }
        wp_safe_redirect(remove_query_arg(['settings-updated', 's', 'action', 'ip', '_wpnonce'], wp_get_referer()));
        exit;
   }
   
   /**
 * Maneja los datos enviados desde el Paso 1 del asistente de configuración.
 */
public function handle_wizard_step_1() {
    // Verificar nonce y permisos
    if ( ! isset( $_POST['_wpnonce'] ) || ! wp_verify_nonce( sanitize_key( $_POST['_wpnonce'] ), 'advaipbl_wizard_step_1_nonce' ) ) {
        wp_die( 'Security check failed.' );
    }
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( 'Permission denied.' );
    }

    // Obtener las IPs (las volvemos a detectar en el servidor para seguridad)
    $admin_ip = $this->plugin->get_client_ip();
    $server_ip = $this->plugin->get_server_ip();

    if ( $admin_ip ) {
        $this->plugin->add_to_whitelist_and_unblock( $admin_ip, __( 'Admin IP (added by setup wizard)', 'advanced-ip-blocker' ) );
    }
    if ( $server_ip && $server_ip !== $admin_ip ) {
        $this->plugin->add_to_whitelist_and_unblock( $server_ip, __( 'Server IP (added by setup wizard)', 'advanced-ip-blocker' ) );
    }

    // Redirigir al siguiente paso
    wp_safe_redirect( admin_url( 'admin.php?page=advaipbl-setup-wizard&step=2' ) );
    exit;
}
/**
 * Maneja los datos enviados desde el Paso 2 del asistente de configuración.
 */
public function handle_wizard_step_2() {
    // Verificar nonce y permisos
    if ( ! isset( $_POST['_wpnonce'] ) || ! wp_verify_nonce( sanitize_key( $_POST['_wpnonce'] ), 'advaipbl_wizard_step_2_nonce' ) ) {
        wp_die( 'Security check failed.' );
    }
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( 'Permission denied.' );
    }

    $options = get_option( ADVAIPBL_Main::OPTION_SETTINGS, [] );

    // Activar User-Agent si está marcado
    if ( isset( $_POST['activate_user_agent_rules'] ) && $_POST['activate_user_agent_rules'] === '1' ) {
            $options['enable_user_agent_blocking'] = '1';
            $default_uas = $this->plugin->get_default_user_agents();
            $existing_uas = get_option( ADVAIPBL_Main::OPTION_BLOCKED_UAS, [] );
            $merged_uas = array_unique( array_merge( $existing_uas, $default_uas ) );
            update_option( ADVAIPBL_Main::OPTION_BLOCKED_UAS, $merged_uas );
        }

    // Activar Honeypot si está marcado
    if ( isset( $_POST['activate_honeypot_rules'] ) && $_POST['activate_honeypot_rules'] === '1' ) {
            $options['enable_honeypot_blocking'] = '1';
            $default_honeypots = $this->plugin->get_default_honeypot_urls();
            $existing_honeypots = get_option( ADVAIPBL_Main::OPTION_HONEYPOT_URLS, [] );
            $merged_honeypots = array_unique( array_merge( $existing_honeypots, $default_honeypots ) );
            update_option( ADVAIPBL_Main::OPTION_HONEYPOT_URLS, $merged_honeypots );
        }

    update_option( ADVAIPBL_Main::OPTION_SETTINGS, $options );

    // Redirigir al siguiente paso
    wp_safe_redirect( admin_url( 'admin.php?page=advaipbl-setup-wizard&step=3' ) );
    exit;
}

/**
 * Maneja los datos enviados desde el Paso 3 del asistente de configuración.
 */
public function handle_wizard_step_3() {
    if ( ! isset( $_POST['_wpnonce'] ) || ! wp_verify_nonce( sanitize_key( $_POST['_wpnonce'] ), 'advaipbl_wizard_step_3_nonce' ) ) {
        wp_die( 'Security check failed.' );
    }
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( 'Permission denied.' );
    }

    $options = get_option( ADVAIPBL_Main::OPTION_SETTINGS, [] );
	
	if ( isset( $_POST['activate_htaccess'] ) && $_POST['activate_htaccess'] === '1' ) {
        $options['enable_htaccess_write'] = '1';
        $options['enable_htaccess_ip_blocking'] = '1';
        $options['htaccess_protect_system_files'] = '1';
        $options['htaccess_protect_wp_config'] = '1';
        $options['htaccess_protect_readme'] = '1';
        
        update_option( ADVAIPBL_Main::OPTION_SETTINGS, $options );
        // Forzamos la actualización de la instancia principal para que el manager vea los cambios
        $this->plugin->options = $options;
        // Escribimos las reglas
        $this->plugin->htaccess_manager->update_htaccess();
    } else {
        // Si no está marcado, solo actualizamos las opciones (la actualización normal de options lo hará)
        update_option( ADVAIPBL_Main::OPTION_SETTINGS, $options );
    }

    if ( isset( $_POST['activate_waf'] ) && $_POST['activate_waf'] === '1' ) {
        $options['enable_waf'] = '1';
        // Aplicamos las reglas WAF por defecto. Necesitaremos una función auxiliar.
        $default_waf_rules = $this->plugin->get_default_waf_rules();
        $existing_waf_rules_raw = get_option( ADVAIPBL_Main::OPTION_WAF_RULES, '' );
        $existing_waf_rules = empty(trim($existing_waf_rules_raw)) ? [] : array_filter(array_map('trim', explode("\n", $existing_waf_rules_raw)));
        $merged_rules = array_unique( array_merge( $existing_waf_rules, $default_waf_rules ) );
        update_option( ADVAIPBL_Main::OPTION_WAF_RULES, implode("\n", $merged_rules) );
    }

    if ( isset( $_POST['activate_rate_limiting'] ) && $_POST['activate_rate_limiting'] === '1' ) {
        $options['rate_limiting_enable'] = '1';
    }
	
	if ( isset( $_POST['activate_spamhaus'] ) && $_POST['activate_spamhaus'] === '1' ) {
        $options['enable_spamhaus_asn'] = '1';
        // Disparamos una actualización inicial de la lista en segundo plano.
        // wp_schedule_single_event es perfecto para esto, no retrasa la carga de la página.
        if (!wp_next_scheduled('advaipbl_update_spamhaus_list_event')) {
             wp_schedule_single_event(time() + 10, 'advaipbl_update_spamhaus_list_event');
        }
    }
	
	if ( isset( $_POST['activate_community_network'] ) && $_POST['activate_community_network'] === '1' ) {
        $options['enable_community_network'] = '1';  // Compartir (Join)
        $options['enable_community_blocking'] = '1'; // Bloquear (Protect)
    }
	
    update_option( ADVAIPBL_Main::OPTION_SETTINGS, $options );

    wp_safe_redirect( admin_url( 'admin.php?page=advaipbl-setup-wizard&step=4' ) );
    exit;
}


/**
 * Maneja los datos enviados desde el Paso 4 del asistente de configuración.
 */
public function handle_wizard_step_4() {
    if ( ! isset( $_POST['_wpnonce'] ) || ! wp_verify_nonce( sanitize_key( $_POST['_wpnonce'] ), 'advaipbl_wizard_step_4_nonce' ) ) {
        wp_die( 'Security check failed.' );
    }
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( 'Permission denied.' );
    }

    $options = get_option( ADVAIPBL_Main::OPTION_SETTINGS, [] );

    if ( isset( $_POST['activate_threat_scoring'] ) && $_POST['activate_threat_scoring'] === '1' ) {
        $options['enable_threat_scoring'] = '1';
    }

    update_option( ADVAIPBL_Main::OPTION_SETTINGS, $options );
    // Eliminamos la bandera para que ya no se muestre el aviso del panel.
    delete_option( 'advaipbl_run_setup_wizard' );
    // Redirigir al paso final
    wp_safe_redirect( admin_url( 'admin.php?page=advaipbl-setup-wizard&step=5' ) );
    exit;
}

}