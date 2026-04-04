<?php

if ( ! defined( 'ABSPATH' ) ) exit;

class ADVAIPBL_Admin_Pages {

    /**
     * Instancia de la clase principal del plugin.
     * @var ADVAIPBL_Main
     */
    private $plugin;

    /**
     * Constructor.
     * @param ADVAIPBL_Main $plugin_instance La instancia de la clase principal.
     */
    public function __construct(ADVAIPBL_Main $plugin_instance) {
        $this->plugin = $plugin_instance;
    }

    public function settings_page_content() {
    if (!current_user_can('manage_options')) {
        return;
    }

    nocache_headers(); // Prevent caching on this admin page
    
    // 1. DEFINIR LA ESTRUCTURA COMPLETA DEL MENÚ
    $menu_structure = [
        'dashboard' => [ 'title' => __('Dashboard', 'advanced-ip-blocker'), 'icon'  => 'dashicons-dashboard', 'sub_tabs' => [ 'main_dashboard' => __('Security Dashboard', 'advanced-ip-blocker'), 'status' => __('System Status', 'advanced-ip-blocker') ] ],
        'security_headers' => [ 
            'title' => __('Security Headers', 'advanced-ip-blocker'), 
            'icon'  => 'dashicons-admin-network', 
            'sub_tabs' => [ 'headers_config' => __('HTTP Headers', 'advanced-ip-blocker') ]
        ],
        'settings' => [ 
            'title' => __('Settings', 'advanced-ip-blocker'), 
            'icon'  => 'dashicons-admin-settings', 
            'sub_tabs' => [ 
                'general_settings' => __('General', 'advanced-ip-blocker'),                 
                '2fa_management'   => __('2FA Management', 'advanced-ip-blocker'), 
                'import_export'    => __('Import / Export', 'advanced-ip-blocker') 
            ] 
        ],
        'rules' => [ 'title' => __('Blocking Rules', 'advanced-ip-blocker'), 'icon'  => 'dashicons-shield-alt', 'sub_tabs' => [ 'waf' => __('Firewall (WAF)', 'advanced-ip-blocker'), 'user_agents' => __('User Agents', 'advanced-ip-blocker'), 'honeypot' => __('Honeypot URLs', 'advanced-ip-blocker'), 'asn_blocking' => __('ASN Blocking', 'advanced-ip-blocker'), 'advanced_rules' => __('Advanced Rules', 'advanced-ip-blocker') ] ],
        'ip_management' => [
            'title' => __('IP Management', 'advanced-ip-blocker'),
            'icon'  => 'dashicons-location',
            'sub_tabs' => [
                'blocked_ips'        => __('Blocked IPs', 'advanced-ip-blocker'),
                'blocked_signatures' => __('Blocked Signatures', 'advanced-ip-blocker'),
                'blocked_endpoints'  => __('Blocked Endpoints', 'advanced-ip-blocker'),
                'whitelist'          => __('Whitelist', 'advanced-ip-blocker')
            ]
        ],

        'scanner' => [ 
            'title' => __('Site Scanner', 'advanced-ip-blocker'), 
            'icon'  => 'dashicons-search', 
            'sub_tabs' => [ 'scan_overview' => __('Health & Vulnerabilities', 'advanced-ip-blocker') ] 
        ],
        'logs' => [ 'title' => __('Logs & Sessions', 'advanced-ip-blocker'), 'icon'  => 'dashicons-list-view', 'sub_tabs' => [ 'security_log' => __('Security Log', 'advanced-ip-blocker'), 'audit_log' => __('Activity Audit Log', 'advanced-ip-blocker'), 'general_log' => __('General Log', 'advanced-ip-blocker'), 'ip_trust_log'   => __('IP Trust Log', 'advanced-ip-blocker'), 'user_sessions' => __('User Sessions', 'advanced-ip-blocker'), 'cron_logs' => __('WP-Cron Log', 'advanced-ip-blocker') ] ],
        'about' => [ 'title' => __('About', 'advanced-ip-blocker'), 'icon'  => 'dashicons-info', 'sub_tabs' => [ 'credits' => __('Credits & Support', 'advanced-ip-blocker') ] ]
    ];
    // phpcs:disable WordPress.Security.NonceVerification.Recommended
    // La verificación de Nonce no es necesaria aquí.
    // Estas variables GET solo se usan para la navegación y visualización de pestañas,
    // no para procesar datos ni realizar acciones. La entrada ya se sanea con sanitize_key().
    $current_page_slug = isset($_GET['page']) ? sanitize_key($_GET['page']) : 'advaipbl_settings_page';
    
    // Primero, verificamos si la navegación es interna (clic en una pestaña/sub-pestaña)
    if (isset($_GET['tab'])) {
        $active_main_tab = sanitize_key($_GET['tab']);
        $active_sub_tab = isset($_GET['sub-tab']) ? sanitize_key($_GET['sub-tab']) : null;
		// phpcs:enable
    } else {
        // Si no, es una navegación desde el menú de la izquierda.
        // Mapeamos el slug de la página a la pestaña correcta.
        $page_slug_to_tab_map = [
            'advaipbl_settings_page'           => ['dashboard', 'main_dashboard'],
            'advaipbl_settings_page-settings'  => ['settings', 'general_settings'],
            'advaipbl_settings_page-security-headers' => ['security_headers', 'headers_config'],
            'advaipbl_settings_page-rules'     => ['rules', 'waf'],
            'advaipbl_settings_page-ip-management' => ['ip_management', 'blocked_ips'],
			'advaipbl_settings_page-scanner'   => ['scanner', 'scan_overview'],
            'advaipbl_settings_page-logs'      => ['logs', 'security_log'],
            'advaipbl_settings_page-about'     => ['about', 'credits'],
        ];

        if (isset($page_slug_to_tab_map[$current_page_slug])) {
            list($active_main_tab, $active_sub_tab) = $page_slug_to_tab_map[$current_page_slug];
        } else {
            // Fallback por si acaso
            $active_main_tab = 'dashboard';
            $active_sub_tab = 'main_dashboard';
        }
    }

    // Validación final para asegurarse de que las pestañas existen
    if (!isset($menu_structure[$active_main_tab])) {
        $active_main_tab = 'dashboard';
    }
    if (empty($active_sub_tab) || !isset($menu_structure[$active_main_tab]['sub_tabs'][$active_sub_tab])) {
        // Asigna la primera sub-pestaña de la pestaña principal activa
        $active_sub_tab = key($menu_structure[$active_main_tab]['sub_tabs']);
    }
    
    $blocked_count = $this->plugin->get_blocked_count();
    ?>
    <div class="wrap advaipbl-wrap">

        <div class="advaipbl-header">
            <div class="advaipbl-header-logo">
                <img src="<?php echo esc_url(plugin_dir_url(dirname(__FILE__)) . 'assets/img/logo-ligth.png'); ?>" alt="Advanced IP Blocker Logo">
            </div>
        </div>

        <h1></h1>

        <div id="advaipbl-notices-container">
            <?php
            settings_errors(); 
            $this->plugin->display_admin_notice();
            ?>
        </div>
        
        <div class="advaipbl-main-nav-wrapper">
            <h2 class="nav-tab-wrapper">
                <?php foreach ($menu_structure as $main_tab_key => $main_tab_data) :
                    $is_active = ($main_tab_key === $active_main_tab);
                    $first_sub_tab = key($main_tab_data['sub_tabs']);
                    // La URL para los enlaces de las pestañas SÍ debe construirse con add_query_arg
                    $url = add_query_arg(
                        [
                            'page' => 'advaipbl_settings_page',
                            'tab' => $main_tab_key,
                            'sub-tab' => $first_sub_tab
                        ],
                        'admin.php'
                    );
                    ?>
                    <a href="<?php echo esc_url($url); ?>" class="nav-tab <?php if ($is_active) echo 'nav-tab-active'; ?>">
                        <span class="dashicons <?php echo esc_attr($main_tab_data['icon']); ?>"></span>
                        <?php echo esc_html($main_tab_data['title']); ?>
                        <?php if ($main_tab_key === 'ip_management' && $blocked_count > 0) : ?>
                            <span class="advaipbl-block-count"><?php echo esc_html(number_format_i18n($blocked_count)); ?></span>
                        <?php endif; ?>
                    </a>
                <?php endforeach; ?>
            </h2>
        </div>
        
        <div class="advaipbl-sub-nav-wrapper">
            <?php foreach ($menu_structure[$active_main_tab]['sub_tabs'] as $sub_tab_key => $sub_tab_title) :
                $is_active = ($sub_tab_key === $active_sub_tab);
                $url = add_query_arg(
                    [
                        'page' => 'advaipbl_settings_page',
                        'tab' => $active_main_tab,
                        'sub-tab' => $sub_tab_key
                    ],
                    'admin.php'
                );
                ?>
                <a href="<?php echo esc_url($url); ?>" class="advaipbl-sub-nav-item <?php if ($is_active) echo 'active'; ?>">
                    <?php echo esc_html($sub_tab_title); ?>
                </a>
            <?php endforeach; ?>
        </div>

        <div class="advaipbl-tab-content">
        <?php
                switch ($active_sub_tab) {
        case 'main_dashboard': $this->display_dashboard_tab(); break;
        case 'status': $this->display_status_tab(); break;
        case 'headers_config': $this->plugin->security_headers_manager->display_settings_tab(); break;
        case 'general_settings': $this->display_general_settings_tab(); break;
		case '2fa_management': $this->display_2fa_management_tab(); break;
        case 'import_export': $this->render_import_export_controls_callback(); break;
        case 'waf': $this->display_waf_tab(); break;
        case 'user_agents': $this->display_user_agents_tab(); break;
        case 'honeypot': $this->display_honeypot_tab(); break;
        case 'asn_blocking': $this->display_asn_blocking_tab(); break;
		case 'advanced_rules': $this->display_advanced_rules_tab(); break;
        case 'blocked_ips': $this->display_blocked_ips_tab(); break;
        case 'blocked_signatures': $this->display_blocked_signatures_tab(); break;
		case 'blocked_endpoints': $this->display_blocked_endpoints_tab(); break;
		case 'whitelist': $this->display_whitelist_tab(); break;
		case 'scan_overview': $this->display_scanner_tab(); break;
        case 'security_log': $this->display_security_log_tab(); break;
        case 'audit_log': $this->display_audit_log_tab(); break;
        case 'general_log': $this->display_general_log_tab(); break;
		case 'ip_trust_log': $this->display_ip_trust_log_tab(); break;
        case 'user_sessions': $this->plugin->session_manager->display_admin_page(); break;
        case 'cron_logs': $this->display_cron_logs_tab(); break;
        case 'credits': $this->display_credits_tab(); break;		
        default: echo '<p>Error: Content for this tab is not available.</p>'; break;
    }
        ?>
        </div>

    </div>
    <?php
}
    /**
 * Muestra la tabla de logs específica para las ejecuciones de WP-Cron.
 * Esto es principalmente una herramienta de diagnóstico.
 */
    public function display_cron_logs_tab() {
        echo '<div class="notice notice-info inline"><p>';
        esc_html_e( 'This log shows which IP addresses are triggering WP-Cron tasks on your site, and which scheduled tasks (hooks) were due to run at that moment.', 'advanced-ip-blocker' );
        echo '</p></div>';

        // phpcs:disable WordPress.Security.NonceVerification.Recommended
        $search_term = isset($_GET['s']) ? sanitize_text_field(wp_unslash($_GET['s'])) : '';
        $orderby = isset($_GET['orderby']) && in_array($_GET['orderby'], ['timestamp', 'ip'], true) ? sanitize_key($_GET['orderby']) : 'timestamp';
        $order = isset($_GET['order']) && in_array(strtolower($_GET['order']), ['asc', 'desc'], true) ? strtolower(sanitize_key($_GET['order'])) : 'desc';
        $current_page = isset($_GET['paged']) ? absint($_GET['paged']) : 1;
        $per_page = isset($_GET['advaipbl_per_page']) ? absint($_GET['advaipbl_per_page']) : 25;
        // phpcs:enable

        global $wpdb;
        $table_name = $wpdb->prefix . 'advaipbl_logs';
        
        $where_clauses = [$wpdb->prepare("log_type = %s", 'wp_cron')]; 
        if (!empty($search_term)) {
            $search_like = '%' . $wpdb->esc_like($search_term) . '%';
            $where_clauses[] = $wpdb->prepare("(ip LIKE %s OR details LIKE %s)", $search_like, $search_like);
        }
        $where_sql = implode(' AND ', $where_clauses);
        
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $total_items = $wpdb->get_var("SELECT COUNT(log_id) FROM $table_name WHERE $where_sql");
        $total_pages = ceil($total_items / $per_page);
        $offset = ($current_page - 1) * $per_page;
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $logs = $wpdb->get_results($wpdb->prepare("SELECT * FROM $table_name WHERE $where_sql ORDER BY " . esc_sql($orderby) . " " . esc_sql($order) . " LIMIT %d OFFSET %d", $per_page, $offset), ARRAY_A);
        ?>
        
        <div class="tablenav top">
            <div class="alignleft actions bulkactions">
                <form method="get">
                    <input type="hidden" name="page" value="advaipbl_settings_page">
                    <input type="hidden" name="tab" value="logs">
                    <input type="hidden" name="sub-tab" value="cron_logs">
                    <?php $this->plugin->render_per_page_selector( $per_page ); ?>
                    <input type="search" name="s" value="<?php echo esc_attr($search_term); ?>" placeholder="<?php esc_attr_e( 'Search by IP or User Agent...', 'advanced-ip-blocker' ); ?>">
                    <input type="submit" class="button" value="<?php esc_attr_e( 'Search Logs', 'advanced-ip-blocker' ); ?>">
                </form>
            </div>

            <div class="alignleft actions">
                <form method="post" action="">
                    <input type="hidden" name="action_type" value="clear_specific_logs">
                    <input type="hidden" name="log_types_to_clear[]" value="wp_cron">
                    <?php wp_nonce_field('advaipbl_admin_nonce_action','advaipbl_admin_nonce_action'); ?>
                    <button type="submit" class="button button-danger advaipbl-confirm-action"
                            data-confirm-title="<?php esc_attr_e( 'Confirm Log Deletion', 'advanced-ip-blocker' ); ?>"
                            data-confirm-message="<?php esc_attr_e( 'Are you sure you want to delete all WP-Cron logs?', 'advanced-ip-blocker' ); ?>"
                            data-confirm-button="<?php esc_attr_e( 'Yes, Delete Logs', 'advanced-ip-blocker' ); ?>">
                        <?php esc_html_e('Clear this Log', 'advanced-ip-blocker'); ?>
                    </button>
                </form>
            </div>

            <div class="tablenav-pages">

                <span class="displaying-num"><?php /* translators: %s: Number of items. */ printf(esc_html(_n('%s item', '%s items', $total_items, 'advanced-ip-blocker')), esc_html(number_format_i18n($total_items))); ?></span>
                <?php 
                $page_links = paginate_links([
                    'base' => add_query_arg([
                        'paged' => '%#%',
                        's' => $search_term,
                        'advaipbl_per_page' => $per_page,
                    ]),
                    'format' => '',
                    'total' => $total_pages,
                    'current' => $current_page
                ]);
                if ($page_links) echo wp_kses_post($page_links); 
                ?>
            </div>
            <br class="clear">
        </div>

        <div class="advaipbl-table-responsive-wrapper">
        <table class="widefat fixed striped" style="margin-top:1em;">
            <thead>
                <tr>
                    <?php $this->plugin->print_log_sortable_header(__('Date/Time', 'advanced-ip-blocker'), 'timestamp', $orderby, $order); ?>
                    <?php $this->plugin->print_log_sortable_header(__('IP Address', 'advanced-ip-blocker'), 'ip', $orderby, $order); ?>
                    <th><?php esc_html_e('Source', 'advanced-ip-blocker'); ?></th>
                    <th><?php esc_html_e('Triggering URI', 'advanced-ip-blocker'); ?></th>
                    <th style="width: 25%;"><?php esc_html_e('Due Hooks', 'advanced-ip-blocker'); ?></th>
                    <th style="width: 25%;"><?php esc_html_e('User Agent', 'advanced-ip-blocker'); ?></th>
                </tr>
            </thead>
            <tbody>
                <?php if(empty($logs)) : ?>
                    <tr><td colspan="6"><?php echo empty($search_term) ? esc_html__('The WP-Cron log is empty.', 'advanced-ip-blocker') : esc_html__('No results found for your search.', 'advanced-ip-blocker'); ?></td></tr>
                <?php else: foreach($logs as $log) :
                    $details = json_decode($log['details'], true) ?: [];
                    $source = $details['source'] ?? 'Unknown';
                    ?>
                    <tr>
                        <td><?php echo esc_html(ADVAIPBL_Main::get_formatted_datetime($log['timestamp'])); ?></td>
                        <td><?php echo esc_html($log['ip']); ?></td>
                        <td>
                            <?php if ($source === 'Server'): ?>
                                <span style="color: #0073aa; font-weight: bold;"><?php esc_html_e('Server', 'advanced-ip-blocker'); ?></span>
                            <?php else: ?>
                                <span style="color: #d63638;"><?php esc_html_e('External', 'advanced-ip-blocker'); ?></span>
                            <?php endif; ?>
                        </td>
                        <td style="word-break: break-all;"><?php echo esc_html($details['url'] ?? 'N/A'); ?></td>
                        <td style="font-size: 11px; line-height: 1.4;">
                            <?php
                            if ( ! empty( $details['due_hooks'] ) && is_array( $details['due_hooks'] ) ) {
                                echo '<ul style="margin: 0; padding-left: 15px;">';
                                foreach ( $details['due_hooks'] as $hook ) {
                                    echo '<li><code>' . esc_html( $hook ) . '</code></li>';
                                }
                                echo '</ul>';
                            } else {
                                echo '–';
                            }
                            ?>
                        </td>
                        <td style="word-break: break-all; font-family: monospace; font-size: 12px;"><?php echo esc_html($details['user_agent'] ?? 'N/A'); ?></td>
                    </tr>
                <?php endforeach; endif; ?>
            </tbody>
        </table>
		</div>
        <?php
    }
	/**
 * Muestra la pestaña para gestionar el bloqueo por ASN, ahora con estados separados.
 */
public function display_asn_blocking_tab() {
    $provider = $this->plugin->options['geolocation_provider'] ?? '';
    $is_compatible = in_array($provider, ['ip-api.com', 'ipinfo.io'], true);
    
    $is_spamhaus_enabled = !empty($this->plugin->options['enable_spamhaus_asn']);
    $is_manual_enabled = !empty($this->plugin->options['enable_manual_asn']);

    $settings_url = admin_url('admin.php?page=advaipbl_settings_page-settings');
    $spamhaus_stats = $this->plugin->dashboard_manager->get_spamhaus_stats();
    ?>
    <h2><?php esc_html_e('ASN Blocking', 'advanced-ip-blocker'); ?></h2>

    <?php if (!$is_compatible): ?>
        <div class="notice notice-warning inline">
            <p>
                <?php printf(
                    wp_kses(
                        /* translators: 1: Geolocation provider name, 2: Link to settings page */
                        __('<strong>Warning:</strong> Your current geolocation provider (<strong>%1$s</strong>) does not support ASN lookups. This feature is fully supported by <strong>ip-api.com</strong> and <strong>ipinfo.io</strong>. Please <a href="%2$s">change your provider</a> to use ASN blocking.', 'advanced-ip-blocker'),
                        ['strong' => [], 'a' => ['href' => []]]
                    ),
                    esc_html($provider),
                    esc_url($settings_url)
                ); ?>
            </p>
        </div>
    <?php endif; ?>

    <form method="post" action="">
        <input type="hidden" name="action_type" value="save_asn_lists">
        <?php wp_nonce_field('advaipbl_admin_nonce_action', 'advaipbl_admin_nonce_action'); ?>

        <div class="advaipbl-dashboard-row">
            <!-- Columna 1: Automated Protection (Spamhaus) -->
            <div class="advaipbl-dashboard-widget widget-third">
                <h3><?php esc_html_e('Spamhaus Protection Status', 'advanced-ip-blocker'); ?></h3>
                
                <div class="advaipbl-status-widget">
                    <span class="dashicons <?php echo $is_spamhaus_enabled ? 'dashicons-yes-alt advaipbl-status-icon-success' : 'dashicons-no-alt advaipbl-status-icon-disabled'; ?>"></span>
                    <div class="advaipbl-status-text">
                        <strong><?php echo $is_spamhaus_enabled ? esc_html__('PROTECTION ACTIVE', 'advanced-ip-blocker') : esc_html__('PROTECTION DISABLED', 'advanced-ip-blocker'); ?></strong><br>
                        <small><?php /* translators: %s: The number of malicious networks being blocked. */ printf(esc_html__('Blocking %s malicious networks.', 'advanced-ip-blocker'), esc_html(number_format_i18n($spamhaus_stats['list_count']))); ?></small>
                    </div>
                </div>
                
                <hr style="margin: 20px 0;">

                <h4><?php esc_html_e('Activity (Last 7 Days)', 'advanced-ip-blocker'); ?></h4>
                <p style="margin: 5px 0;">
                    <?php esc_html_e('Total IPs Blocked by this list:', 'advanced-ip-blocker'); ?>
                    <strong style="float: right;"><?php echo esc_html(number_format_i18n($spamhaus_stats['blocked_count'])); ?></strong>
                </p>
                
                <div style="margin-top: auto; padding-top: 20px; font-size: 11px; color: #666; text-align: right;">
                    <?php 
                    $last_update = get_option('advaipbl_spamhaus_last_update');
                    if ($last_update) { /* translators: %s: hours. */
                        printf(esc_html__('List updated %s ago.', 'advanced-ip-blocker'), esc_html(human_time_diff($last_update)));
                    } else {
                        esc_html_e('The list has not been updated yet.', 'advanced-ip-blocker');
                    }
                    $refresh_url = wp_nonce_url(admin_url('admin-post.php?action=advaipbl_refresh_spamhaus'), 'advaipbl-refresh-spamhaus');
                    ?>
                    <a href="<?php echo esc_url($refresh_url); ?>" class="button button-secondary button-small" style="margin-left: 10px;"><?php esc_html_e('Refresh Now', 'advanced-ip-blocker'); ?></a>
                </div>
            </div>

            <!-- Columna 2: Manual Lists (Block & Whitelist) -->
            <div class="advaipbl-dashboard-widget widget-two-thirds">
                <!-- Manual Blocklist -->
                <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #eee; padding-bottom: 15px; margin-bottom: 1em;">
                    <h3 style="margin: 0; padding: 0; border: none;"><?php esc_html_e('Manual ASN Blocklist', 'advanced-ip-blocker'); ?></h3>
                    <span class="advaipbl-status-tag <?php echo $is_manual_enabled ? 'enabled' : 'disabled'; ?>">
                        <?php echo $is_manual_enabled ? esc_html__('Enabled', 'advanced-ip-blocker') : esc_html__('Disabled', 'advanced-ip-blocker'); ?>
                    </span>
                </div>
                <p><?php esc_html_e('Add one ASN per line (e.g., AS200373) to block it. The check is case-insensitive.', 'advanced-ip-blocker'); ?></p>
                <textarea name="blocked_asns" rows="10" class="large-text code" style="width: 100%;" <?php disabled(!$is_compatible); ?>><?php echo esc_textarea(implode("\n", get_option(ADVAIPBL_Main::OPTION_BLOCKED_ASNS, []))); ?></textarea>
                
                <hr style="margin: 2em 0;">

                <!-- Columna 3: Whitelist ASN -->
                <h3 style="margin-bottom: 1em;"><?php esc_html_e('ASN Whitelist', 'advanced-ip-blocker'); ?></h3>
                <p><?php esc_html_e('Add one ASN per line to always allow traffic from that network. This will override ALL other blocking rules, including the WAF and Signature Engine.', 'advanced-ip-blocker'); ?></p>
                <p class="description"><?php esc_html_e('Useful for trusted services like Google (AS15169) or Cloudflare (AS13335) to prevent false positives.', 'advanced-ip-blocker'); ?></p>
                <textarea name="whitelisted_asns" rows="10" class="large-text code" style="width: 100%;" <?php disabled(!$is_compatible); ?>><?php echo esc_textarea(implode("\n", get_option(ADVAIPBL_Main::OPTION_WHITELISTED_ASNS, []))); ?></textarea>

            </div>
        </div> 
        <?php submit_button(__('Save ASN Lists', 'advanced-ip-blocker')); ?>
    </form>
    <?php
}
/**
     * Muestra la tabla de Firmas de Ataque actualmente bloqueadas.
     */
        public function display_blocked_signatures_tab() {
        global $wpdb;
        $table_name = $wpdb->prefix . 'advaipbl_malicious_signatures';
		
		$is_enabled = !empty($this->plugin->options['enable_signature_blocking']);
        $settings_url = admin_url('admin.php?page=advaipbl_settings_page-settings&sub-tab=general_settings#section-signature_engine');
        ?>
        <div class="notice notice-info inline">
            <p>
                <?php
                $status_tag = sprintf(
                    '<span class="advaipbl-status-tag %s">%s</span>',
                    $is_enabled ? 'enabled' : 'disabled',
                    $is_enabled ? esc_html__('Active', 'advanced-ip-blocker') : esc_html__('Inactive', 'advanced-ip-blocker')
                );
                printf(
                    wp_kses(
                        /* translators: 1: Status (Enabled/Disabled), 2: Link to settings page. */
                        __('The Attack Signature Blocking system is currently %1$s. You can change this in the <a href="%2$s">Settings</a>.', 'advanced-ip-blocker'),
                        [ 'span' => ['class' => true], 'a' => ['href' => []] ]
                    ),
					// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
                    $status_tag,
                    esc_url($settings_url)
                );
                ?>
            </p>
        </div>
        <?php        
        
        // phpcs:disable WordPress.Security.NonceVerification.Recommended
        $orderby = isset($_GET['orderby']) && in_array($_GET['orderby'], ['signature_hash', 'reason', 'last_seen', 'expires_at'], true) ? sanitize_key($_GET['orderby']) : 'last_seen';
        $order = isset($_GET['order']) && in_array(strtolower($_GET['order']), ['asc', 'desc'], true) ? strtolower(sanitize_key($_GET['order'])) : 'desc';
        $current_page = isset($_GET['paged']) ? absint($_GET['paged']) : 1;
        $per_page = isset($_GET['advaipbl_per_page']) ? absint($_GET['advaipbl_per_page']) : 20;
        // phpcs:enable

        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $total_items = $wpdb->get_var("SELECT COUNT(id) FROM {$table_name}");
        $total_pages = ceil($total_items / $per_page);
        $offset = ($current_page - 1) * $per_page;

        $query = "SELECT * FROM {$table_name} ORDER BY " . esc_sql($orderby) . " " . esc_sql($order) . " LIMIT %d OFFSET %d";
        // phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $items = $wpdb->get_results($wpdb->prepare($query, $per_page, $offset), ARRAY_A);
        // phpcs:enable
        ?>

        <h2><?php esc_html_e('Blocked Attack Signatures', 'advanced-ip-blocker'); ?></h2>
        <p><?php esc_html_e('This table lists all attack "fingerprints" that are currently being challenged by the JavaScript verifier. These rules are generated automatically by the Signature Analysis engine and expire on their own.', 'advanced-ip-blocker'); ?></p>
		
        <div class="tablenav top">
            <div class="alignleft actions bulkactions">
                <form method="get" style="display:inline-block;">
                    <input type="hidden" name="page" value="advaipbl_settings_page">
                    <input type="hidden" name="tab" value="ip_management">
                    <input type="hidden" name="sub-tab" value="blocked_signatures">
                    <?php $this->plugin->render_per_page_selector($per_page); ?>
                </form>
            </div>           
            <div class="alignleft actions">
                <form method="post" action="">
                    <input type="hidden" name="action_type" value="clear_all_signatures">
                    <?php wp_nonce_field('advaipbl_admin_nonce_action', 'advaipbl_admin_nonce_action'); ?>
                    <button type="submit" class="button button-danger advaipbl-confirm-action"
                            data-confirm-title="<?php esc_attr_e('Confirm Signature Deletion', 'advanced-ip-blocker'); ?>"
                            data-confirm-message="<?php esc_attr_e('Are you sure you want to delete all active attack signatures? This action cannot be undone.', 'advanced-ip-blocker'); ?>"
                            data-confirm-button="<?php esc_attr_e('Yes, Delete All Signatures', 'advanced-ip-blocker'); ?>">
                        <?php esc_html_e('Delete All Signatures', 'advanced-ip-blocker'); ?>
                    </button>
                </form>
            </div>           
            <div class="tablenav-pages">
                <span class="displaying-num"><?php /* translators: %s: The number of items per page. */ printf(esc_html(_n('%s item', '%s items', $total_items, 'advanced-ip-blocker')), esc_html(number_format_i18n($total_items))); ?></span>
                <?php $page_links = paginate_links(['base' => add_query_arg('paged', '%#%'), 'format' => '', 'total' => $total_pages, 'current' => $current_page]); if ($page_links) echo wp_kses_post($page_links); ?>
            </div>
            <br class="clear">
        </div>
        
		<div class="advaipbl-table-responsive-wrapper">
        <table class="wp-list-table widefat fixed striped">
            <thead>
                <tr>
                    <?php $this->plugin->print_log_sortable_header(__('Signature Hash', 'advanced-ip-blocker'), 'signature_hash', $orderby, $order); ?>
                    <?php $this->plugin->print_log_sortable_header(__('Reason', 'advanced-ip-blocker'), 'reason', $orderby, $order); ?>
                    <?php $this->plugin->print_log_sortable_header(__('Last Seen', 'advanced-ip-blocker'), 'last_seen', $orderby, $order); ?>
                    <?php $this->plugin->print_log_sortable_header(__('Expires In', 'advanced-ip-blocker'), 'expires_at', $orderby, $order); ?>
                    <th><?php esc_html_e('Actions', 'advanced-ip-blocker'); ?></th>
                </tr>
            </thead>
            <tbody>
                <?php if (empty($items)) : ?>
                    <tr class="no-items"><td class="colspanchange" colspan="5"><?php esc_html_e('No malicious signatures are currently active.', 'advanced-ip-blocker'); ?></td></tr>
                <?php else: foreach ($items as $item) : ?>
                    <tr data-hash="<?php echo esc_attr($item['signature_hash']); ?>">
                        <td class="code">
                            <span title="<?php echo esc_attr($item['signature_hash']); ?>">
                                <?php echo esc_html(substr($item['signature_hash'], 0, 12) . '...'); ?>
                            </span>
							<button class="button button-small advaipbl-copy-hash" data-hash="<?php echo esc_attr($item['signature_hash']); ?>" title="<?php esc_attr_e('Copy full hash', 'advanced-ip-blocker'); ?>"><?php esc_html_e('Copy', 'advanced-ip-blocker'); ?></button>
                            <br>
                            <button class="button button-small advaipbl-view-signature-details"><?php esc_html_e('View Details', 'advanced-ip-blocker'); ?></button>
                        </td>
                        <td><?php echo esc_html($item['reason']); ?></td>
                        <td><?php echo esc_html(human_time_diff($item['last_seen'])) . ' ' . esc_html__('ago', 'advanced-ip-blocker'); ?></td>
                        <td><?php echo esc_html(human_time_diff($item['expires_at'])) . ' ' . esc_html__('from now', 'advanced-ip-blocker'); ?></td>
                        <td>
                            <button class="button button-secondary advaipbl-whitelist-signature" title="<?php esc_attr_e('Add to Whitelist', 'advanced-ip-blocker'); ?>">
                                <?php esc_html_e('Whitelist', 'advanced-ip-blocker'); ?>
                            </button>
                            <button class="button button-link-delete advaipbl-delete-signature">
                                <?php esc_html_e('Delete', 'advanced-ip-blocker'); ?>
                            </button>
                        </td>
                    </tr>
                <?php endforeach; endif; ?>
            </tbody>
        </table>
		</div>
		
        <div id="advaipbl-signature-details-modal" class="advaipbl-modal-overlay" style="display: none;">
            <div class="advaipbl-modal-content" style="max-width: 800px;">
                <h3 class="advaipbl-modal-title"><?php esc_html_e('Signature Details:', 'advanced-ip-blocker'); ?> <code class="modal-hash-placeholder"></code></h3>
                <div class="advaipbl-modal-body">
                    <div class="advaipbl-loader-wrapper" style="text-align: center; padding: 20px;">
                        <div class="advaipbl-loader"></div>
                    </div>
                    <div class="details-content" style="display: none;"></div>
                </div>
                <div class="advaipbl-modal-footer">
                    <button class="button advaipbl-modal-cancel"><?php esc_html_e( 'Close', 'advanced-ip-blocker' ); ?></button>
                </div>
            </div>
        </div>
        <?php
    }
	/**
     * Muestra la tabla de Endpoints actualmente bajo Lockdown.
     */
    public function display_blocked_endpoints_tab() {
        global $wpdb;
        $table_name = $wpdb->prefix . 'advaipbl_endpoint_lockdowns';
        // Array para definir los endpoints que soportan lockdown
        $lockdown_endpoints = [
            'xmlrpc' => [
                'name' => 'XML-RPC',
                'option' => 'enable_xmlrpc_lockdown',
                'anchor' => '#sub-section-xmlrpc-lockdown'
            ],
            'login' => [
                'name' => 'Login Page (wp-login.php)',
                'option' => 'enable_login_lockdown',
                'anchor' => '#sub-section-login-lockdown'
            ],
            '404' => [
                'name' => '404 Errors',
                'option' => 'enable_404_lockdown',
                'anchor' => '#section-blocking_rules'
            ],
            '403' => [
                'name' => '403 Errors',
                'option' => 'enable_403_lockdown',
                'anchor' => '#section-blocking_rules'
            ],
        ];

        $settings_base_url = admin_url('admin.php?page=advaipbl_settings_page-settings&sub-tab=general_settings');
        $status_parts = [];

        foreach ($lockdown_endpoints as $key => $details) {
            $is_enabled = !empty($this->plugin->options[$details['option']]);
            $status_tag = sprintf(
                '<span class="advaipbl-status-tag %s">%s</span>',
                $is_enabled ? 'enabled' : 'disabled',
                $is_enabled ? esc_html__('Active', 'advanced-ip-blocker') : esc_html__('Inactive', 'advanced-ip-blocker')
            );
            $settings_link = sprintf(
                '<a href="%s">%s</a>',
                esc_url($settings_base_url . $details['anchor']),
                esc_html__('Configure', 'advanced-ip-blocker')
            );
            /* translators: 1: Endpoint name (e.g., XML-RPC), 2: Status tag (Active/Inactive), 3: Link to configure */
            $status_parts[] = sprintf('<strong>%1$s:</strong> %2$s (%3$s)', esc_html($details['name']), $status_tag, $settings_link);
        }
        ?>
        <div class="notice notice-info inline">
            <p><?php echo wp_kses(implode(' &nbsp;|&nbsp; ', $status_parts), [
                'strong' => [],
                'span'   => ['class' => true],
                'a'      => ['href' => true],
            ]); ?></p>
        </div>
        <?php
        // Primero, limpiamos los lockdowns expirados.
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $wpdb->query($wpdb->prepare("DELETE FROM {$table_name} WHERE expires_at <= %d", time()));
        
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $items = $wpdb->get_results("SELECT * FROM {$table_name} ORDER BY created_at DESC", ARRAY_A);
        ?>
        <h2><?php esc_html_e('Active Endpoint Lockdowns', 'advanced-ip-blocker'); ?></h2>
        <p><?php esc_html_e('This table lists all site endpoints that are currently in "Lockdown Mode" due to a sustained attack. You can manually cancel a lockdown here if needed.', 'advanced-ip-blocker'); ?></p>
        
        <div class="advaipbl-table-responsive-wrapper">
        <table class="wp-list-table widefat fixed striped">
            <thead>
                <tr>
                    <th><?php esc_html_e('Endpoint', 'advanced-ip-blocker'); ?></th>
                    <th><?php esc_html_e('Reason for Lockdown', 'advanced-ip-blocker'); ?></th>
                    <th><?php esc_html_e('Activated', 'advanced-ip-blocker'); ?></th>
                    <th><?php esc_html_e('Expires In', 'advanced-ip-blocker'); ?></th>
                    <th><?php esc_html_e('Actions', 'advanced-ip-blocker'); ?></th>
                </tr>
            </thead>
            <tbody>
                <?php if (empty($items)) : ?>
                    <tr class="no-items"><td class="colspanchange" colspan="5"><?php esc_html_e('No endpoints are currently in lockdown mode.', 'advanced-ip-blocker'); ?></td></tr>
                <?php else: foreach ($items as $item) : ?>
                    <tr data-lockdown-id="<?php echo esc_attr($item['id']); ?>">
                        <td>
                            <strong><code><?php echo esc_html(strtoupper($item['endpoint_key'])); ?></code></strong>
                            <br>
                            <button class="button button-small advaipbl-view-lockdown-details"><?php esc_html_e('View Details', 'advanced-ip-blocker'); ?></button>
                        </td>
                        <td><?php echo esc_html($item['reason']); ?></td>
                        <td><?php echo esc_html(ADVAIPBL_Main::get_formatted_datetime($item['created_at'])); ?></td>
                        <td><?php echo esc_html(human_time_diff($item['expires_at'])) . ' ' . esc_html__('from now', 'advanced-ip-blocker'); ?></td>
                        <td>
                            <?php
                            $delete_nonce_url = wp_nonce_url(
                                add_query_arg([
                                    'action' => 'advaipbl_delete_lockdown',
                                    'lockdown_id' => $item['id']
                                ]),
                                'advaipbl_delete_lockdown_' . $item['id']
                            );
                            ?>
                            <a href="<?php echo esc_url($delete_nonce_url); ?>" class="button button-link-delete advaipbl-delete-lockdown">
                                <?php esc_html_e('Cancel Lockdown', 'advanced-ip-blocker'); ?>
                            </a>
                        </td>
                    </tr>
                <?php endforeach; endif; ?>
            </tbody>
        </table>
        </div>
        </div>
        
        <div id="advaipbl-lockdown-details-modal" class="advaipbl-modal-overlay" style="display: none;">
            <div class="advaipbl-modal-content" style="max-width: 800px;">
                <h3 class="advaipbl-modal-title"><?php esc_html_e('Lockdown Details', 'advanced-ip-blocker'); ?></h3>
                <div class="advaipbl-modal-body">
                    <div class="advaipbl-loader-wrapper" style="text-align: center; padding: 20px;">
                        <div class="advaipbl-loader"></div>
                    </div>
                    <div class="details-content" style="display: none;"></div>
                </div>
                <div class="advaipbl-modal-footer">
                    <button class="button advaipbl-modal-cancel"><?php esc_html_e( 'Close', 'advanced-ip-blocker' ); ?></button>
                </div>
            </div>
        </div>
        <?php
    }
	/**
 * Muestra la pestaña de configuración del Firewall (WAF).
 */
public function display_waf_tab() {
    $is_enabled = !empty($this->plugin->options['enable_waf']);
    $settings_url = admin_url('admin.php?page=advaipbl_settings_page-settings&sub-tab=general_settings#sub-section-waf');
    ?>
    <div class="notice notice-info inline">
        <p>
            <?php 
            // Creamos la etiqueta de estado con las clases correctas.
            $status_tag = sprintf(
                '<span class="advaipbl-status-tag %s">%s</span>',
                $is_enabled ? 'enabled' : 'disabled',
                $is_enabled ? esc_html__('Active', 'advanced-ip-blocker') : esc_html__('Inactive', 'advanced-ip-blocker')
            );

            printf(
                wp_kses( 
                    /* translators: 1: Status tag (Active/Inactive), 2: Link to settings page. */
                    __('Web Application Firewall (WAF) is currently %1$s. You can change this in the <a href="%2$s">Settings</a>.', 'advanced-ip-blocker'),
                    [
                        'span' => ['class' => true], 
                        'a'    => ['href' => []]
                    ]
                ),
				// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
                $status_tag,
                esc_url($settings_url)
            );
            ?>
        </p>
    </div>
    <?php
// Conjunto de reglas WAF recomendadas para que el usuario las copie.
$default_waf_rules_list = [
            '# === SQL Injection (SQLi) ===',
            '# Blocks common SQL injection patterns.',
            'union\s+select',
            'information_schema\.',
            '--\s*$',
            '(?:--|#|\/\*)\s*(select|insert|update|delete|union)',
            '',
            '# === Cross-Site Scripting (XSS) ===',
            '# Blocks attempts to inject malicious scripts.',
            '<\s*script',
            'on(error|load|click|mouseover)\s*=',
            'javascript:',
            'data:text/html',
            '',
            '# === Path Traversal & File Inclusion (LFI/RFI) ===',
            '# Prevents access to local files or inclusion of remote files.',
            '\.\.\/',
            '\.\.\\\\',
            '/etc/passwd',
            'php://(input|filter)',
            '',
            '# === Command Injection & RCE ===',
            '# Blocks attempts to execute system commands on the server.',
            '(passthru|shell_exec|system|exec|popen)\s*\(',
            'base64_decode\s*\(',
            '(wget|curl)\s+http',
            '',
            '# === WordPress-Specific Probes & Attacks ===',
            '# Blocks scanning for sensitive files and common exploits.',
            '/(wlwmanifest\.xml|wp-config\.php|\.env|\.git/config)',
            '/?author=\d+',
        ];
    $default_waf_rules_text = implode("\n", $default_waf_rules_list);
    ?>

    <h2><?php esc_html_e('Web Application Firewall (WAF)', 'advanced-ip-blocker'); ?></h2>
    <p><?php esc_html_e('The WAF scans incoming requests for malicious patterns. If a pattern is found, the visitor\'s IP is instantly blocked.', 'advanced-ip-blocker'); ?></p>
    <div class="notice notice-error inline" style="margin-top: 15px;">
    <p>
        <strong><?php esc_html_e('WARNING:', 'advanced-ip-blocker'); ?></strong>
        <?php esc_html_e('Incorrectly configured rules can lock you out of your site or break functionality. A rule that is too broad (e.g., `/` or `a`) can block all traffic. Always test new rules carefully from a different browser or device.', 'advanced-ip-blocker'); ?>
    </p>
    </div>
    <form method="post" action="options.php">
        <?php settings_fields('advaipbl_waf_rules_group'); ?>
        <div class="advaipbl-card">
            <h3><?php esc_html_e('Active Firewall Rules', 'advanced-ip-blocker'); ?></h3>
            <p><?php esc_html_e('Add one regular expression per line. The check is case-insensitive.', 'advanced-ip-blocker'); ?></p>
            <table class="form-table">
                <tr valign="top">
                    <th scope="row"><?php esc_html_e('WAF Rules', 'advanced-ip-blocker'); ?></th>
                    <td>
                        <textarea name="<?php echo esc_attr(ADVAIPBL_Main::OPTION_WAF_RULES); ?>" rows="15" class="large-text code"><?php echo esc_textarea(get_option(ADVAIPBL_Main::OPTION_WAF_RULES, '')); ?></textarea>
                    </td>
                </tr>
            </table>
        </div>
        <?php submit_button(__('Save WAF Rules', 'advanced-ip-blocker')); ?>
    </form>

    <hr>

    <div class="advaipbl-card">
        <h3><?php esc_html_e('Common WAF Rule Suggestions', 'advanced-ip-blocker'); ?></h3>
        <p><?php esc_html_e('You can copy and paste these rules into the active rules list above. It is recommended to test your site after adding new rules to ensure they do not interfere with your plugins or theme.', 'advanced-ip-blocker'); ?></p>
        <textarea rows="15" class="large-text code" readonly><?php echo esc_textarea($default_waf_rules_text); ?></textarea>
    </div>

    <?php
}
/**
 * Muestra el dashboard de seguridad con el layout y los estilos de alta especificidad.
 */
public function display_dashboard_tab() {
    ?>
    <div id="advaipbl-dashboard" class="advaipbl-dashboard-loading">
        <div class="advaipbl-loader-wrapper">
            <div class="advaipbl-loader"></div>
            <p><?php esc_html_e('Loading security data...', 'advanced-ip-blocker'); ?></p>
        </div>

        <div class="advaipbl-dashboard-content" style="display: none;">
            
            <!-- Fila 1: Tres columnas -->
            <div class="advaipbl-dashboard-row">
                <div class="advaipbl-dashboard-widget widget-third">
                    <h3><?php esc_html_e('Attack Summary (Last 7 Days)', 'advanced-ip-blocker'); ?></h3>
                    <div class="advaipbl-summary-stats">
                        <div class="advaipbl-summary-chart"><canvas id="advaipbl-attack-type-chart"></canvas></div>
                        <div id="advaipbl-summary-legend" class="advaipbl-summary-legend"></div>
                    </div>
                </div>
                <div class="advaipbl-dashboard-widget widget-third">
                    <h3><?php esc_html_e('Top Attacking IPs', 'advanced-ip-blocker'); ?></h3>
                    <div id="advaipbl-top-ips-list" class="advaipbl-top-list"></div>
                </div>
                <div class="advaipbl-dashboard-widget widget-third">
                    <h3><?php esc_html_e('Top Attacking Countries', 'advanced-ip-blocker'); ?></h3>
                    <div id="advaipbl-top-countries-list" class="advaipbl-top-list"></div>
                </div>
            </div>
            
			<!-- Fila 2: Dos columnas -->
            <div class="advaipbl-dashboard-row">
                <div class="advaipbl-dashboard-widget widget-third">
                    <h3><?php esc_html_e('System Status', 'advanced-ip-blocker'); ?></h3>
                    <div id="advaipbl-system-status-list"></div>
                    <div class="advaipbl-widget-footer">
                        <a href="<?php echo esc_url(admin_url('admin.php?page=advaipbl_settings_page-settings')); ?>"><?php esc_html_e('Manage Settings', 'advanced-ip-blocker'); ?> →</a>
                    </div>
                </div>
                <div class="advaipbl-dashboard-widget widget-two-thirds">
                    <h3><?php esc_html_e('Live Attack Map', 'advanced-ip-blocker'); ?></h3>
                    <div id="advaipbl-map-wrapper">
                        <div id="advaipbl-attack-map" style="height: 100%; width: 100%; min-height: 350px;"></div>
                    </div>
                </div>
            </div>
			
            <!-- Fila 3: Una columna -->
            <div class="advaipbl-dashboard-row">
                <div class="advaipbl-dashboard-widget widget-full">
                    <h3><?php esc_html_e('Threat Activity Timeline', 'advanced-ip-blocker'); ?></h3>
                    <div class="advaipbl-timeline-chart-container">
                        <canvas id="advaipbl-timeline-chart"></canvas>
                    </div>
                </div>
            </div>
            
        </div>
    </div>
    <?php
}
public function display_general_settings_tab() {
        $this->plugin->options = get_option(ADVAIPBL_Main::OPTION_SETTINGS);

        $sections = [
            'general' => __('General', 'advanced-ip-blocker'),
            'notifications' => __('Notifications', 'advanced-ip-blocker'),
            'htaccess' => __('Server Firewall (.htaccess)', 'advanced-ip-blocker'),
            'cloudflare' => __('Cloud Edge Defense', 'advanced-ip-blocker'),
            'ip_detection' => __('IP Detection', 'advanced-ip-blocker'),
            'geolocation' => __('Geolocation', 'advanced-ip-blocker'),
            'threat_intelligence' => __('Threat Intelligence', 'advanced-ip-blocker'),
            'protections' => __('Core Protections', 'advanced-ip-blocker'),
            'blocking_rules' => __('Threshold Blocking', 'advanced-ip-blocker'),
            'ip_trust' => __('IP Trust & Scoring', 'advanced-ip-blocker'),
            'login_protection' => __('Login Protection', 'advanced-ip-blocker'),
            'signature_engine' => __('Signature Engine', 'advanced-ip-blocker'),
            'internal_security' => __('Internal Security', 'advanced-ip-blocker'),
            'uninstall' => __('Uninstallation', 'advanced-ip-blocker'),
        ];
		// Obtener estadísticas de la lista comunitaria
                        $community_stats = $this->plugin->community_manager->get_stats();
                        $list_count = $community_stats['count'] ?? 0;
                        $last_update = $community_stats['last_update'] ?? 0;
        ?>
        <div class="advaipbl-settings-layout">
            <div class="advaipbl-settings-nav">
                <ul>
                    <?php foreach ($sections as $id => $title) : ?>
                        <li><a href="#section-<?php echo esc_attr($id); ?>"><?php echo esc_html($title); ?></a></li>
                    <?php endforeach; ?>
                </ul>
            </div>
    
            <div class="advaipbl-settings-content">
                <form method="post" action="options.php">
                    <?php settings_fields('advaipbl_settings_group'); ?>
                    
                    <div class="advaipbl-settings-search-wrapper">
                        <span class="dashicons dashicons-search"></span>
                        <input type="text" id="advaipbl-settings-search" placeholder="<?php esc_attr_e( 'Search settings (e.g., WAF, Geoblock, API Key)...', 'advanced-ip-blocker' ); ?>">
                    </div>     
                    
                    <div id="section-general" class="advaipbl-settings-section">
                        <div class="advaipbl-card">
                            <h2><?php esc_html_e('General Settings', 'advanced-ip-blocker'); ?></h2>
                            <table class="form-table">
                                <?php do_settings_fields('advaipbl_settings_page', 'advaipbl_general_settings_section'); ?>
                            </table>
                        </div>
                    </div>

                    <div id="section-notifications" class="advaipbl-settings-section">
                        <div class="advaipbl-card">
                            <h2><?php esc_html_e('Notifications', 'advanced-ip-blocker'); ?></h2>
                            <h3 style="margin-top: 20px;"><?php esc_html_e('Email Notifications', 'advanced-ip-blocker'); ?></h3>
                            <table class="form-table">
                                <?php do_settings_fields('advaipbl_settings_page', 'advaipbl_email_notifications_section'); ?>
                            </table>
                            <h3 style="margin-top: 20px;"><?php esc_html_e('Push Notifications (Webhooks)', 'advanced-ip-blocker'); ?></h3>
                            <p class="description"><?php esc_html_e('Send real-time alerts to services like Slack or Discord. Simply paste the webhook URL provided by the service.', 'advanced-ip-blocker'); ?></p>
                            <table class="form-table">
                                <?php do_settings_fields('advaipbl_settings_page', 'advaipbl_push_notifications_section'); ?>
                            </table>

                             <h3 style="margin-top: 20px;"><?php esc_html_e('Site Scanner Automation', 'advanced-ip-blocker'); ?></h3>
                            <p class="description"><?php esc_html_e('Configure automatic deep scans and email reports.', 'advanced-ip-blocker'); ?></p>
                            <table class="form-table">
                                <?php do_settings_fields('advaipbl_settings_page', 'advaipbl_scanner_settings_section'); ?>
                            </table>
                        </div>
                    </div>

                    <div id="section-htaccess" class="advaipbl-settings-section">
                        <div class="advaipbl-card">
                            <h2><?php esc_html_e('Server-Level Firewall (.htaccess)', 'advanced-ip-blocker'); ?></h2>
                            
                            <?php 
                            // Detección básica de servidor
                            $server_software = isset($_SERVER['SERVER_SOFTWARE']) ? sanitize_text_field(wp_unslash($_SERVER['SERVER_SOFTWARE'])) : '';
                            $is_apache_ls = (stripos($server_software, 'Apache') !== false || stripos($server_software, 'LiteSpeed') !== false);
                            $is_nginx = (stripos($server_software, 'nginx') !== false);
                            
                            // Si detectamos Nginx pero NO Apache/LiteSpeed (Nginx puro)
                            if ($is_nginx && !$is_apache_ls) {
                                echo '<div class="notice notice-warning inline"><p>';
                                echo '<strong>' . esc_html__('Compatibility Warning:', 'advanced-ip-blocker') . '</strong> ';
                                echo esc_html__('Your server appears to be running Nginx independently. Nginx does NOT support .htaccess files. Enabling these options will write to the file, but the server will likely ignore them.', 'advanced-ip-blocker');
                                echo '</p></div>';
                            }
                            ?>

                            <p><?php esc_html_e('Write security rules directly to your .htaccess file to block threats before WordPress loads.', 'advanced-ip-blocker'); ?></p>
                            
                            <?php if (!$this->plugin->htaccess_manager->is_writable()) : ?>
                                <div class="notice notice-error inline"><p><?php esc_html_e('Error: Your .htaccess file is not writable.', 'advanced-ip-blocker'); ?></p></div>
                            <?php endif; ?>

                            <table class="form-table">
                                <?php do_settings_fields('advaipbl_settings_page', 'advaipbl_htaccess_settings_section'); ?>
                            </table>
                        </div>
                    </div>

                    <div id="section-cloudflare" class="advaipbl-settings-section">
                        <div class="advaipbl-card">
                            <h2><?php esc_html_e('Cloud Edge Defense (Cloudflare)', 'advanced-ip-blocker'); ?></h2>
                            <p><?php esc_html_e('Offload security to the cloud. Block attackers at the Cloudflare Edge before they even touch your server.', 'advanced-ip-blocker'); ?></p>
                            <table class="form-table">
                                <?php do_settings_fields('advaipbl_settings_page', 'advaipbl_cloudflare_section'); ?>
                            </table>
                        </div>
                    </div>
                    
                    <div id="section-ip_detection" class="advaipbl-settings-section">
                        <div class="advaipbl-card">
                            <h2><?php esc_html_e('Visitor IP Detection', 'advanced-ip-blocker'); ?></h2>
                            <p><?php esc_html_e('Define which proxy servers you trust to provide the real visitor IP address. The plugin will only trust headers like <code>X-Forwarded-For</code> if the request comes from one of these IPs, preventing IP spoofing.', 'advanced-ip-blocker'); ?></p>
                            <table class="form-table">
                                <?php do_settings_fields('advaipbl_settings_page', 'advaipbl_ip_detection_section'); ?>
                            </table>
                        </div>
                    </div>

                    <div id="section-geolocation" class="advaipbl-settings-section">
                        <div class="advaipbl-card">
                            <h2><?php esc_html_e('Geo-Security', 'advanced-ip-blocker'); ?></h2>
                            <table class="form-table">
                                <?php do_settings_fields('advaipbl_settings_page', 'advaipbl_geolocation_section'); ?>
                            </table>
                        </div>
                    </div>
                    
                    <div id="section-threat_intelligence" class="advaipbl-settings-section">
                        <div class="advaipbl-card">
                            <h2><?php esc_html_e('Threat Intelligence Services', 'advanced-ip-blocker'); ?></h2>
                            <p><?php esc_html_e('Integrate with real-time threat databases to proactively block known malicious IPs.', 'advanced-ip-blocker'); ?></p>
                            <h3 style="margin-top: 20px;"><?php esc_html_e('AbuseIPDB Integration', 'advanced-ip-blocker'); ?></h3>
                            <p class="description">
                                <?php printf(
                                    wp_kses(
                                        /* translators: %s is a link to the AbuseIPDB website. */
                                        __('AbuseIPDB is a crowdsourced database of IPs that have been reported for malicious activity. This feature checks new visitors against the database and blocks them if their abuse score is too high. A <a href="%s" target="_blank">free API key</a> is required.', 'advanced-ip-blocker'),
                                        ['a' => ['href' => [], 'target' => []]]
                                    ),
                                    'https://www.abuseipdb.com/pricing'
                                ); ?>
                            </p>
                            <table class="form-table">
                                <?php do_settings_fields('advaipbl_settings_page', 'advaipbl_abuseipdb_section'); ?>
                            </table>
                        </div>
                        <div id="advaipbl-community-network-card" class="advaipbl-card">
                            <h3><?php esc_html_e('AIB Community Defense Network (Beta)', 'advanced-ip-blocker'); ?></h3>
                            
                            <?php if ( ! empty( $this->plugin->options['enable_community_blocking'] ) ) : ?>
                                <div class="advaipbl-status-indicator" style="margin-bottom: 15px; padding: 10px; background: #f0f6fc; border: 1px solid #cce5ff; border-radius: 4px;">
                                    <span class="dashicons dashicons-cloud-saved" style="color: #2271b1; vertical-align: middle;"></span>
                                    <strong><?php esc_html_e('Protection Active:', 'advanced-ip-blocker'); ?></strong> 
                                    <?php 
                                    if ( $list_count > 0 ) {
                                        printf(
                                            wp_kses(
                                                /* translators: 1: Number of IPs, 2: Time since last update. */
                                                __( 'Blocking %1$s known malicious IPs. Updated %2$s ago.', 'advanced-ip-blocker' ),
                                                [ 'strong' => [] ] // Permitimos la etiqueta strong
                                            ),
                                            '<strong>' . esc_html( number_format_i18n( $list_count ) ) . '</strong>',
                                            esc_html( human_time_diff( $last_update ) )
                                        );
                                    } else {
                                        esc_html_e('Waiting for initial download...', 'advanced-ip-blocker');
                                    }
                                    ?>
                                </div>
                            <?php endif; ?>
                            <p><?php esc_html_e('Join forces with other WordPress admins. By sharing verified attack data, we build a real-time blocklist specifically tailored for WordPress threats.', 'advanced-ip-blocker'); ?></p>
							<table class="form-table">
                                <?php do_settings_fields('advaipbl_settings_page', 'advaipbl_community_network_section'); ?>
                            </table>
                        </div>
                    </div>
                    
                    <div id="section-protections" class="advaipbl-settings-section">
                         <div class="advaipbl-card">
                            <h2><?php esc_html_e('Core Protection Modules', 'advanced-ip-blocker'); ?></h2>
                            <p><?php esc_html_e('These are proactive defenses that block threats based on known malicious patterns.', 'advanced-ip-blocker'); ?></p>

                            <h3 id="sub-section-honeypot" style="margin-top: 20px;"><?php esc_html_e('Honeypot Protection', 'advanced-ip-blocker'); ?></h3>
                            <table class="form-table"><?php do_settings_fields('advaipbl_settings_page', 'advaipbl_honeypot_settings_section'); ?></table>

                            <h3 id="sub-section-user-agent" style="margin-top: 20px;"><?php esc_html_e('User-Agent Protection', 'advanced-ip-blocker'); ?></h3>
                            <table class="form-table"><?php do_settings_fields('advaipbl_settings_page', 'advaipbl_user_agent_settings_section'); ?></table>

                            <h3 id="sub-section-asn" style="margin-top: 20px;"><?php esc_html_e('ASN Protection', 'advanced-ip-blocker'); ?></h3>
                            <table class="form-table"><?php do_settings_fields('advaipbl_settings_page', 'advaipbl_asn_protection_section'); ?></table>
                            
                            <h3 id="sub-section-waf" style="margin-top: 20px;"><?php esc_html_e('Web Application Firewall (WAF)', 'advanced-ip-blocker'); ?></h3>
                            <table class="form-table"><?php do_settings_fields('advaipbl_settings_page', 'advaipbl_waf_settings_section'); ?></table>
                        </div>
                    </div>

                    <div id="section-blocking_rules" class="advaipbl-settings-section">
                        <div class="advaipbl-card">
                            <h2><?php esc_html_e('Threshold Blocking & Rate Limiting', 'advanced-ip-blocker'); ?></h2>
                            <p><?php esc_html_e('Configure blocking rules based on repeated offenses or excessive request rates.', 'advanced-ip-blocker'); ?></p>
                            <h3 style="margin-top: 20px;"><?php esc_html_e('404 Error Blocking', 'advanced-ip-blocker'); ?></h3>
                            <table class="form-table"><?php do_settings_fields('advaipbl_settings_page', 'advaipbl_404_settings_section'); ?></table>
                            <h3 style="margin-top: 20px;"><?php esc_html_e('403 Error Blocking', 'advanced-ip-blocker'); ?></h3>
                            <table class="form-table"><?php do_settings_fields('advaipbl_settings_page', 'advaipbl_403_settings_section'); ?></table>
                            <h3 style="margin-top: 20px;"><?php esc_html_e('Rate Limiting', 'advanced-ip-blocker'); ?></h3>
                            <table class="form-table"><?php do_settings_fields('advaipbl_settings_page', 'advaipbl_rate_limiting_section'); ?></table>
                            <h3 style="margin-top: 20px;"><?php esc_html_e('Failed Login Blocking', 'advanced-ip-blocker'); ?></h3>
                            <table class="form-table"><?php do_settings_fields('advaipbl_settings_page', 'advaipbl_login_settings_section'); ?></table>
                        </div>
                    </div>

                    <div id="section-ip_trust" class="advaipbl-settings-section">
                        <div class="advaipbl-card">
                          <h2><?php esc_html_e('IP Trust & Threat Scoring', 'advanced-ip-blocker'); ?></h2>
                          <p><?php esc_html_e('Configure the dynamic threat scoring system. Assign points for different malicious events and define when an IP should be blocked.', 'advanced-ip-blocker'); ?></p>
                          <table class="form-table"><?php do_settings_fields('advaipbl_settings_page', 'advaipbl_threat_scoring_section'); ?></table>
                        </div>
                    </div>
                    

                    <div id="section-login_protection" class="advaipbl-settings-section">
                         <div class="advaipbl-card">
                            <h2><?php esc_html_e('Login & User Protection', 'advanced-ip-blocker'); ?></h2>
                            <h3 style="margin-top: 20px;"><?php esc_html_e('Advanced Login Protection', 'advanced-ip-blocker'); ?></h3>
                            <table class="form-table"><?php do_settings_fields('advaipbl_settings_page', 'advaipbl_advanced_login_section'); ?></table>

                            <h3 id="sub-section-login-lockdown" style="margin-top: 20px;"><?php esc_html_e('Login Page Lockdown Mode (Beta)', 'advanced-ip-blocker'); ?></h3>
                            <table class="form-table"><?php do_settings_fields('advaipbl_settings_page', 'advaipbl_login_lockdown_section'); ?></table>

                            <h3 style="margin-top: 20px;"><?php esc_html_e('Advanced XML-RPC Protection', 'advanced-ip-blocker'); ?></h3>
                            <table class="form-table"><?php do_settings_fields('advaipbl_settings_page', 'advaipbl_advanced_xmlrpc_section'); ?></table>
                            <h3 id="sub-section-xmlrpc-lockdown" style="margin-top: 20px;"><?php esc_html_e( 'Distributed XML-RPC attacks protection', 'advanced-ip-blocker' ); ?></h3>
                            <table class="form-table"><?php do_settings_fields('advaipbl_settings_page', 'advaipbl_advanced_xmlrpc_protection_section'); ?></table>
                            
                            <h3 id="sub-section-2FA" style="margin-top: 20px;"><?php esc_html_e('Two-Factor Authentication (2FA)', 'advanced-ip-blocker'); ?></h3>
                            <table class="form-table"><?php do_settings_fields('advaipbl_settings_page', 'advaipbl_2fa_settings_section'); ?></table>

                            <h3 style="margin-top: 20px;"><?php esc_html_e('reCAPTCHA Protection', 'advanced-ip-blocker'); ?></h3>
                            <table class="form-table"><?php do_settings_fields('advaipbl_settings_page', 'advaipbl_recaptcha_section'); ?></table>
                        </div>
                    </div>

                    <div id="section-signature_engine" class="advaipbl-settings-section">
                        <div class="advaipbl-card">
                            <h2><?php esc_html_e('Attack Signature Engine (Beta)', 'advanced-ip-blocker'); ?></h2>
                            <p><?php esc_html_e('This is an advanced defense system to detect and stop distributed attacks (botnets) by analyzing request patterns rather than individual IPs.', 'advanced-ip-blocker'); ?></p>
                            <table class="form-table"><?php do_settings_fields('advaipbl_settings_page', 'advaipbl_signature_engine_section'); ?></table>
                        </div>
                        <div class="advaipbl-card">
                            <h2><?php esc_html_e('Trusted Signatures (Whitelist)', 'advanced-ip-blocker'); ?></h2>
                            <p><?php esc_html_e('Manage specific request signatures that should always be allowed by the Attack Signature Engine.', 'advanced-ip-blocker'); ?></p>
                            <table class="form-table"><?php do_settings_fields('advaipbl_settings_page', 'advaipbl_trusted_signatures_section'); ?></table>
                        </div>
                    </div>
                    
                    <div id="section-internal_security" class="advaipbl-settings-section">
                        <div class="advaipbl-card">
                            <h2><?php esc_html_e('Internal Security & Forensics', 'advanced-ip-blocker'); ?></h2>
                            <p class="description">
                                <?php esc_html_e('Audit administrative actions and monitor the integrity of your WordPress files.', 'advanced-ip-blocker'); ?>
                                <br><br>
                                <a href="<?php echo esc_url(admin_url('admin.php?page=advaipbl_settings_page&tab=logs&sub-tab=audit_log')); ?>" class="button button-secondary">
                                    <?php esc_html_e('View Activity Audit Logs', 'advanced-ip-blocker'); ?>
                                </a>
                            </p>
                            <table class="form-table">
                                <?php do_settings_fields('advaipbl_settings_page', 'advaipbl_internal_security_section'); ?>
                            </table>
                        </div>
                    </div>

                    <?php if (empty($this->plugin->options['allow_telemetry'])) :
                        $telemetry_setting_id = 'advaipbl_allow_telemetry';
                        ?>
                        <div class="advaipbl-soft-notice">
                            <p>
                                <?php /* translators: %s: Settings URL. */printf(wp_kses(__('Psst! Help us improve the plugin. <a href="%s">Enable anonymous usage tracking</a>.', 'advanced-ip-blocker'), ['a' => ['href' => []]]), '#' . esc_attr($telemetry_setting_id)); ?>
                            </p>
                        </div>
                    <?php endif; ?>

                    <div class="no-results-message">
                    <p><?php esc_html_e( 'No settings found matching your search.', 'advanced-ip-blocker' ); ?></p>
                    </div>
                    
                    <div id="section-uninstall" class="advaipbl-settings-section">
                        <div class="advaipbl-card">
                            <h2><?php esc_html_e('Uninstallation', 'advanced-ip-blocker'); ?></h2>
                            <table class="form-table"><?php do_settings_fields('advaipbl_settings_page', 'advaipbl_uninstall_section'); ?></table>
                        </div>
                    </div>

                    <?php submit_button(); ?>
                </form>
            </div>
        </div>
        
        <div id="advaipbl-floating-save-bar" class="advaipbl-save-bar-hidden">
           <div class="advaipbl-save-bar-content">
              <span class="advaipbl-save-bar-text"><?php esc_html_e('You have unsaved changes.', 'advanced-ip-blocker'); ?></span>
              <span class="advaipbl-save-bar-buttons">
                <button type="button" id="advaipbl-discard-changes" class="button button-secondary"><?php esc_html_e('Discard', 'advanced-ip-blocker'); ?></button>
                <button type="submit" id="advaipbl-save-changes-floating" class="button button-primary"><?php esc_html_e('Save Changes', 'advanced-ip-blocker'); ?></button>
              </span>
          </div>
        </div>
        <?php
    }
/**
 * Muestra la tabla de gestión de usuarios para la Autenticación de Dos Factores.
 */
    public function display_2fa_management_tab() {
	$is_enabled = !empty($this->plugin->options['enable_2fa']);
    $settings_url = admin_url('admin.php?page=advaipbl_settings_page-settings&sub-tab=general_settings#sub-section-2FA');
	$profile_url = admin_url('profile.php');
    ?>
        <div class="notice notice-info inline">
      <p>
    <?php
        // Creamos la etiqueta de estado con las clases correctas.
        $status_tag = sprintf(
            '<span class="advaipbl-status-tag %s">%s</span>',
            $is_enabled ? 'enabled' : 'disabled',
            $is_enabled ? esc_html__('Active', 'advanced-ip-blocker') : esc_html__('Inactive', 'advanced-ip-blocker')
        );

        printf(
            wp_kses(
                /* translators: %1$s: Status tag (Active/Inactive), %2$s: Link to Settings, %3$s: Link to Profile. */
                __('Two-Factor Authentication (2FA) is currently %1$s. You can change this in the <a href="%2$s">Settings</a>. When enabled, users will see the 2FA setup section in their <a href="%3$s">Profile</a>.', 'advanced-ip-blocker'),
                [
                    'span' => ['class' => true],
                    'a'    => ['href' => true],
                ]
            ),
			// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
            $status_tag,
            esc_url($settings_url),
            esc_url($profile_url)
        );
        ?>
      </p>
    </div>		
    <?php
		
        if ( ! class_exists( 'WP_List_Table' ) ) {
            require_once( ABSPATH . 'wp-admin/includes/class-wp-list-table.php' );
        }
        if ( ! class_exists('ADVAIPBL_2FA_Users_List_Table') ) {
            require_once plugin_dir_path( __FILE__ ) . 'class-advaipbl-2fa-users-list-table.php';
        }
        
        $users_list_table = new ADVAIPBL_2FA_Users_List_Table();
        
        // Procesamos la acción en lote aquí, ANTES de preparar los items.
        $users_list_table->process_bulk_action();
        $users_list_table->prepare_items();
				
        ?>
        <div class="wrap">
            <h1 class="wp-heading-inline"><?php esc_html_e( 'User 2FA Status', 'advanced-ip-blocker' ); ?></h1>
            <p><?php esc_html_e( 'This table shows the 2FA status for all users. You can manually reset a user\'s 2FA if they get locked out of their account.', 'advanced-ip-blocker' ); ?></p>
            
            <hr class="wp-header-end">
            
            <?php $users_list_table->views(); ?>
            
            <form id="advaipbl-2fa-users-form" method="post">
                <!-- Para las acciones en lote, WordPress necesita un nonce aquí -->
                <?php wp_nonce_field( 'advaipbl_2fa_bulk_action_nonce', 'advaipbl_2fa_nonce_field' ); ?>

                <?php
                $users_list_table->search_box( __( 'Search Users', 'advanced-ip-blocker' ), 'user' );
                $users_list_table->display();
                ?>
            </form>
        </div>
        <?php
    }
	public function display_user_agents_tab() {
    $is_enabled = !empty($this->plugin->options['enable_user_agent_blocking']);
    $settings_url = admin_url('admin.php?page=advaipbl_settings_page-settings&sub-tab=general_settings#sub-section-user-agent');
    ?>
    <div class="notice notice-info inline">
        <p>
            <?php 
            // Creamos la etiqueta de estado con las clases correctas.
            $status_tag = sprintf(
                '<span class="advaipbl-status-tag %s">%s</span>',
                $is_enabled ? 'enabled' : 'disabled',
                $is_enabled ? esc_html__('Active', 'advanced-ip-blocker') : esc_html__('Inactive', 'advanced-ip-blocker')
            );

            printf(
                wp_kses( 
                    /* translators: 1: Status tag (Active/Inactive), 2: Link to settings page. */
                    __('User-Agent Protection is currently %1$s. You can change this in the <a href="%2$s">Settings</a>.', 'advanced-ip-blocker'),
                    [
                        'span' => ['class' => true], 
                        'a'    => ['href' => []]
                    ]
                ),
				// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
                $status_tag,
                esc_url($settings_url)
            );
            ?>
        </p>
    </div>
    <?php
        $blocked_user_agents = get_option('advaipbl_blocked_user_agents', []);
        $whitelisted_user_agents = get_option('advaipbl_whitelisted_user_agents', []);
        
                $default_uas_list = [
            '# === Vulnerability Scanners & Pentesting Tools ===',
            'Acunetix', 'Arachni', 'Burp', 'Dirb', 'DirBuster', 'Feroxbuster', 'Go-http-client', 'Havij', 'Nessus', 'Nikto', 'Nmap', 'Netsparker', 'OpenVAS', 'Photon/1.0', 'sqlmap', 'Vega', 'Wfuzz', 'WhatWeb', 'WPScan', 'WPSec', 'ZAP/', 'masscan', 'ScanNG', 'PressVuln', 'PostmanRuntime', 'CensysInspect', 'Expanse', 'internet-measurement', 'JSScanner/',
            '',
            '# === Generic Bots & Scripting Libraries ===',
            'curl', 'HTTrack', 'Java/', 'okhttp', 'perl', 'php/', 'Python', 'python-requests', 'Scrapy', 'wget', 'libwww', 'ruby',
            '',
            '# === Aggressive Scrapers & Black Hat SEO Bots ===',
            '#AhrefsBot', 'Bytespider', 'contabot', 'dataprovider', 'DigExt', 'DotBot', 'EmailCollector', 'ExtractorPro', 'MegaIndex', '#MJ12bot', 'SemrushBot', 'WebCollector', 'WebCopier', 'AliyunSecBot', 'AwarioBot', 'BW/', '#GoogleOther', 'IonCrawl', 'ISSCyberRiskCrawler',
            '',
            '# === Spam, Low-Quality AI & Comment Bots ===',
            '#Applebot-Extended', 'ClaudeBot', 'Diffbot', '#FacebookBot', 'FriendlyCrawler', '#Google-Extended', 'ImagesiftBot', 'Image2dataset', '#Meta-ExternalAgent', 'omgili', 'Timpibot', 'omgilibot', 'AcoonBot/', 'anthropic-ai', 'BoardReader', 'CCBot', '#ChatGPT-User', 'Claude-Web', 'DataForSeoBot', '#GPTBot', 'PerplexityBot', '#petalbot', '#YandexBot', 'ZmEu',
            '',
            '# === Aggressive Regional Crawlers (optional) ===',
            'Baiduspider', 'Baiduspider-image', 'Baiduspider-news', 'Barkrowler', 'msnbot-media', 'SeznamBot', 'Sogou', 'YisouSpider', 'BLEXBot', 'news-please', 'Orbbot', 'peer39_crawler', 'VelenPublicWebCrawler', '#wp_is_mobile', 'Zoominfobot',
            '',
            '# === Suspicious or Malformed User-Agents ===',
            'Dalvik/', 'morfeus', 'ShellBot', 'zgrab', 'Chrome/45', 'Mozilla/4.0', 'Empty', 'Mozlila', 'GRequests/'
        ];
        $default_uas_text = implode("\n", $default_uas_list);
        ?>
        <h2><?php esc_html_e('User-Agent Blocking Management', 'advanced-ip-blocker'); ?></h2>
        <form method="post" action="">
            <input type="hidden" name="action_type" value="save_user_agents">
            <?php wp_nonce_field('advaipbl_admin_nonce_action', 'advaipbl_admin_nonce_action'); ?>
            <div style="display: flex; gap: 20px; flex-wrap: wrap;">
                <div style="flex: 1; min-width: 300px;">
                    <h3><?php esc_html_e('Blocked User-Agents List', 'advanced-ip-blocker'); ?></h3>
                    <p><?php esc_html_e('Add one User-Agent or fragment per line to instantly block any visit containing it.', 'advanced-ip-blocker'); ?></p>
                    <textarea name="blocked_user_agents" rows="15" style="width:100%;" class="large-text code"><?php echo esc_textarea(implode("\n", $blocked_user_agents)); ?></textarea>
                </div>
                <div style="flex: 1; min-width: 300px;">
                    <h3><?php esc_html_e('Whitelisted User-Agents List', 'advanced-ip-blocker'); ?></h3>
                    <p><?php esc_html_e('Add one User-Agent or fragment per line. Any User-Agent containing these strings will NEVER be blocked.', 'advanced-ip-blocker'); ?></p>
                    <textarea name="whitelisted_user_agents" rows="15" style="width:100%;" class="large-text code"><?php echo esc_textarea(implode("\n", $whitelisted_user_agents)); ?></textarea>
                </div>
            </div>
            <?php submit_button(__('Save User-Agent Lists', 'advanced-ip-blocker')); ?>
        </form>
        <hr>
        <h3><?php esc_html_e('Common User-Agent Suggestions to Block', 'advanced-ip-blocker'); ?></h3>
        <p><?php esc_html_e('You can copy and paste these into the block list above.', 'advanced-ip-blocker'); ?></p>
        <textarea rows="15" cols="80" class="large-text code" readonly><?php echo esc_textarea($default_uas_text); ?></textarea>
        <?php
    }
	public function display_honeypot_tab() {
		 $is_enabled = !empty($this->plugin->options['enable_honeypot_blocking']);
    $settings_url = admin_url('admin.php?page=advaipbl_settings_page-settings&sub-tab=general_settings#sub-section-honeypot');
    ?>
        <div class="notice notice-info inline">
        <p>
            <?php 
            // Creamos la etiqueta de estado con las clases correctas.
            $status_tag = sprintf(
                '<span class="advaipbl-status-tag %s">%s</span>',
                $is_enabled ? 'enabled' : 'disabled',
                $is_enabled ? esc_html__('Active', 'advanced-ip-blocker') : esc_html__('Inactive', 'advanced-ip-blocker')
            );

            printf(
                wp_kses( 
                    /* translators: 1: Status tag (Active/Inactive), 2: Link to settings page. */
                    __('Honeypot Protection is currently %1$s. You can change this in the <a href="%2$s">Settings</a>.', 'advanced-ip-blocker'),
                    [
                        'span' => ['class' => true], 
                        'a'    => ['href' => []]
                    ]
                ),
				// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
                $status_tag,
                esc_url($settings_url)
            );
            ?>
        </p>
    </div>
    <?php
        $honeypot_urls = get_option('advaipbl_honeypot_urls', []);
        
        $default_traps_list = [
            '# === Configuration & Credential Files ===',
            '/.env', '/.htpasswd', '/wp-config.php', '/wp-config.bak', '/config.json',
            '',
            '# === Version Control Systems (Source Code Exposure) ===',
            '/.git/', '/.svn/',
            '',
            '# === Server & PHP Information Files ===',
            '/phpinfo.php', '/info.php', '/.user.ini',
            '',
            '# === Common Attack Shells & Payloads ===',
            '/shell.php', '/cmd.php', '/wso.php', '/c99.php', '/r57.php', '/eval-stdin.php',
            '',
            '# === Vulnerability Scans for Plugins/Themes ===',
            '/wp-content/plugins/revslider/',
            '/wp-content/plugins/gravityforms/',
            '/timthumb.php',
            '',
            '# === Backup & Database Files ===',
            '/wordpress.zip', '/backup.zip', '/site.sql',
        ];
        $default_traps_text = implode("\n", $default_traps_list);
        ?>
        <h2><?php esc_html_e('Honeypot URL Blocking', 'advanced-ip-blocker'); ?></h2>
        <p><?php echo wp_kses_post( __('Instantly block any IP that tries to access a URL containing one of the following texts. This is very effective against vulnerability scanning bots.', 'advanced-ip-blocker') ); ?></p>
        <p><strong><?php esc_html_e('Warning!', 'advanced-ip-blocker'); ?></strong> <?php echo wp_kses_post( __('Do not add URLs that a legitimate user might visit (like <code>/blog/</code> or <code>/contact/</code>). Use attack-specific patterns.', 'advanced-ip-blocker') ); ?></p>
        <form method="post" action="">
            <input type="hidden" name="action_type" value="save_honeypot_urls"><?php wp_nonce_field('advaipbl_admin_nonce_action', 'advaipbl_admin_nonce_action'); ?>
            <h3><?php esc_html_e('Honeypot URLs List', 'advanced-ip-blocker'); ?></h3>
            <p><?php esc_html_e('Add one URL or URL fragment per line. The check is case-insensitive.', 'advanced-ip-blocker'); ?></p>
            <textarea name="honeypot_urls" rows="15" cols="80" class="large-text code"><?php echo esc_textarea(implode("\n", $honeypot_urls)); ?></textarea>
            <?php submit_button(__('Save Honeypot URLs', 'advanced-ip-blocker')); ?>
        </form>
        <hr>
        <h3><?php esc_html_e('Common URL Suggestions to Block', 'advanced-ip-blocker'); ?></h3>
        <p><?php esc_html_e('You can copy and paste these into the list above.', 'advanced-ip-blocker'); ?></p>
        <textarea rows="15" cols="80" class="large-text code" readonly><?php echo esc_textarea(trim($default_traps_text)); ?></textarea>
    <?php }
	
        public function display_blocked_ips_tab() {
    global $wpdb;
    $table_name = $wpdb->prefix . 'advaipbl_blocked_ips';
    
    // phpcs:disable WordPress.Security.NonceVerification.Recommended
    $filter_type = isset($_GET['filter_type']) ? sanitize_key($_GET['filter_type']) : 'all';
    $search_term = isset($_GET['s']) ? sanitize_text_field(wp_unslash($_GET['s'])) : '';
    $orderby = isset($_GET['orderby']) && in_array($_GET['orderby'], ['ip_range', 'block_type', 'timestamp'], true) ? sanitize_key($_GET['orderby']) : 'timestamp';
    $order = isset($_GET['order']) && in_array(strtolower($_GET['order']), ['asc', 'desc'], true) ? strtolower(sanitize_key($_GET['order'])) : 'desc';
    $current_page = isset($_GET['paged']) ? absint($_GET['paged']) : 1;
    $per_page = isset($_GET['advaipbl_per_page']) ? absint($_GET['advaipbl_per_page']) : 20;
    // phpcs:enable
    $offset = ($current_page - 1) * $per_page;

    $where_clauses = [];
    if ('all' !== $filter_type) {
        $where_clauses[] = $wpdb->prepare("block_type = %s", $filter_type);
    }
    
    // Add Search Clause
    if (!empty($search_term)) {
        $search_like = '%' . $wpdb->esc_like($search_term) . '%';
        $where_clauses[] = $wpdb->prepare("ip_range LIKE %s", $search_like);
    }

    $where_sql = !empty($where_clauses) ? 'WHERE ' . implode(' AND ', $where_clauses) : '';

    // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
    $total_items = $wpdb->get_var("SELECT COUNT(id) FROM {$table_name} {$where_sql}");
    $total_pages = ceil($total_items / $per_page);

    // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
    $items_for_page = $wpdb->get_results($wpdb->prepare("SELECT * FROM {$table_name} {$where_sql} ORDER BY " . esc_sql($orderby) . " " . esc_sql($order) . " LIMIT %d OFFSET %d", $per_page, $offset), ARRAY_A);

    $ips_and_ranges_on_page = wp_list_pluck($items_for_page, 'ip_range');
    $single_ips_on_page = array_filter($ips_and_ranges_on_page, function($entry) { return filter_var($entry, FILTER_VALIDATE_IP); });
    $locations = !empty($single_ips_on_page) ? $this->plugin->session_manager->get_cached_locations($single_ips_on_page) : [];
    $definitions = $this->plugin->get_all_block_type_definitions();
    ?>
    
    <h2><?php esc_html_e('Manually Block IP', 'advanced-ip-blocker'); ?></h2>
    <form method="post" action="">
        <input type="hidden" name="action_type" value="add_manual_block">
        <?php wp_nonce_field('advaipbl_admin_nonce_action', 'advaipbl_admin_nonce_action'); ?>
        <input type="text" name="ip_address" placeholder="<?php esc_attr_e('IP, CIDR, or Range (e.g., 1.2.3.0/24)', 'advanced-ip-blocker'); ?>" required style="width: 350px;">
        <button type="submit" class="button button-primary"><?php esc_html_e('Block IP', 'advanced-ip-blocker'); ?></button>
    </form>

    <h2><?php esc_html_e('All Blocked IPs', 'advanced-ip-blocker'); ?></h2>

    <!-- FORMULARIO DE FILTROS (GET) -->
    <form method="get" class="advaipbl-filters-form">
        <?php // phpcs:ignore WordPress.Security.NonceVerification.Recommended ?>
        <input type="hidden" name="page" value="<?php echo esc_attr( sanitize_text_field( wp_unslash( $_REQUEST['page'] ?? '' ) ) ); ?>">
        <input type="hidden" name="tab" value="ip_management">
        <input type="hidden" name="sub-tab" value="blocked_ips">
        <div class="tablenav top">
            <div class="alignleft actions">
                <?php $this->plugin->render_per_page_selector($per_page); ?>
                <select id="filter-by-type" name="filter_type">
                    <option value="all" <?php selected($filter_type, 'all'); ?>><?php esc_html_e('All Block Types', 'advanced-ip-blocker'); ?></option>
                    <?php foreach ($definitions as $type => $def) : ?>
                        <?php
                        // Solo mostramos en el filtro los tipos que realmente generan un bloqueo persistente en la tabla.
                        $is_persistent_block = ($type === 'manual' || $type === 'bulk_import' || $type === 'advanced_rule' || !empty($def['duration_key']));
                        if ( ! $is_persistent_block ) continue;
                        ?>
                        <option value="<?php echo esc_attr($type); ?>" <?php selected($filter_type, $type); ?>><?php echo esc_html($def['label']); ?></option>
                    <?php endforeach; ?>
                </select>
                <input type="search" name="s" value="<?php echo esc_attr($search_term); ?>" placeholder="<?php esc_attr_e('Search IP...', 'advanced-ip-blocker'); ?>">
                <input type="submit" id="post-query-submit" class="button" value="<?php esc_attr_e('Filter', 'advanced-ip-blocker'); ?>">
            </div>
            <div class="alignleft actions">
                <button type="button" id="advaipbl-bulk-import-blocked-btn" class="button button-secondary"><?php esc_html_e('Bulk Import', 'advanced-ip-blocker'); ?></button>
                <button type="button" id="advaipbl-bulk-export-blocked-btn" class="button button-secondary"><?php esc_html_e('Export Blocked IPs', 'advanced-ip-blocker'); ?></button>
            </div>
            <div class="tablenav-pages">
                <span class="displaying-num"><?php /* translators: %s: The number of items per page. */ printf(esc_html(_n('%s item', '%s items', $total_items, 'advanced-ip-blocker')), esc_html(number_format_i18n($total_items))); ?></span>
                <?php $page_links = paginate_links(['base' => add_query_arg(['paged' => '%#%', 'filter_type' => $filter_type, 's' => $search_term, 'advaipbl_per_page' => $per_page]), 'format' => '', 'total' => $total_pages, 'current' => $current_page]); if ($page_links) echo wp_kses_post($page_links); ?>
            </div>
            <br class="clear">
        </div>
    </form>

    <!-- Bulk Import Blocked IPs Modal -->
    <div id="advaipbl-bulk-import-blocked-modal" class="advaipbl-modal-overlay" style="display:none;">
        <div class="advaipbl-modal-content">
            <span class="advaipbl-modal-close advaipbl-modal-cancel">&times;</span>
            <h2><?php esc_html_e('Bulk Import Blocked IPs', 'advanced-ip-blocker'); ?></h2>
            <div class="advaipbl-modal-body">
                <p><?php esc_html_e('Upload a CSV file OR enter IPs/CIDRs manually (one per line).', 'advanced-ip-blocker'); ?></p>
                
                <div style="margin-bottom: 15px; padding: 10px; background: #f0f0f1; border: 1px dashed #8c8f94; text-align: center;">
                    <input type="file" id="advaipbl-bulk-import-blocked-csv" accept=".csv" style="display: none;">
                    <button type="button" class="button button-secondary" onclick="document.getElementById('advaipbl-bulk-import-blocked-csv').click();"><?php esc_html_e('Select CSV File', 'advanced-ip-blocker'); ?></button>
                    <span id="advaipbl-bulk-import-blocked-csv-name" style="margin-left: 10px; font-style: italic;"></span>
                </div>

                <textarea id="advaipbl-bulk-import-blocked-textarea" rows="8" style="width:100%;" placeholder="192.168.1.1&#10;10.0.0.0/24"></textarea>
                
                <div style="display: flex; gap: 15px; margin-top: 15px;">
                    <div style="flex: 1;">
                        <label for="advaipbl-bulk-import-blocked-duration"><strong><?php esc_html_e('Duration:', 'advanced-ip-blocker'); ?></strong></label>
                        <select id="advaipbl-bulk-import-blocked-duration" style="width:100%;">
                            <option value="0"><?php esc_html_e('Permanent', 'advanced-ip-blocker'); ?></option>
                            <option value="60"><?php esc_html_e('1 Hour', 'advanced-ip-blocker'); ?></option>
                            <option value="1440" selected><?php esc_html_e('24 Hours', 'advanced-ip-blocker'); ?></option>
                            <option value="10080"><?php esc_html_e('7 Days', 'advanced-ip-blocker'); ?></option>
                            <option value="43200"><?php esc_html_e('30 Days', 'advanced-ip-blocker'); ?></option>
                        </select>
                    </div>
                </div>

                <div id="advaipbl-bulk-import-blocked-results" style="margin-top: 10px; display:none;"></div>
                
                <div style="margin-top: 15px; text-align: right;">
                    <button type="button" class="button button-primary" id="advaipbl-process-bulk-import-blocked"><?php esc_html_e('Import IPs', 'advanced-ip-blocker'); ?></button>
                    <button type="button" class="button button-secondary advaipbl-modal-cancel"><?php esc_html_e('Close', 'advanced-ip-blocker'); ?></button>
                </div>
            </div>
        </div>
    </div>

    <!-- FORMULARIO DE ACCIONES EN LOTE (POST) -->
    <form id="advaipbl-blocked-ips-form" method="post">
        <?php wp_nonce_field('advaipbl_admin_nonce_action', 'advaipbl_admin_nonce_action'); ?>
        <div class="tablenav top bulkactions">
            <div class="alignleft actions">
                <label for="bulk-action-selector-top" class="screen-reader-text"><?php esc_html_e('Select bulk action', 'advanced-ip-blocker'); ?></label>
                <select name="bulk_action" id="bulk-action-selector-top">
                    <option value="-1"><?php esc_html_e('Bulk Actions', 'advanced-ip-blocker'); ?></option>
                    <option value="unblock"><?php esc_html_e('Unblock Selected', 'advanced-ip-blocker'); ?></option>
                    <option value="unblock_all" style="color: red; font-weight: bold;"><?php esc_html_e('Unblock ALL IPs', 'advanced-ip-blocker'); ?></option>
                </select>
                <input type="submit" id="doaction" class="button action" value="<?php esc_attr_e('Apply', 'advanced-ip-blocker'); ?>">
            </div>
            <br class="clear">
        </div>
        
        <div class="advaipbl-table-responsive-wrapper">
        <table class="wp-list-table widefat fixed striped">
            <thead>
                <tr>
                    <td id="cb" class="manage-column column-cb check-column"><input id="cb-select-all-1" type="checkbox"></td>
                    <?php $this->plugin->print_sortable_header(__('IP', 'advanced-ip-blocker'), 'ip_range', $orderby, $order); ?>
                        <?php $this->plugin->print_sortable_header(__('Block Type', 'advanced-ip-blocker'), 'block_type', $orderby, $order); ?>
                        <?php $this->plugin->print_sortable_header(__('Since', 'advanced-ip-blocker'), 'timestamp', $orderby, $order); ?>
                        <th><?php esc_html_e('Duration', 'advanced-ip-blocker'); ?></th>
                        <th><?php esc_html_e('Details', 'advanced-ip-blocker'); ?></th>
                        <th><?php esc_html_e('Location', 'advanced-ip-blocker'); ?></th>
                        <th><?php esc_html_e('Status', 'advanced-ip-blocker'); ?></th>
                    </tr>
                </thead>
                <tbody id="the-list">
                    <?php if (empty($items_for_page)) : ?>
                        <tr class="no-items"><td class="colspanchange" colspan="8"><?php esc_html_e('No IPs found for the current filter.', 'advanced-ip-blocker'); ?></td></tr>
                    <?php else: foreach ($items_for_page as $block) : ?>
                        <tr>
                            <th scope="row" class="check-column"><input type="checkbox" name="ips_to_process[]" value="<?php echo esc_attr($block['ip_range']); ?>"></th>
                            <td><strong><?php echo esc_html($block['ip_range']); ?></strong></td>
                            <td><?php echo esc_html($definitions[$block['block_type']]['label'] ?? ucwords(str_replace('_', ' ', $block['block_type']))); ?></td>
                            <td><?php echo esc_html(ADVAIPBL_Main::get_formatted_datetime($block['timestamp'])); ?></td>
<td>
    <?php
    // CRITICAL FIX: Universal DB-based block duration. 
    // We calculate the duration based on the actual 'expires_at' and 'timestamp' stored in the DB.
    // This ensures that the UI matches the Logs and the Notifications 100%, regardless of subsequent settings changes.
    
    $expires_at = (int) $block['expires_at'];
    $timestamp  = (int) $block['timestamp'];
    
    if ($expires_at === 0) {
        // 0 explicitamente significa Permanente en nuestra lógica
        esc_html_e('Permanent', 'advanced-ip-blocker');
    } else {
        $duration_seconds = $expires_at - $timestamp;
        
        // Sanity check: si es manual, o si la duración es <= 0 (glitch), o es muy larga (> 1 año, legacy permanent), lo mostramos como permanente.
        if ($block['block_type'] === 'manual' || $duration_seconds <= 0 || $duration_seconds > 31536000) {
             esc_html_e('Permanent', 'advanced-ip-blocker');
        } else {
             $duration_minutes = round($duration_seconds / 60);
             printf( /* translators: %d: The number of minutes for a block duration. */
                esc_html__('%d minutes', 'advanced-ip-blocker'),
                (int) $duration_minutes
             );
        }
    }
    ?>
</td>
                            <td style="word-break:break-all;"><?php echo esc_html($block['reason']); ?></td>
                            <td>
                                <?php
                                $location = $locations[ $block['ip_range'] ] ?? null;
                                if ( $location && empty($location['error']) ) {
                                    $location_parts = [];
                                    if ( ! empty( $location['city'] ) ) { $location_parts[] = $location['city']; }
                                    if ( ! empty( $location['country'] ) ) {
                                        $country_str = $location['country'];
                                        if ( ! empty( $location['country_code'] ) ) {
                                            $country_str .= ' (' . $location['country_code'] . ')';
                                        }
                                        $location_parts[] = $country_str;
                                    }
                                    echo esc_html( implode( ', ', $location_parts ) );
                                    if ( ! empty( $location['lat'] ) && ! empty( $location['lon'] ) ) {
                                        echo '<br><button class="button button-small advaipbl-btn-map" data-lat="' . esc_attr( $location['lat'] ) . '" data-lon="' . esc_attr( $location['lon'] ) . '">' . esc_html__( 'View Map', 'advanced-ip-blocker' ) . '</button>';
                                    }
                                } else {
                                    esc_html_e( 'Not available', 'advanced-ip-blocker' );
                                }
                                ?>
                            </td>
                            <td>
                                <?php
                                $is_active = $block['expires_at'] == 0 || time() < $block['expires_at'];
                                $status_text = $is_active ? __('Blocked', 'advanced-ip-blocker') : __('Unblocked (Expired)', 'advanced-ip-blocker');
                                $status_color = $is_active ? 'red' : 'green';
                                ?>
                                <span style="color:<?php echo esc_attr($status_color); ?>;"><?php echo esc_html($status_text); ?></span>
                                <?php if ($is_active) : 
                                    $unblock_nonce_url = wp_nonce_url(
                                        add_query_arg(['action' => 'advaipbl_unblock_ip', 'ip' => $block['ip_range']]),
                                        'advaipbl_unblock_ip'
                                    );
                                ?>
                                <div class="row-actions">
                                    <span class="trash">
                                        <a href="<?php echo esc_url($unblock_nonce_url); ?>" style="color: #b32d2e;"><?php esc_html_e('Unblock', 'advanced-ip-blocker'); ?></a>
                                    </span>
                                </div>
                                <?php endif; ?>
                                <?php ?>
                            </td>
                        </tr>
                    <?php endforeach; endif; ?>
                </tbody>
            </table>
            </div>

            <div class="tablenav bottom">
            <div class="alignleft actions bulkactions">
                <label for="bulk-action-selector-bottom" class="screen-reader-text"><?php esc_html_e('Select bulk action', 'advanced-ip-blocker'); ?></label>
                <select name="bulk_action2" id="bulk-action-selector-bottom">
                    <option value="-1"><?php esc_html_e('Bulk Actions', 'advanced-ip-blocker'); ?></option>
                    <option value="unblock"><?php esc_html_e('Unblock Selected', 'advanced-ip-blocker'); ?></option>
                    <option value="unblock_all" style="color: red; font-weight: bold;"><?php esc_html_e('Unblock ALL IPs', 'advanced-ip-blocker'); ?></option>
                </select>
                <input type="submit" id="doaction2" class="button action" value="<?php esc_attr_e('Apply', 'advanced-ip-blocker'); ?>">
            </div>
                <div class="tablenav-pages">
                    <span class="displaying-num"><?php /* translators: %s: The number of items per page. */ printf(esc_html(_n('%s item', '%s items', $total_items, 'advanced-ip-blocker')), esc_html(number_format_i18n($total_items))); ?></span>
                    <?php if ($page_links) echo wp_kses_post($page_links); ?>
                </div>
                <br class="clear">
            </div>
        </form>
        <div id="mapModal"><div id="mapModalContent"><div id="mapModalHeader"><button id="closeModalBtn" class="button"><?php esc_html_e('Close', 'advanced-ip-blocker'); ?></button></div><iframe id="mapModalFrame" loading="lazy"></iframe></div></div>
        <?php
    }
	public function display_whitelist_tab() {
    $raw_whitelist_ips = get_option('advaipbl_ips_whitelist', []);
    $table_data = [];
    if ( is_array($raw_whitelist_ips) ) {
        foreach ($raw_whitelist_ips as $ip => $data) {
            if ( is_array($data) && isset($data['timestamp']) ) {
                 $table_data[] = [ 'ip' => $ip, 'timestamp' => $data['timestamp'], 'detail' => $data['detail'] ?? '' ];
            } elseif ( is_numeric($data) ) {
                $table_data[] = [ 'ip' => $ip, 'timestamp' => $data, 'detail' => __('Migrated from old format', 'advanced-ip-blocker') ];
            }
        }
    }
    
    // phpcs:disable WordPress.Security.NonceVerification.Recommended
    $sortable_columns = ['ip', 'timestamp', 'detail'];
    $orderby = isset($_GET['orderby']) && in_array($_GET['orderby'], $sortable_columns, true) ? sanitize_key($_GET['orderby']) : 'timestamp';
    $order = isset($_GET['order']) && in_array(strtolower($_GET['order']), ['asc', 'desc'], true) ? strtolower(sanitize_key($_GET['order'])) : 'desc';
    // phpcs:enable
    
    usort($table_data, function($a, $b) use ($orderby, $order) {
        $a_val = $a[$orderby] ?? ''; $b_val = $b[$orderby] ?? '';
        if ($a_val == $b_val) return 0;
        return ($order === 'asc') ? strnatcasecmp((string)$a_val, (string)$b_val) : strnatcasecmp((string)$b_val, (string)$a_val);
    });

    // phpcs:ignore WordPress.Security.NonceVerification.Recommended
    $current_page = isset($_GET['paged']) ? absint($_GET['paged']) : 1;
    // phpcs:ignore WordPress.Security.NonceVerification.Recommended
    $per_page = isset($_GET['advaipbl_per_page']) ? absint($_GET['advaipbl_per_page']) : 20;
    $total_items = count($table_data);
    $total_pages = ceil($total_items / $per_page);
    $items_for_page = array_slice($table_data, ($current_page - 1) * $per_page, $per_page);

    $ips_on_page = wp_list_pluck($items_for_page, 'ip');
    $locations = $this->plugin->session_manager->get_cached_locations($ips_on_page);
    ?>
    <h2><?php esc_html_e('Add IP to Whitelist', 'advanced-ip-blocker'); ?></h2>
    <form method="post" action="">
        <input type="hidden" name="action_type" value="add_whitelist">
        <?php wp_nonce_field('advaipbl_admin_nonce_action', 'advaipbl_admin_nonce_action'); ?>
        <input type="text" name="ip_address" placeholder="<?php esc_attr_e('IP, CIDR, or Range (e.g., 1.2.3.0/24)', 'advanced-ip-blocker'); ?>" required style="width: 350px;">
        <button type="submit" class="button button-primary"><?php esc_html_e('Add to Whitelist', 'advanced-ip-blocker'); ?></button>
    </form>

    <h2><?php esc_html_e('IPs in Whitelist', 'advanced-ip-blocker'); ?></h2>

    <!-- Controles de filtros GET (fuera del formulario POST) -->
    <div class="tablenav top">
        <div class="alignleft actions">
            <form method="get" class="advaipbl-filters-form">
                <?php // phpcs:ignore WordPress.Security.NonceVerification.Recommended ?>
                <input type="hidden" name="page" value="<?php echo esc_attr( sanitize_text_field( wp_unslash( $_REQUEST['page'] ?? '' ) ) ); ?>">
                <input type="hidden" name="tab" value="ip_management">
                <input type="hidden" name="sub-tab" value="whitelist">
                <?php $this->plugin->render_per_page_selector($per_page); ?>
            </form>
        </div>
        <div class="alignleft actions">
            <button id="advaipbl-bulk-import-btn" class="button button-secondary"><?php esc_html_e('Bulk Import', 'advanced-ip-blocker'); ?></button>
            <button id="advaipbl-bulk-export-btn" class="button button-secondary"><?php esc_html_e('Export Whitelist', 'advanced-ip-blocker'); ?></button>
        </div>
        <div class="tablenav-pages">
            <span class="displaying-num"><?php /* translators: %s: The number of items per page. */ printf(esc_html(_n('%s item', '%s items', $total_items, 'advanced-ip-blocker')), esc_html(number_format_i18n($total_items))); ?></span>
            <?php $page_links = paginate_links(['base' => add_query_arg('paged', '%#%'), 'format' => '', 'total' => $total_pages, 'current' => $current_page]); if ($page_links) echo wp_kses_post($page_links); ?>
        </div>
        <br class="clear">
    </div>

    <!-- Formulario para Acciones en Lote -->
    <form id="advaipbl-whitelist-form" method="post">
        <input type="hidden" name="action_type" value="remove_whitelist_bulk">
        <?php wp_nonce_field('advaipbl_admin_nonce_action', 'advaipbl_admin_nonce_action'); ?>
        <div class="tablenav top">
             <div class="alignleft actions bulkactions">
                <label for="bulk-action-selector-top" class="screen-reader-text"><?php esc_html_e('Select bulk action', 'advanced-ip-blocker'); ?></label>
                <select name="bulk_action" id="bulk-action-selector-top">
                    <option value="-1"><?php esc_html_e('Bulk Actions', 'advanced-ip-blocker'); ?></option>
                    <option value="remove"><?php esc_html_e('Remove from Whitelist', 'advanced-ip-blocker'); ?></option>
                </select>
                <input type="submit" id="doaction" class="button action" value="<?php esc_attr_e('Apply', 'advanced-ip-blocker'); ?>">
            </div>
            <br class="clear">
        </div>

        <!-- Bulk Import Modal -->
        <div id="advaipbl-bulk-import-modal" class="advaipbl-modal-overlay" style="display:none;">
            <div class="advaipbl-modal-content">
                <span class="advaipbl-modal-close advaipbl-modal-cancel">&times;</span>
                <h2><?php esc_html_e('Bulk Import IPs to Whitelist', 'advanced-ip-blocker'); ?></h2>
                <div class="advaipbl-modal-body">
                    <p><?php esc_html_e('Enter IP addresses or CIDR ranges, one per line.', 'advanced-ip-blocker'); ?></p>
                    <textarea id="advaipbl-bulk-import-textarea" rows="10" style="width:100%;" placeholder="192.168.1.1&#10;10.0.0.0/24"></textarea>
                    
                    <p>
                        <label for="advaipbl-bulk-import-detail"><strong><?php esc_html_e('Reason / Detail (Required):', 'advanced-ip-blocker'); ?></strong></label>
                        <input type="text" id="advaipbl-bulk-import-detail" style="width:100%;" placeholder="<?php esc_attr_e('e.g., Office IPs, Monitoring Service', 'advanced-ip-blocker'); ?>">
                    </p>

                    <div id="advaipbl-bulk-import-results" style="margin-top: 10px; display:none;"></div>
                    
                    <div style="margin-top: 15px; text-align: right;">
                        <button type="button" class="button button-primary" id="advaipbl-process-bulk-import"><?php esc_html_e('Import IPs', 'advanced-ip-blocker'); ?></button>
                        <button type="button" class="button button-secondary advaipbl-modal-cancel"><?php esc_html_e('Close', 'advanced-ip-blocker'); ?></button>
                    </div>
                </div>
            </div>
        </div>

        <div class="advaipbl-table-responsive-wrapper">
            <table class="wp-list-table widefat striped">
                <thead>
                    <tr>
                        <td id="cb" class="manage-column column-cb check-column"><input id="cb-select-all-1" type="checkbox"></td>
                        <?php $this->plugin->print_log_sortable_header(__('IP / Location', 'advanced-ip-blocker'), 'ip', $orderby, $order); ?>
                        <?php $this->plugin->print_log_sortable_header(__('User', 'advanced-ip-blocker'), 'user', $orderby, $order); ?>
                        <?php $this->plugin->print_log_sortable_header(__('Details', 'advanced-ip-blocker'), 'detail', $orderby, $order); ?>
                        <?php $this->plugin->print_log_sortable_header(__('Added Since', 'advanced-ip-blocker'), 'timestamp', $orderby, $order); ?>
                        <th><?php esc_html_e('Actions', 'advanced-ip-blocker'); ?></th>
                    </tr>
                </thead>
                <tbody id="the-list">
                    <?php if (empty($items_for_page)) : ?>
                        <tr class="no-items"><td class="colspanchange" colspan="6"><?php esc_html_e('No IPs in the whitelist.', 'advanced-ip-blocker'); ?></td></tr>
                    <?php else: foreach ($items_for_page as $item) : ?>
                        <tr>
                            <th scope="row" class="check-column"><input type="checkbox" name="entries_to_process[]" value="<?php echo esc_attr($item['ip']); ?>"></th>
                            <td>
                                <strong><?php echo esc_html($item['ip']); ?></strong>
                                <?php
                                $location = $locations[$item['ip']] ?? null;
                                if ($location && !empty($location['country'])) {
                                    $location_parts = [];
                                    if (!empty($location['city'])) { $location_parts[] = $location['city']; }
                                    if (!empty($location['region'])) { $location_parts[] = $location['region']; }
                                    $location_parts[] = $location['country'];
                                    echo '<br><small style="color: #50575e;">' . esc_html(implode(', ', $location_parts)) . '</small>';
                                }
                                ?>
                            </td>
                            <td>
                                <?php
                                if (preg_match('/^Auto-whitelisted admin: (.*?) \((.*?)\)$/', $item['detail'], $matches)) {
                                    echo '<strong>' . esc_html($matches[1]) . '</strong>';
                                    echo '<br><small>' . esc_html($matches[2]) . '</small>';
                                }
                                ?>
                            </td>
                            <td><em><?php echo esc_html($item['detail']); ?></em></td>
                            <td><?php echo $item['timestamp'] > 0 ? esc_html(ADVAIPBL_Main::get_formatted_datetime($item['timestamp'])) : '...'; ?></td>
                            <td>
                                <form method="post" action="" class="advaipbl-remove-whitelist-form">
                                    <input type="hidden" name="action_type" value="remove_whitelist">
                                    <?php wp_nonce_field('advaipbl_admin_nonce_action','advaipbl_admin_nonce_action');?>
                                    <input type="hidden" name="ip_address" value="<?php echo esc_attr($item['ip']); ?>">
                                    <button type="submit" class="button advaipbl-remove-whitelist-button" data-ip-to-remove="<?php echo esc_attr($item['ip']); ?>">
                                        <?php esc_html_e('Remove', 'advanced-ip-blocker'); ?>
                                    </button>
                                </form>
                            </td>
                        </tr>
                    <?php endforeach; endif; ?>
                </tbody>
            </table>
        </div>
        
        <div class="tablenav bottom">
             <div class="alignleft actions bulkactions">
                <label for="bulk-action-selector-bottom" class="screen-reader-text"><?php esc_html_e('Select bulk action', 'advanced-ip-blocker'); ?></label>
                <select name="bulk_action2" id="bulk-action-selector-bottom">
                    <option value="-1"><?php esc_html_e('Bulk Actions', 'advanced-ip-blocker'); ?></option>
                    <option value="remove"><?php esc_html_e('Remove from Whitelist', 'advanced-ip-blocker'); ?></option>
                </select>
                <input type="submit" id="doaction2" class="button action" value="<?php esc_attr_e('Apply', 'advanced-ip-blocker'); ?>">
            </div>
            <div class="tablenav-pages">
                <span class="displaying-num"><?php /* translators: %s: The number of items per page. */ printf(esc_html(_n('%s item', '%s items', $total_items, 'advanced-ip-blocker')), esc_html(number_format_i18n($total_items))); ?></span>
                <?php if ($page_links) echo wp_kses_post($page_links); ?>
            </div>
            <br class="clear">
        </div>
    </form>
    <?php
}

/**
 * Muestra la nueva pestaña unificada de logs de seguridad.
 */
    public function display_security_log_tab() {
        // Añadimos 'endpoint_challenge' y el tipo implícito 'general' (para el log de activación) a la lista.
        // Aunque no podemos filtrar por el mensaje exacto, los usuarios podrán ver los eventos críticos de auditoría.
        $security_log_types = [
            'waf', 'rate_limit', 'asn', 'xmlrpc_block', 
            'honeypot', 'user_agent', 'geoblock', 
            '404', '403', 'login', 'threat_score',
			'abuseipdb', 'abuseipdb_challenge',
			'aib_network', 'aib_network_challenge',
            'signature_challenge', 'signature_flagged',
            'endpoint_challenge', 'geo_challenge', 'impersonation',
            'advanced_rule'
        ];
        $this->display_log_table_generic($security_log_types, ['critical', 'warning']);
    }

/**
 * Muestra la pestaña de logs generales (auditoría), restaurada a su formato original.
 */
public function display_general_log_tab() {
    if (empty($this->plugin->options['enable_logging'])) {
        echo '<div class="notice notice-info"><p>' . esc_html__('General event logging is disabled in the "Settings" tab.', 'advanced-ip-blocker') . '</p></div>';
        return;
    }
    
    // phpcs:disable WordPress.Security.NonceVerification.Recommended
    // phpcs:disable WordPress.Security.NonceVerification.Recommended
    $search_term = isset($_GET['s']) ? sanitize_text_field(wp_unslash($_GET['s'])) : '';
    $orderby = isset($_GET['orderby']) && in_array($_GET['orderby'], ['timestamp', 'level', 'ip', 'message'], true) ? sanitize_key($_GET['orderby']) : 'timestamp';
    $order = isset($_GET['order']) && in_array(strtolower($_GET['order']), ['asc', 'desc'], true) ? strtolower(sanitize_key($_GET['order'])) : 'desc';
    $current_page = isset($_GET['paged']) ? absint($_GET['paged']) : 1;
    $per_page = isset($_GET['advaipbl_per_page']) ? absint($_GET['advaipbl_per_page']) : 25;
    // phpcs:enable
    // phpcs:enable

    global $wpdb;
    $table_name = $wpdb->prefix . 'advaipbl_logs';
    
    $where_clauses = [$wpdb->prepare("log_type = %s", 'general')];
    if (!empty($search_term)) {
        $search_like = '%' . $wpdb->esc_like($search_term) . '%';
        $where_clauses[] = $wpdb->prepare("(ip LIKE %s OR message LIKE %s)", $search_like, $search_like);
    }
    $where_sql = implode(' AND ', $where_clauses);
    
    // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
    $total_items = $wpdb->get_var("SELECT COUNT(log_id) FROM $table_name WHERE $where_sql");
    $total_pages = ceil($total_items / $per_page);
    $offset = ($current_page - 1) * $per_page;
    // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
    $logs = $wpdb->get_results($wpdb->prepare("SELECT * FROM $table_name WHERE $where_sql ORDER BY " . esc_sql($orderby) . " " . esc_sql($order) . " LIMIT %d OFFSET %d", $per_page, $offset), ARRAY_A);
    
    ?>
    <h2><?php echo esc_html__('General System Event Log', 'advanced-ip-blocker'); ?></h2>
    
    <div class="tablenav top">
        <div class="alignleft actions bulkactions">
            <form method="get">
                <?php // phpcs:ignore WordPress.Security.NonceVerification.Recommended ?>
                <input type="hidden" name="page" value="<?php echo esc_attr( sanitize_text_field( wp_unslash( $_REQUEST['page'] ?? '' ) ) ); ?>">
                <input type="hidden" name="tab" value="logs">
                <input type="hidden" name="sub-tab" value="general_log">
                <?php $this->plugin->render_per_page_selector( $per_page ); ?>
                <input type="search" name="s" value="<?php echo esc_attr($search_term); ?>" placeholder="<?php esc_attr_e( 'Search by IP or message...', 'advanced-ip-blocker' ); ?>">
                <input type="submit" class="button" value="<?php esc_html_e('Search Logs', 'advanced-ip-blocker'); ?>">
            </form>
        </div>

        <div class="alignleft actions">
            <button type="button" id="advaipbl-open-clear-log-modal" class="button button-danger">
                <?php esc_html_e('Clear Logs...', 'advanced-ip-blocker'); ?>
            </button>
        </div>

        <div class="tablenav-pages">
            <span class="displaying-num"><?php /* translators: %s: The number of items per page. */ printf(esc_html(_n('%s item', '%s items', $total_items, 'advanced-ip-blocker')), esc_html(number_format_i18n($total_items))); ?></span>
            <?php $page_links = paginate_links(['base' => add_query_arg('paged', '%#%'), 'format' => '', 'total' => $total_pages, 'current' => $current_page]); if ($page_links) echo wp_kses_post($page_links); ?>
        </div>
        <br class="clear">
    </div>

    <div class="advaipbl-table-responsive-wrapper">
    <table class="widefat striped" style="margin-top:1em;">
        <thead>
            <tr>
                <?php $this->plugin->print_log_sortable_header(__('Date/Time', 'advanced-ip-blocker'), 'timestamp', $orderby, $order); ?>
                <?php $this->plugin->print_log_sortable_header(__('Level', 'advanced-ip-blocker'), 'level', $orderby, $order); ?>
                <?php $this->plugin->print_log_sortable_header(__('IP', 'advanced-ip-blocker'), 'ip', $orderby, $order); ?>
                <?php $this->plugin->print_log_sortable_header(__('Message', 'advanced-ip-blocker'), 'message', $orderby, $order); ?>
            </tr>
        </thead>
        <tbody>
            <?php if(empty($logs)) : ?>
                <tr><td colspan="4"><?php echo empty($search_term) ? esc_html__('The general log is empty.', 'advanced-ip-blocker') : esc_html__('No results found for your search.', 'advanced-ip-blocker'); ?></td></tr>
            <?php else: foreach($logs as $log) :
                $level = strtolower($log['level']);
                $color = '#646970';
                switch ($level) {
                    case 'info': $color = '#0073aa'; break;
                    case 'warning': $color = '#f59e0b'; break;
                    case 'error': $color = '#dc3232'; break;
                    case 'critical': $color = '#b91c1c'; break;
                }
                ?>
                <tr>
                    <td><?php echo esc_html(ADVAIPBL_Main::get_formatted_datetime($log['timestamp'])); ?></td>
                    <td><strong style="color:<?php echo esc_attr($color); ?>;"><?php echo esc_html(ucfirst($log['level'])); ?></strong></td>
                    <td><?php echo esc_html($log['ip']); ?></td>
                    <td><?php echo esc_html($log['message']); ?></td>
                </tr>
            <?php endforeach; endif; ?>
        </tbody>
    </table>
	</div>
    <?php
}

        /**
     * Muestra la tabla de estado del sistema de Puntuación de Amenaza (IP Trust Log).
     */
        public function display_ip_trust_log_tab() {
        global $wpdb;
        $table_name = $wpdb->prefix . 'advaipbl_ip_scores';		
        $is_enabled = !empty($this->plugin->options['enable_threat_scoring']);
        $settings_url = admin_url('admin.php?page=advaipbl_settings_page-settings&sub-tab=general_settings#section-ip_trust');
        ?>
        <div class="notice notice-info inline">
            <p>
                <?php
                $status_tag = sprintf(
                    '<span class="advaipbl-status-tag %s">%s</span>',
                    $is_enabled ? 'enabled' : 'disabled',
                    $is_enabled ? esc_html__('Active', 'advanced-ip-blocker') : esc_html__('Inactive', 'advanced-ip-blocker')
                );
                
                printf(
                    wp_kses(
                        /* translators: 1: Status tag (Active/Inactive), 2: Link to settings page. */
                        __('The Threat Scoring System is currently %1$s. You can change this in the <a href="%2$s">Settings</a>.', 'advanced-ip-blocker'),
                        [ 'span' => ['class' => true], 'a' => ['href' => []] ]
                    ),
					// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
                    $status_tag,
                    esc_url($settings_url)
                );
                ?>
            </p>
        </div>
        <?php

        // phpcs:disable WordPress.Security.NonceVerification.Recommended
        $search_term = isset($_GET['s']) ? sanitize_text_field(wp_unslash($_GET['s'])) : '';
        $orderby = isset($_GET['orderby']) && in_array($_GET['orderby'], ['ip', 'score', 'last_event_timestamp'], true) ? sanitize_key($_GET['orderby']) : 'score';
        $order = isset($_GET['order']) && in_array(strtolower($_GET['order']), ['asc', 'desc'], true) ? strtolower(sanitize_key($_GET['order'])) : 'desc';
        $current_page = isset($_GET['paged']) ? absint($_GET['paged']) : 1;
        $per_page = isset($_GET['advaipbl_per_page']) ? absint($_GET['advaipbl_per_page']) : 20;
        // phpcs:enable

        $where_clauses = ["score > 0"];
        if (!empty($search_term)) {
            $where_clauses[] = $wpdb->prepare("ip LIKE %s", '%' . $wpdb->esc_like($search_term) . '%');
        }
        $where_sql = implode(' AND ', $where_clauses);

        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $total_items = $wpdb->get_var("SELECT COUNT(id) FROM {$table_name} WHERE {$where_sql}");
        $total_pages = ceil($total_items / $per_page);
        $offset = ($current_page - 1) * $per_page;

        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $items = $wpdb->get_results($wpdb->prepare(
            // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
            "SELECT * FROM {$table_name} WHERE {$where_sql} ORDER BY " . esc_sql($orderby) . " " . esc_sql($order) . " LIMIT %d OFFSET %d",
            $per_page, $offset
        ), ARRAY_A);

        $ips_on_page = wp_list_pluck($items, 'ip');
        $locations = $this->plugin->session_manager->get_cached_locations($ips_on_page);
        $threshold = (int) ($this->plugin->options['threat_score_threshold'] ?? 100);
        ?>

        <h2><?php esc_html_e('IP Trust Log & Status', 'advanced-ip-blocker'); ?></h2>
        <p><?php esc_html_e('This table shows all IPs that currently have a threat score greater than zero. The score is automatically reduced over time if the IP remains inactive.', 'advanced-ip-blocker'); ?></p>
        
        <div class="tablenav top">
            <div class="alignleft actions bulkactions">
                <form method="get">
                    <?php // phpcs:ignore WordPress.Security.NonceVerification.Recommended ?>
                    <input type="hidden" name="page" value="<?php echo esc_attr( sanitize_text_field( wp_unslash( $_REQUEST['page'] ?? '' ) ) ); ?>">
                    <input type="hidden" name="tab" value="logs">
                    <input type="hidden" name="sub-tab" value="ip_trust_log">
                    <?php $this->plugin->render_per_page_selector($per_page); ?>
                    <input type="search" name="s" value="<?php echo esc_attr($search_term); ?>" placeholder="<?php esc_attr_e('Search by IP...', 'advanced-ip-blocker'); ?>">
                    <input type="submit" class="button" value="<?php esc_html_e('Search IP', 'advanced-ip-blocker'); ?>">
                </form>
            </div>
            
            <div class="alignleft actions">
                <form method="post" action="">
                    <input type="hidden" name="action_type" value="clear_all_threat_scores">
                    <?php wp_nonce_field('advaipbl_admin_nonce_action', 'advaipbl_admin_nonce_action'); ?>
                    <button type="submit" class="button button-danger advaipbl-confirm-action"
                            data-confirm-title="<?php esc_attr_e('Confirm Score Reset', 'advanced-ip-blocker'); ?>"
                            data-confirm-message="<?php esc_attr_e('Are you sure you want to reset all active threat scores to zero? This action will remove all IPs from this list but will NOT unblock them if they are in the main blocklist.', 'advanced-ip-blocker'); ?>"
                            data-confirm-button="<?php esc_attr_e('Yes, Reset All Scores', 'advanced-ip-blocker'); ?>">
                        <?php esc_html_e('Reset All Scores', 'advanced-ip-blocker'); ?>
                    </button>
                </form>
            </div>

            <div class="tablenav-pages">
                <span class="displaying-num"><?php /* translators: %s: The number of items per page. */ printf(esc_html(_n('%s item', '%s items', $total_items, 'advanced-ip-blocker')), esc_html(number_format_i18n($total_items))); ?></span>
                <?php $page_links = paginate_links(['base' => add_query_arg('paged', '%#%'), 'format' => '', 'total' => $total_pages, 'current' => $current_page]); if ($page_links) echo wp_kses_post($page_links); ?>
            </div>
            <br class="clear">
        </div>

        <div class="advaipbl-table-responsive-wrapper">
        <table class="wp-list-table widefat fixed striped">
            <thead>
                <tr>
                    <?php $this->plugin->print_log_sortable_header(__('IP / Location', 'advanced-ip-blocker'), 'ip', $orderby, $order); ?>
                    <?php $this->plugin->print_log_sortable_header(__('Current Score', 'advanced-ip-blocker'), 'score', $orderby, $order); ?>
                    <?php $this->plugin->print_log_sortable_header(__('Last Activity', 'advanced-ip-blocker'), 'last_event_timestamp', $orderby, $order); ?>
                    <th><?php esc_html_e('History & Last Event', 'advanced-ip-blocker'); ?></th>
                    <th><?php esc_html_e('Actions', 'advanced-ip-blocker'); ?></th>
                </tr>
            </thead>
            <tbody id="the-list">
                <?php if (empty($items)) : ?>
                    <tr class="no-items"><td class="colspanchange" colspan="5"><?php esc_html_e('No IPs currently have an active threat score.', 'advanced-ip-blocker'); ?></td></tr>
                <?php else: foreach ($items as $item) : ?>
                    <tr data-ip="<?php echo esc_attr($item['ip']); ?>">
                        <td>
                            <strong><?php echo esc_html($item['ip']); ?></strong>
                            <?php $location = $locations[$item['ip']] ?? null;
                            if ($location && !empty($location['country'])) {
                                $city = $location['city'] ?? '';
                                $country = $location['country'] ?? '';
                                echo '<br><small>' . esc_html(trim("$city, $country", ', ')) . '</small>';
                            } ?>
                        </td>
                        <td>
                            <?php
                            $score_percentage = $threshold > 0 ? min(100, ($item['score'] / $threshold) * 100) : 100;
                            $progress_color = $score_percentage > 80 ? '#dc3232' : ($score_percentage > 50 ? '#f59e0b' : '#0073aa');
                            ?>
                            <strong><?php echo esc_html($item['score'] . ' / ' . $threshold); ?></strong>
                            <div style="background-color: #e0e0e0; border-radius: 3px; height: 8px; overflow: hidden;">
                                <div style="width: <?php echo esc_attr($score_percentage); ?>%; background-color: <?php echo esc_attr($progress_color); ?>; height: 100%;"></div>
                            </div>
                        </td>
                        <td>
                            <?php echo esc_html(ADVAIPBL_Main::get_formatted_datetime($item['last_event_timestamp'])); ?>
                            <br><small><?php echo esc_html(human_time_diff($item['last_event_timestamp'])) . ' ' . esc_html__('ago', 'advanced-ip-blocker'); ?></small>
                        </td>
                        <td>
                            <?php
                            $log_details = json_decode($item['log_details'], true);
                            if (is_array($log_details) && !empty($log_details)) {
                                $last_event = $log_details[0];
                                echo '<strong>' . esc_html(ucfirst(str_replace('_', ' ', $last_event['event']))) . '</strong>';
                                echo ' (+ ' . esc_html($last_event['points']) . ' ' . esc_html__('points', 'advanced-ip-blocker') . ')';
                            }
                            ?>
                            <br>
                            <button class="button button-small advaipbl-view-score-history"><?php esc_html_e('View History', 'advanced-ip-blocker'); ?></button>
                        </td>
                        <td>
                            <button class="button button-secondary advaipbl-reset-score" title="<?php esc_attr_e('Reset Score to 0', 'advanced-ip-blocker'); ?>">
                                <span class="dashicons dashicons-image-rotate"></span>
                            </button>
                            <button class="button button-secondary advaipbl-add-whitelist-ajax" data-ip="<?php echo esc_attr($item['ip']); ?>" data-detail="<?php esc_attr_e('Added from IP Trust Log', 'advanced-ip-blocker'); ?>" title="<?php esc_attr_e('Add to Whitelist', 'advanced-ip-blocker'); ?>">
                                <span class="dashicons dashicons-yes"></span>
                            </button>
                        </td>
                    </tr>
                <?php endforeach; endif; ?>
            </tbody>
        </table>
        </div>
        <div id="advaipbl-score-history-modal" class="advaipbl-modal-overlay" style="display: none;">
            <div class="advaipbl-modal-content" style="max-width: 700px;">
                <h3 class="advaipbl-modal-title"><?php esc_html_e('Threat Score History for', 'advanced-ip-blocker'); ?> <span class="modal-ip-placeholder"></span></h3>
                <div class="advaipbl-modal-body">
                    <div class="advaipbl-loader-wrapper" style="text-align: center; padding: 20px;">
                        <div class="advaipbl-loader"></div>
                    </div>
                    <div class="history-content" style="display: none; max-height: 400px; overflow-y: auto;"></div>
                </div>
                <div class="advaipbl-modal-footer">
                    <button class="button advaipbl-modal-cancel"><?php esc_html_e( 'Close', 'advanced-ip-blocker' ); ?></button>
                </div>
            </div>
        </div>
        <?php
    }

    public function display_log_table_generic($log_types, $levels_to_show = ['critical']) {
        $is_unified_log = is_array($log_types);
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $current_filter = isset($_GET['filter_log_type']) ? sanitize_key($_GET['filter_log_type']) : 'all';
        
        $title = '';
        $current_sub_tab = '';
        if ($is_unified_log) {
            $title = __('Security Log', 'advanced-ip-blocker');
            $current_sub_tab = 'security_log';
        } else {
            $titles = [ 'general' => __('General System Event Log', 'advanced-ip-blocker'), 'wp_cron' => __('WP-Cron Execution Log', 'advanced-ip-blocker'), ];
            $title = $titles[$log_types] ?? ucfirst($log_types) . ' Log';
            $current_sub_tab = ($log_types === 'general') ? 'general_log' : $log_types . '_logs';
        }

        // phpcs:disable WordPress.Security.NonceVerification.Recommended
        $search_term = isset($_GET['s']) ? sanitize_text_field(wp_unslash($_GET['s'])) : '';
        $orderby = isset($_GET['orderby']) && in_array($_GET['orderby'], ['timestamp', 'ip', 'log_type', 'message'], true) ? sanitize_key($_GET['orderby']) : 'timestamp';
        $order = isset($_GET['order']) && in_array(strtolower($_GET['order']), ['asc', 'desc'], true) ? strtolower(sanitize_key($_GET['order'])) : 'desc';
        $current_page = isset($_GET['paged']) ? absint($_GET['paged']) : 1;
        $per_page = isset($_GET['advaipbl_per_page']) ? absint($_GET['advaipbl_per_page']) : 20;
        // phpcs:enable

        global $wpdb;
        $table_name = $wpdb->prefix . 'advaipbl_logs';
        $where_clauses = [];

        $level_placeholders = implode(', ', array_fill(0, count($levels_to_show), '%s'));
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare
        $where_clauses[] = $wpdb->prepare("level IN ({$level_placeholders})", ...$levels_to_show);

        if ($is_unified_log) {
            $types_to_query = ($current_filter !== 'all' && in_array($current_filter, $log_types)) ? [$current_filter] : $log_types;
            if (!empty($types_to_query)) {
                $placeholders = implode(', ', array_fill(0, count($types_to_query), '%s'));
                // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare
                $where_clauses[] = $wpdb->prepare("log_type IN ({$placeholders})", ...$types_to_query);
            }
        } else {
            $where_clauses[] = $wpdb->prepare("log_type = %s", $log_types);
        }
        if (!empty($search_term)) {
            $search_like = '%' . $wpdb->esc_like($search_term) . '%';
            $where_clauses[] = $wpdb->prepare("(ip LIKE %s OR details LIKE %s OR message LIKE %s)", $search_like, $search_like, $search_like);
        }
        
        $where_sql = implode(' AND ', $where_clauses);
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $total_items = $wpdb->get_var("SELECT COUNT(log_id) FROM $table_name WHERE $where_sql");
        $total_pages = ceil($total_items / $per_page);
        $offset = ($current_page - 1) * $per_page;
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $logs = $wpdb->get_results($wpdb->prepare("SELECT * FROM $table_name WHERE $where_sql ORDER BY " . esc_sql($orderby) . " " . esc_sql($order) . " LIMIT %d OFFSET %d", $per_page, $offset), ARRAY_A);
    ?>
    <h2><?php echo esc_html($title); ?></h2>
    
        <div class="tablenav top">
        <div class="alignleft actions bulkactions">
            <form method="get" class="advaipbl-filters-form">
                <?php // phpcs:ignore WordPress.Security.NonceVerification.Recommended ?>
                <input type="hidden" name="page" value="<?php echo esc_attr( sanitize_text_field( wp_unslash( $_REQUEST['page'] ?? '' ) ) ); ?>"><input type="hidden" name="tab" value="logs"><input type="hidden" name="sub-tab" value="<?php echo esc_attr($current_sub_tab); ?>">
                <?php $this->plugin->render_per_page_selector( $per_page ); ?>
                <?php if ($is_unified_log) : ?>
                    <select id="advaipbl-log-filter" name="filter_log_type" class="advaipbl-log-filter">
                        <option value="all" <?php selected($current_filter, 'all'); ?>><?php esc_html_e('All Security Events', 'advanced-ip-blocker'); ?></option>
                        <?php $block_type_definitions = $this->plugin->get_all_block_type_definitions(); foreach ($log_types as $type) : $label = $block_type_definitions[$type]['label'] ?? ucwords(str_replace('_', ' ', $type)); ?>
                            <option value="<?php echo esc_attr($type); ?>" <?php selected($current_filter, $type); ?>><?php echo esc_html($label); ?></option>
                        <?php endforeach; ?>
                    </select>
                <?php endif; ?>
                <input type="search" name="s" value="<?php echo esc_attr($search_term); ?>" placeholder="<?php esc_attr_e( 'Search by IP, etc.', 'advanced-ip-blocker' ); ?>"><input type="submit" class="button" value="<?php esc_html_e('Search / Filter', 'advanced-ip-blocker'); ?>">
            </form>
        </div>
        <div class="alignleft actions">
            <?php if ($is_unified_log) : ?><button type="button" id="advaipbl-open-clear-log-modal" class="button button-danger"><?php esc_html_e('Clear Log...', 'advanced-ip-blocker'); ?></button>
            <?php elseif ($log_types === 'wp_cron' || $log_types === 'general') : ?><form method="post" action=""><input type="hidden" name="action_type" value="clear_specific_logs_single"><input type="hidden" name="log_type_to_clear" value="<?php echo esc_attr($log_types); ?>"><?php wp_nonce_field('advaipbl_admin_nonce_action','advaipbl_admin_nonce_action'); ?><?php $confirm_message = sprintf( /* translators: $s: Logs Type */ __( 'Are you sure you want to delete all %s logs?', 'advanced-ip-blocker' ), esc_attr( strtoupper( $log_types ) ) ); ?><button type="submit" class="button button-danger advaipbl-confirm-action" data-confirm-title="<?php esc_attr_e( 'Confirm Log Deletion', 'advanced-ip-blocker' ); ?>" data-confirm-message="<?php echo esc_attr( $confirm_message ); ?>" data-confirm-button="<?php esc_attr_e( 'Yes, Delete Logs', 'advanced-ip-blocker' ); ?>"><?php esc_html_e('Clear this Log', 'advanced-ip-blocker'); ?></button></form>
            <?php endif; ?>
        </div>
        <div class="tablenav-pages">
            <span class="displaying-num"><?php /* translators: %s: The number of items per page. */ printf(esc_html(_n('%s item', '%s items', $total_items, 'advanced-ip-blocker')), esc_html(number_format_i18n($total_items))); ?></span>
            <?php $page_links = paginate_links(['base' => add_query_arg('paged', '%#%'), 'format' => '', 'total' => $total_pages, 'current' => $current_page]); if ($page_links) echo wp_kses_post($page_links); ?>
        </div>
        <br class="clear">
    </div>
     
	<div class="advaipbl-table-responsive-wrapper">
    <table class="widefat striped" style="margin-top:1em;">
        <thead>
            <tr>
                <?php $this->plugin->print_log_sortable_header(__('Date/Time', 'advanced-ip-blocker'), 'timestamp', $orderby, $order); ?>
                <?php $this->plugin->print_log_sortable_header(__('IP', 'advanced-ip-blocker'), 'ip', $orderby, $order); ?>
                <?php if ($is_unified_log) : ?><?php $this->plugin->print_log_sortable_header(__('Type', 'advanced-ip-blocker'), 'log_type', $orderby, $order); ?><?php endif; ?>
                <th><?php esc_html_e('Method', 'advanced-ip-blocker'); ?></th>
                <th><?php esc_html_e('Trigger / Details', 'advanced-ip-blocker'); ?></th>
                <th style="width: 30%;"><?php esc_html_e('User Agent', 'advanced-ip-blocker'); ?></th>
                <th><?php esc_html_e('Actions', 'advanced-ip-blocker'); ?></th>
            </tr>
        </thead>
                <tbody>
            <?php $colspan = $is_unified_log ? 7 : 6;
            if (empty($logs)): ?>
                <tr><td colspan="<?php echo esc_attr($colspan); ?>"><?php esc_html_e('No log entries found for the current filter.', 'advanced-ip-blocker'); ?></td></tr>
            <?php else: 
                foreach ($logs as $entry): 
                    $details = json_decode($entry['details'], true) ?: [];
                    $user_agent_string = $details['user_agent'] ?? 'N/A';
                    $log_type = $entry['log_type'];
            ?>
                <tr>
                    <td>
                        <?php echo esc_html(ADVAIPBL_Main::get_formatted_datetime($entry['timestamp'])); ?>
                        <?php
                        if ('critical' === $entry['level'] && 'signature_flagged' !== $log_type) {
                            $duration_minutes = 0;
                            
                            // CRITICAL FIX: Prioritize explicit duration from details (e.g. from Impersonation or Advanced Rules)
                            if (isset($details['duration_seconds'])) {
                                $duration_minutes = round((int)$details['duration_seconds'] / 60);
                            } 
                            // Fallback to global options if not in details (legacy support)
                            elseif (isset($this->plugin->options['duration_' . $log_type])) {
                                $duration_minutes = (int) $this->plugin->options['duration_' . $log_type];    
                            }

                            $duration_text = '';
                            if ($duration_minutes <= 0) {
                                $duration_text = __('Permanent', 'advanced-ip-blocker');
                            } else {
                                /* translators: %d: The number of minutes for a block duration. */
                                $duration_text = sprintf(esc_html__('%d min', 'advanced-ip-blocker'), $duration_minutes);
                            }
                            echo '<br><strong style="color: #c00;">' . esc_html__('Blocked:', 'advanced-ip-blocker') . '</strong> ' . esc_html($duration_text);
                        }
                        ?>
                    </td>
                    <td>
    <?php echo esc_html($entry['ip']); ?>
    <?php
    // Mostramos la ubicación siempre que esté disponible en los detalles del log, sin importar el nivel.
    if ( ! empty($details['country']) ) {
        $location_parts = [];
        if ( ! empty($details['city']) ) { $location_parts[] = esc_html($details['city']); }
        
        $country_str = esc_html($details['country']);
        if ( ! empty($details['country_code']) ) {
            $country_str .= ' (' . esc_html($details['country_code']) . ')';
        }
        $location_parts[] = $country_str;
        
        // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
        echo '<br><small style="color: #50575e;">' . implode(', ', $location_parts) . '</small>';
    }
    ?>
</td>
                    <?php if ($is_unified_log) : ?><td><strong><?php echo esc_html($this->plugin->get_all_block_type_definitions()[$log_type]['label'] ?? ucwords(str_replace('_', ' ', $log_type))); ?></strong></td><?php endif; ?>
                    <td><?php echo ('signature_flagged' === $log_type) ? '-' : esc_html($details['method'] ?? 'N/A'); ?></td>
                    <td style="word-break: break-all;">
                        <?php
                        $detail_display = '';
                        $uri = esc_html($details['uri'] ?? ($details['url'] ?? ''));

                        switch ($log_type) {
                            case 'login':
                                $detail_display = '<strong>' . esc_html__('User:', 'advanced-ip-blocker') . '</strong> ' . esc_html($details['username'] ?? 'N/A');
                                break;
                            case 'waf':
                                $detail_display = '<strong>' . esc_html__('Rule:', 'advanced-ip-blocker') . '</strong> ' . esc_html($details['rule'] ?? 'N/A');
                                if (!empty($uri)) { $detail_display .= '<br><small>' . $uri . '</small>'; }
                                break;
                            case 'asn':
                                $detail_display = esc_html($details['asn_number'] ?? 'N/A') . ' (' . esc_html($details['asn_name'] ?? '') . ')';
                                if (!empty($details['source'])) { $detail_display .= ' - <strong>' . __('Source:', 'advanced-ip-blocker') . '</strong> ' . esc_html($details['source']); }
                                if (!empty($uri)) { $detail_display .= '<br><small>' . $uri . '</small>'; }
								break;
                            case 'threat_score':
                                $detail_display = esc_html($entry['message']);
								if (!empty($uri)) { $detail_display .= '<br><small>' . $uri . '</small>'; }
                                break;
							case 'advanced_rule':
    $level = $entry['level'];
    $rule_name_html = '<strong>' . esc_html__('Rule:', 'advanced-ip-blocker') . '</strong> ' . esc_html($details['rule_name'] ?? 'N/A');
    
    if ($level === 'critical') { // Block
        $detail_display = $rule_name_html;
    } elseif ($level === 'warning') { // Challenge
        $detail_display = $rule_name_html;
    } else { // Score (info)
        $points = $details['points_added'] ?? 0;
        $detail_display = $rule_name_html . ' (+ ' . esc_html($points) . ' ' . esc_html__('points', 'advanced-ip-blocker') . ')';
    }
    
    if (!empty($uri)) {
        $detail_display .= '<br><small>' . $uri . '</small>';
    }
    break;	
							case 'geo_challenge':
                                $country_name = esc_html($details['country'] ?? 'N/A');
                                $detail_display = '<strong>' . esc_html__('Country:', 'advanced-ip-blocker') . '</strong> ' . $country_name;
                                if (!empty($uri)) {
                                    $detail_display .= '<br><small>' . $uri . '</small>';
                                }
                                break;
							case 'signature_challenge':
                                $detail_display = esc_html($entry['message']);
								if (!empty($uri)) { $detail_display .= '<br><small>' . $uri . '</small>'; }
                                break;
							case 'signature_flagged':
                                $hash = $details['signature_hash'] ?? 'N/A';
                                $short_hash = substr($hash, 0, 12) . '...';
                                $detail_display = '<strong>' . esc_html__('Signature:', 'advanced-ip-blocker') . '</strong> <code title="' . esc_attr($hash) . '">' . esc_html($short_hash) . '</code>';
                                $detail_display .= '<br><small>' . esc_html($entry['message']) . '</small>';
                                break;
                            case 'endpoint_challenge':
                                $reason = $details['reason'] ?? $entry['message'];
                                $detail_display = '<strong>' . esc_html($reason) . '</strong>';
                                if (!empty($uri)) {
                                    $detail_display .= '<br><small>' . $uri . '</small>';
                                }
                                break;
                            case '404':
                            case '403':
                            case 'honeypot':
                            default:
                                $detail_display = !empty($uri) ? $uri : esc_html($entry['message']);
                                break;
                        }
                        echo wp_kses_post($detail_display);
                        ?>
                    </td>
                    <td style="word-break: break-all; font-family: monospace; font-size: 12px;"><?php echo esc_html($user_agent_string); ?></td>
                    <td>
                        <?php if (in_array($log_type, ['signature_challenge', 'signature_flagged'], true)) : ?>
                            <?php 
                            $manage_signatures_url = admin_url('admin.php?page=advaipbl_settings_page&tab=ip_management&sub-tab=blocked_signatures');
                            ?>
                            <a href="<?php echo esc_url($manage_signatures_url); ?>" class="button button-secondary">
                                <?php esc_html_e('Manage Signature', 'advanced-ip-blocker'); ?>
                            </a>
                        <?php else: ?>
                            <form method="post" action="" style="margin-bottom: 5px;"><input type="hidden" name="action_type" value="add_manual_block"><?php wp_nonce_field('advaipbl_admin_nonce_action','advaipbl_admin_nonce_action'); ?><input type="hidden" name="ip_address" value="<?php echo esc_attr($entry['ip']);?>"><button type="submit" class="button button-small"><?php esc_html_e('Block', 'advanced-ip-blocker'); ?></button></form>
                            <form method="post" action=""><input type="hidden" name="action_type" value="add_whitelist"><?php wp_nonce_field('advaipbl_admin_nonce_action','advaipbl_admin_nonce_action'); ?><input type="hidden" name="ip_address" value="<?php echo esc_attr($entry['ip']);?>"><button type="submit" class="button button-small"><?php esc_html_e('Whitelist', 'advanced-ip-blocker'); ?></button></form>
                        <?php endif; ?>
                    </td>
                </tr>
            <?php endforeach; endif; ?>
        </tbody>
    </table>
	</div>
	
    <?php
}
public function display_credits_tab() {
        $plugin_data = get_plugin_data( ADVAIPBL_PLUGIN_FILE );
        $plugin_name = $plugin_data['Name'] ?? 'Advanced IP Blocker';
        ?>
        <div class="wrap">
            
            <h2><?php esc_html_e('About Advanced IP Blocker', 'advanced-ip-blocker'); ?></h2>
            <div class="advaipbl-card">
                <h3><?php echo esc_html($plugin_name); ?></h3>
                <p><strong><?php esc_html_e('Version:', 'advanced-ip-blocker'); ?></strong> <?php echo esc_html(ADVAIPBL_VERSION); ?></p>
                <p><?php esc_html_e('Thank you for using our plugin! This tool helps protect your WordPress site by automatically blocking malicious IPs based on their behavior.', 'advanced-ip-blocker'); ?></p>
                
                <h4><?php esc_html_e('Key Features Overview:', 'advanced-ip-blocker'); ?></h4>
                <div class="advaipbl-features-grid">
                    <div class="advaipbl-feature-item"><strong><?php esc_html_e('Site Health & Vulnerability Scanner:', 'advanced-ip-blocker'); ?></strong> <?php esc_html_e('Audit your WordPress environment for weaknesses and check installed plugins against a database of 30,000+ known security vulnerabilities.', 'advanced-ip-blocker'); ?></div>
                    <div class="advaipbl-feature-item"><strong><?php esc_html_e('Community Defense Network:', 'advanced-ip-blocker'); ?></strong> <?php esc_html_e('A global collaborative network that shares verified attack data to block emerging threats in real-time across all participating sites.', 'advanced-ip-blocker'); ?></div>
				    <div class="advaipbl-feature-item"><strong><?php esc_html_e('Cloud Edge Defense (Cloudflare):', 'advanced-ip-blocker'); ?></strong> <?php esc_html_e('Connects your site to the Cloudflare Firewall to block malicious IPs at the network edge, preventing them from ever reaching your server. Zero load protection.', 'advanced-ip-blocker'); ?></div>
                    <div class="advaipbl-feature-item"><strong><?php esc_html_e('Server-Level Firewall (.htaccess):', 'advanced-ip-blocker'); ?></strong> <?php esc_html_e('Writes blocking rules directly to your server configuration for extreme performance. Also hardens sensitive files like wp-config.php.', 'advanced-ip-blocker'); ?></div>
					<div class="advaipbl-feature-item"><strong><?php esc_html_e('AbuseIPDB Integration:', 'advanced-ip-blocker'); ?></strong> <?php esc_html_e('Proactively checks visitor IP reputation against a global crowdsourced database of hackers and spammers, blocking bad actors on their very first request.', 'advanced-ip-blocker'); ?></div>
					<div class="advaipbl-feature-item"><strong><?php esc_html_e('IP Trust & Threat Scoring System:', 'advanced-ip-blocker'); ?></strong> <?php esc_html_e('An advanced defense that assigns threat points for malicious actions, blocking IPs based on their cumulative score for more accurate, context-aware security.', 'advanced-ip-blocker'); ?></div>
                    <div class="advaipbl-feature-item"><strong><?php esc_html_e('Attack Signature Engine:', 'advanced-ip-blocker'); ?></strong> <?php esc_html_e('A proactive defense that detects distributed botnet attacks by analyzing request "fingerprints" and stops them with an invisible JavaScript challenge.', 'advanced-ip-blocker'); ?></div>
                    <div class="advaipbl-feature-item"><strong><?php esc_html_e('Endpoint Lockdown Mode:', 'advanced-ip-blocker'); ?></strong> <?php esc_html_e('Automatically shields critical endpoints like wp-login.php and xmlrpc.php with a challenge mode during sustained distributed attacks, preventing server overload.', 'advanced-ip-blocker'); ?></div>
                    <div class="advaipbl-feature-item"><strong><?php esc_html_e('Two-Factor Authentication (2FA):', 'advanced-ip-blocker'); ?></strong> <?php esc_html_e('Secure user accounts with TOTP authentication, backup codes, and role enforcement. Fully manageable via UI and WP-CLI.', 'advanced-ip-blocker'); ?></div>
                    <div class="advaipbl-feature-item"><strong><?php esc_html_e('Security Dashboard:', 'advanced-ip-blocker'); ?></strong> <?php esc_html_e('Get a real-time visual overview of all threats with interactive charts and a live attack map.', 'advanced-ip-blocker'); ?></div>
                    <div class="advaipbl-feature-item"><strong><?php esc_html_e('High-Performance Geolocation:', 'advanced-ip-blocker'); ?></strong> <?php esc_html_e('Choose between real-time APIs or a high-performance local MaxMind database for IP lookups, ensuring speed and reliability.', 'advanced-ip-blocker'); ?></div>
                    <div class="advaipbl-feature-item"><strong><?php esc_html_e('Web Application Firewall (WAF):', 'advanced-ip-blocker'); ?></strong> <?php esc_html_e('Proactively block malicious requests (SQLi, XSS, etc.) with customizable rules.', 'advanced-ip-blocker'); ?></div>
                    <div class="advaipbl-feature-item"><strong><?php esc_html_e('Rate Limiting:', 'advanced-ip-blocker'); ?></strong> <?php esc_html_e('Prevent DoS and brute-force attacks by limiting request frequency.', 'advanced-ip-blocker'); ?></div>
                    <div class="advaipbl-feature-item"><strong><?php esc_html_e('Country & ASN Blocking:', 'advanced-ip-blocker'); ?></strong> <?php esc_html_e('Block traffic from entire countries or networks (ASNs), with support for the Spamhaus list and a new ASN Whitelist feature.', 'advanced-ip-blocker'); ?></div>
                    <div class="advaipbl-feature-item"><strong><?php esc_html_e('Advanced Login Protection:', 'advanced-ip-blocker'); ?></strong> <?php esc_html_e('Harden your login page by disabling user enumeration, protecting XML-RPC, and restricting access to whitelisted IPs.', 'advanced-ip-blocker'); ?></div>
                </div>
            </div>

            <h2 style="margin-top: 40px;"><?php esc_html_e('Support This Plugin', 'advanced-ip-blocker'); ?></h2>
            <div class="advaipbl-card">
                 <p><?php esc_html_e('If you find this plugin useful, please consider supporting its development. Your donation helps keep the project alive and ad-free. Thank you!', 'advanced-ip-blocker'); ?></p>
                <div style="display: flex; flex-wrap: wrap; gap: 40px; align-items: center; margin-top: 20px;">
                    <div>
                        <stripe-buy-button
                            buy-button-id="buy_btn_1RaKehINpxSnWCEmchYRAa51"
                            publishable-key="pk_live_51RaIn8INpxSnWCEmruyFaKF1LquLWcjRN3huLYpvWq5WvVxf50ZyX50OF7PI6tkIUGwNeINduiIJxJzC9zxFHkOL00X3REvrtt"
                        ></stripe-buy-button>
                    </div>
                    <div>
                       <h2><?php esc_html_e('You are free to choose the amount you donate.', 'advanced-ip-blocker'); ?></h2>
                        <p><strong><?php esc_html_e('Other ways to support:', 'advanced-ip-blocker'); ?></strong></p>
                        <ul style="list-style: disc; padding-left: 20px;">
                            <li><a href="https://donate.stripe.com/bJe00kaIP89O1wFfargUM00" target="_blank" rel="noopener">Stripe</a></li>
                            <li><strong><?php esc_html_e('Bitcoin (BTC):', 'advanced-ip-blocker'); ?></strong> <code style="background: #f0f0f1; padding: 2px 4px; border-radius: 3px;">bc1qxfsmpqk0q7an82ckm7380pzpsea2sa294824lg</code></li>
                            <li><strong><?php esc_html_e('Ethereum (ETH):', 'advanced-ip-blocker'); ?></strong> <code style="background: #f0f0f1; padding: 2px 4px; border-radius: 3px;">0xAF8CC1B71EAbF5dffDa2aF58AEF43b2559163284</code></li>
                        </ul>
                    </div>
                </div>
            </div>

            <h2 style="margin-top: 40px;"><?php esc_html_e('WP-CLI Interface', 'advanced-ip-blocker'); ?></h2>
            <div class="advaipbl-card">
                <p><?php esc_html_e('This plugin is fully manageable via the WordPress command line. This allows developers and system administrators to automate tasks and manage the plugin remotely.', 'advanced-ip-blocker'); ?></p>
                <details style="margin-top: 10px; border: 1px solid #c3c4c7; padding: 10px; background-color: #f9f9f9;">
                    <summary style="cursor: pointer; font-weight: bold;"><?php esc_html_e('View Available Commands', 'advanced-ip-blocker'); ?></summary>
                    <pre style="background: #fff; border: 1px solid #ddd; padding: 15px; white-space: pre-wrap; word-wrap: break-word; font-size: 12px;"><code>
# General Help
wp help advaipbl

# IP Management
wp advaipbl block &lt;ip&gt; [--reason=&lt;reason&gt;]
wp advaipbl unblock &lt;ip&gt;
wp advaipbl whitelist &lt;add|remove|list&gt; [&lt;ip&gt;]

# Threat Scoring & Signatures
wp advaipbl score &lt;list|get|reset|decay-run&gt; [--ip=&lt;ip&gt;]
wp advaipbl signature &lt;list|delete|whitelist&gt; [--hash=&lt;hash&gt;]
wp advaipbl signature-analyze

# Geolocation, ASN & WAF
wp advaipbl geoblock &lt;add|remove|list&gt; &lt;country_code&gt;
wp advaipbl asn &lt;add|remove|list&gt; &lt;asn&gt;
wp advaipbl asn-whitelist &lt;add|remove|list&gt; &lt;asn&gt;
wp advaipbl waf &lt;add|remove|list&gt; [&lt;rule&gt;] [--from-file=&lt;file&gt;]

# User & Session Management
wp advaipbl session &lt;list|terminate&gt; [--user-id=&lt;id&gt;]
wp advaipbl 2fa &lt;status|reset&gt; &lt;user&gt;

# System & Config
wp advaipbl log &lt;list|clear&gt; [--type=&lt;type&gt;] [--count=&lt;number&gt;]
wp advaipbl config &lt;get|set&gt; [&lt;key&gt;] [&lt;value&gt;]
wp advaipbl provider &lt;list|set|set_key|remove_key&gt;
wp advaipbl spamhaus-update
</code></pre>
                </details>
            </div>

            <?php /* translators: Header for the support section */ ?>
            <h2 style="margin-top: 40px;"><?php esc_html_e('Support', 'advanced-ip-blocker'); ?></h2>
            <div class="advaipbl-card">
                <div style="display: flex; flex-wrap: wrap; gap: 20px; align-items: center;">
                    <div style="flex: 1; min-width: 250px;">
                        <h3><?php esc_html_e('Official Website', 'advanced-ip-blocker'); ?></h3>
                        <p><?php esc_html_e('Visit our official website for documentation, advanced guides, and more information about the plugin.', 'advanced-ip-blocker'); ?></p>
                        <a href="https://advaipbl.com/" target="_blank" rel="noopener" class="button button-primary"><?php esc_html_e('Visit advaipbl.com', 'advanced-ip-blocker'); ?></a>
                    </div>
                    <div style="flex: 1; min-width: 250px;">
                        <h3><?php esc_html_e('Need Help?', 'advanced-ip-blocker'); ?></h3>
                        <p><?php esc_html_e('If you have encountered a bug or have a question, please open a support ticket on the WordPress.org forums.', 'advanced-ip-blocker'); ?></p>
                        <a href="https://wordpress.org/support/plugin/advanced-ip-blocker/" target="_blank" rel="noopener" class="button button-secondary"><?php esc_html_e('Open Support Ticket', 'advanced-ip-blocker'); ?></a>
                    </div>
                </div>
            </div>

            <h2 style="margin-top: 40px;"><?php esc_html_e('Credits and Attributions', 'advanced-ip-blocker'); ?></h2>
            <div class="advaipbl-card">
                <p><strong><?php esc_html_e('Included Libraries & Services', 'advanced-ip-blocker'); ?></strong></p>
                <ul>
                    <li><a href="https://www.maxmind.com" target="_blank" rel="noopener">MaxMind GeoLite2</a> - <?php esc_html_e('For local database geolocation.', 'advanced-ip-blocker'); ?></li>
                    <li><a href="https://www.spamhaus.org/drop/" target="_blank" rel="noopener">Spamhaus ASN DROP List</a> - <?php esc_html_e('For automated blocking of malicious networks.', 'advanced-ip-blocker'); ?></li>
                    <li><a href="https://www.chartjs.org/" target="_blank" rel="noopener">Chart.js</a>, <a href="https://leafletjs.com/" target="_blank" rel="noopener">Leaflet.js</a> & <a href="https://github.com/Leaflet/Leaflet.markercluster" target="_blank" rel="noopener">Leaflet.markercluster</a> - <?php esc_html_e('For the interactive Security Dashboard.', 'advanced-ip-blocker'); ?></li>
                    <li><a href="https://www.openstreetmap.org/copyright" target="_blank" rel="noopener">OpenStreetMap contributors</a> &amp; <a href="https://carto.com/attributions" target="_blank" rel="noopener">CARTO</a> - <?php esc_html_e('For the Dashboard map tiles.', 'advanced-ip-blocker'); ?></li>
                    <li><a href="https://github.com/RobThree/TwoFactorAuth" target="_blank" rel="noopener">RobThree/TwoFactorAuth</a> - <?php esc_html_e('The core library powering our 2FA functionality.', 'advanced-ip-blocker'); ?></li>
                    <li><a href="https://select2.org/" target="_blank" rel="noopener">Select2</a> - <?php esc_html_e('For the user-friendly country selector.', 'advanced-ip-blocker'); ?></li>
                    <li><a href="https://www.abuseipdb.com/" target="_blank" rel="noopener">AbuseIPDB</a> - <?php esc_html_e('For crowdsourced IP reputation checking.', 'advanced-ip-blocker'); ?></li>
                    <li><a href="https://www.wordfence.com/intelligence-documentation/" target="_blank" rel="noopener">Wordfence Intelligence</a> - <?php esc_html_e('For vulnerability database (production).', 'advanced-ip-blocker'); ?></li>
                </ul>
                <p><strong><?php esc_html_e('Geolocation API Providers', 'advanced-ip-blocker'); ?></strong></p>
                <ul>
                    <li><a href="https://ip-api.com/" target="_blank" rel="noopener">ip-api.com</a>, <a href="https://ipinfo.io/" target="_blank" rel="noopener">ipinfo.io</a>, <a href="https://ipapi.com/" target="_blank" rel="noopener">ipapi.com</a>, <a href="https://ipstack.com/" target="_blank" rel="noopener">ipstack.com</a>, and <a href="http://geoiplookup.net/" target="_blank" rel="noopener">geoiplookup.net</a>.</li>
                </ul>
            </div>
            <style>
                .advaipbl-features-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 20px; }
                .advaipbl-feature-item { background: #f6f7f7; padding: 15px; border-radius: 4px; border-left: 4px solid var(--advaipbl-color-primary); }
            </style>
        </div>
        <?php
    }
	/**
     * Displays the content for the Status & Debug tab.
     * This tab helps users diagnose issues with IP detection and server configuration.
     */
    public function display_status_tab() {
        // Obtenemos los datos una sola vez para usarlos en toda la función.
        $ip_data = $this->plugin->get_ip_intelligence();
        $server_ip = $this->plugin->get_server_ip();
        $client_ip = $ip_data['visitor_ip'] ?? 'N/A';
        ?>
        <div class="wrap advaipbl-wrap">

            <div class="advaipbl-card">
                <h2><?php esc_html_e( 'IP & Connection Status', 'advanced-ip-blocker' ); ?></h2>
                <p><?php esc_html_e( 'This section helps you verify how the plugin detects your IP and server environment.', 'advanced-ip-blocker' ); ?></p>

                <table class="form-table" role="presentation">
                    <tbody>
                        <tr>
                            <th scope="row"><?php esc_html_e( 'Your Detected IP Address', 'advanced-ip-blocker' ); ?></th>
                            <td>
                                <code><?php echo esc_html( $client_ip ); ?></code>
                                <?php
                                // Comprobamos si la IP del admin está en la whitelist.
                                if ( $this->plugin->is_whitelisted( $client_ip ) ) {
                                    /* translators: A status icon indicating success. */
                                    echo '<span class="advaipbl-status-icon success" title="' . esc_attr__( 'This IP is on the whitelist.', 'advanced-ip-blocker' ) . '">✔</span>';
                                } else {
                                    // Si no está, mostramos el botón.
                                    echo '<button class="button button-secondary advaipbl-add-whitelist-ajax" data-ip="' . esc_attr( $client_ip ) . '" data-detail="' . esc_attr__( 'Admin IP (added from Status page)', 'advanced-ip-blocker' ) . '">' . esc_html__( 'Add to Whitelist', 'advanced-ip-blocker' ) . '</button>';
                                }
                                ?>
                                <p class="description">
                                    <?php 
                                    /* translators: %s: The HTTP header used for detection (e.g., 'HTTP_X_FORWARDED_FOR'). */
                                    printf( esc_html__( 'Detected using the %s header.', 'advanced-ip-blocker' ), '<strong>' . esc_html( $ip_data['visitor_ip_source'] ) . '</strong>' ); 
                                    ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e( 'Server\'s Detected IP Address', 'advanced-ip-blocker' ); ?></th>
                            <td>
                                <?php
                                if ( $server_ip ) {
                                    echo '<code>' . esc_html( $server_ip ) . '</code>';
                                    // Comprobamos si la IP del servidor está en la whitelist.
                                    if ( $this->plugin->is_whitelisted( $server_ip ) ) {
                                        /* translators: A status icon indicating success. */
                                        echo '<span class="advaipbl-status-icon success" title="' . esc_attr__( 'This IP is on the whitelist.', 'advanced-ip-blocker' ) . '">✔</span>';
                                    } else {
                                        // Si no está, mostramos el botón.
                                        echo '<button class="button button-secondary advaipbl-add-whitelist-ajax" data-ip="' . esc_attr( $server_ip ) . '" data-detail="' . esc_attr__( 'Server IP (added from Status page)', 'advanced-ip-blocker' ) . '">' . esc_html__( 'Add to Whitelist', 'advanced-ip-blocker' ) . '</button>';
                                    }
                                } else {
                                    echo '<span style="color: #d63638;">' . esc_html__( 'Could not be determined.', 'advanced-ip-blocker' ) . '</span>';
                                }
                                ?>
                                <p class="description"><?php esc_html_e( 'This is the public IP of your web server. It is highly recommended to whitelist this IP.', 'advanced-ip-blocker' ); ?></p>
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>

            <div class="advaipbl-card">
                <h2><?php esc_html_e( 'Network Infrastructure', 'advanced-ip-blocker' ); ?></h2>
                <table class="form-table" role="presentation">
                    <tbody>
                        <tr>
                            <th scope="row"><?php esc_html_e( 'Connection via Proxy / CDN', 'advanced-ip-blocker' ); ?></th>
                            <td>
                                <?php
                                $cdn_service = __( 'None', 'advanced-ip-blocker' );
                                $status_color = 'black';
                                $cf_detected_raw = isset($_SERVER['HTTP_CF_RAY']);
                                
                                // Detección de "Proxy Transparente"
                                $is_transparent_proxy = false;
                                $cf_connecting_ip = isset($_SERVER['HTTP_CF_CONNECTING_IP']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_CF_CONNECTING_IP'])) : '';
                                $remote_addr = isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '';

                                if ( $cf_detected_raw && !empty($cf_connecting_ip) ) {
                                    if ( $remote_addr === $cf_connecting_ip ) {
                                        $is_transparent_proxy = true;
                                    }
                                }

                                if ( $ip_data['is_proxied'] || $is_transparent_proxy ) {
                                    // Caso 1: Detectado y De Confianza (o Transparente)
                                    $status_color = 'green';
                                    
                                    // Si es transparente, forzamos el nombre correcto
                                    if ( $is_transparent_proxy ) {
                                        $cdn_service = __( 'Cloudflare (Transparent / Server-Module)', 'advanced-ip-blocker' );
                                    } else {
                                        $cdn_service = $ip_data['cdn_info']['provider'] ?? __( 'Generic Proxy / Load Balancer', 'advanced-ip-blocker' );
                                    }
                                    
                                    echo '<strong style="color: ' . esc_attr($status_color) . ';">' . esc_html( $cdn_service ) . '</strong>';
                                    
                                    if ($is_transparent_proxy && !$ip_data['is_proxied']) {
                                        echo '<p class="description">' . esc_html__('Your server is automatically handling IP restoration. No additional configuration needed.', 'advanced-ip-blocker') . '</p>';
                                    }
                                } elseif ( $cf_detected_raw ) {
                                    // Caso 2: Detectado pero NO De Confianza
                                    echo '<strong style="color: #f59e0b;">' . esc_html__( 'Cloudflare (Detected but NOT Trusted)', 'advanced-ip-blocker' ) . '</strong>';
                                    echo '<p class="description" style="color: #d63638;">';
                                    esc_html_e( 'Warning: Cloudflare headers are present, but the plugin does not trust the source IP yet. This means IP blocking will fail.', 'advanced-ip-blocker' );
                                    echo '</p>';
                                    echo '<p><a href="' . esc_url( admin_url( 'admin.php?page=advaipbl_settings_page-settings#section-ip_detection' ) ) . '" class="button button-small">' . esc_html__( 'Fix: Add AS13335 to Trusted Proxies', 'advanced-ip-blocker' ) . '</a></p>';
                                } else {
                                    // Caso 3: No detectado
                                    echo '<strong>' . esc_html( $cdn_service ) . '</strong>';
                                }
                                ?>
                            </td>
                        </tr>
                        <?php if ( ! empty( $ip_data['proxy_chain'] ) ) : ?>
                        <tr>
                            <th scope="row"><?php esc_html_e( 'Proxy/CDN IP(s)', 'advanced-ip-blocker' ); ?></th>
                            <td>
                                <?php foreach ( $ip_data['proxy_chain'] as $proxy_ip ) : ?>
                                    <code><?php echo esc_html( $proxy_ip ); ?></code><br>
                                <?php endforeach; ?>
                            </td>
                        </tr>
                        <?php endif; ?>
                        
                        <?php 
                        // Mostrar datos de Cloudflare si están disponibles (ya sea confiable o crudo)
                        $cf_ray_raw = isset($_SERVER['HTTP_CF_RAY']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_CF_RAY'])) : null;
                        $cf_country_raw = isset($_SERVER['HTTP_CF_IPCOUNTRY']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_CF_IPCOUNTRY'])) : null;
                        
                        $ray_id = $ip_data['cdn_info']['ray_id'] ?? $cf_ray_raw;
                        $cf_country = $ip_data['cdn_info']['country'] ?? $cf_country_raw;
                        ?>

                        <?php if ( ! empty( $ray_id ) ) : ?>
                        <tr>
                            <th scope="row"><?php esc_html_e( 'Cloudflare Ray ID', 'advanced-ip-blocker' ); ?></th>
                            <td><?php echo esc_html( $ray_id ); ?></td>
                        </tr>
                        <?php endif; ?>
                        
                        <?php if ( ! empty( $cf_country ) ) : ?>
                        <tr>
                            <th scope="row"><?php esc_html_e( 'Visitor Country (from CDN)', 'advanced-ip-blocker' ); ?></th>
                            <td><?php echo esc_html( $cf_country ); ?></td>
                        </tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>

            <div class="advaipbl-card">
    <h2><?php esc_html_e( 'Server Environment', 'advanced-ip-blocker' ); ?></h2>
    <table class="form-table" role="presentation">
        <tbody>
            <tr>
                <th scope="row"><?php esc_html_e( 'Web Server', 'advanced-ip-blocker' ); ?></th>
                <td><?php echo isset( $_SERVER['SERVER_SOFTWARE'] ) ? esc_html( sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) ) : esc_html__( 'Not available', 'advanced-ip-blocker' ); ?></td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e( 'PHP Version', 'advanced-ip-blocker' ); ?></th>
                <td>
                    <?php
                    $php_version = phpversion();
                    if ( version_compare( $php_version, '7.4', '>=' ) ) {
                        echo '<span style="color: green; font-weight: bold;">' . esc_html( $php_version ) . '</span>';
                    } else {
                        echo '<span style="color: #d63638; font-weight: bold;">' . esc_html( $php_version ) . '</span>';
                        echo '<p class="description">' . esc_html__( 'Warning: Your PHP version is outdated. The plugin requires PHP 7.4 or higher for optimal performance and security.', 'advanced-ip-blocker' ) . '</p>';
                    }
                    ?>
                </td>
            </tr>
             <tr>
                <th scope="row"><?php esc_html_e( 'PHP SAPI', 'advanced-ip-blocker' ); ?></th>
                <td><?php echo esc_html( php_sapi_name() ); ?></td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e( 'PHP Memory Limit', 'advanced-ip-blocker' ); ?></th>
                <td><?php echo esc_html( ini_get('memory_limit') ); ?></td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e( 'Server OS', 'advanced-ip-blocker' ); ?></th>
                <td><?php echo esc_html( PHP_OS ); ?></td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e( 'Outbound Connection Test', 'advanced-ip-blocker' ); ?></th>
                <td>
                    <button id="advaipbl-test-connection-btn" class="button"><?php esc_html_e( 'Run Test', 'advanced-ip-blocker' ); ?></button>
                    <span id="advaipbl-test-connection-result" style="margin-left: 10px;"></span>
                    <p class="description"><?php esc_html_e( 'Tests if your server can make external HTTPS calls, required for some geolocation APIs and the server IP detection.', 'advanced-ip-blocker' ); ?></p>
                </td>
            </tr>
        </tbody>
    </table>
</div>
			
            <div class="advaipbl-card">
                <h2><?php esc_html_e( 'WordPress Environment', 'advanced-ip-blocker' ); ?></h2>
                <table class="form-table" role="presentation">
                    <tbody>
                        <tr>
                            <th scope="row"><?php esc_html_e( 'WordPress Version', 'advanced-ip-blocker' ); ?></th>
                            <td><?php echo esc_html( get_bloginfo( 'version' ) ); ?></td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e( 'Debug Mode (WP_DEBUG)', 'advanced-ip-blocker' ); ?></th>
                            <td>
                                <?php if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) : ?>
                                    <span style="color: #f59e0b; font-weight: bold;"><?php esc_html_e( 'On', 'advanced-ip-blocker' ); ?></span>
                                <?php else : ?>
                                    <span style="color: green; font-weight: bold;"><?php esc_html_e( 'Off', 'advanced-ip-blocker' ); ?></span>
                                <?php endif; ?>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e( 'Memory Limit (WP_MEMORY_LIMIT)', 'advanced-ip-blocker' ); ?></th>
                            <td><?php echo esc_html( WP_MEMORY_LIMIT ); ?></td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e( 'Multisite Enabled', 'advanced-ip-blocker' ); ?></th>
                            <td><?php echo is_multisite() ? esc_html__( 'Yes', 'advanced-ip-blocker' ) : esc_html__( 'No', 'advanced-ip-blocker' ); ?></td>
                        </tr>
                         <tr>
                            <th scope="row"><?php esc_html_e( 'Object Cache', 'advanced-ip-blocker' ); ?></th>
                            <td>
                                <?php if ( wp_using_ext_object_cache() ) : ?>
                                    <span style="color: green; font-weight: bold;"><?php esc_html_e( 'Enabled (Persistent)', 'advanced-ip-blocker' ); ?></span>
                                    <p class="description"><?php esc_html_e( 'Your site is using a persistent object cache (e.g., Redis, Memcached, Docket Cache), which improves performance.', 'advanced-ip-blocker' ); ?></p>
                                <?php else : ?>
                                    <span style="color: #50575e;"><?php esc_html_e( 'Disabled (Default)', 'advanced-ip-blocker' ); ?></span>
                                    <p class="description"><?php esc_html_e( 'Your site is using the default WordPress object cache. Performance can be improved with a persistent cache solution.', 'advanced-ip-blocker' ); ?></p>
                                <?php endif; ?>
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>

            <div class="advaipbl-card">
                <h2><?php esc_html_e( 'Recommendations & Troubleshooting', 'advanced-ip-blocker' ); ?></h2>
                <?php
                // Variable de control para saber si hemos mostrado algún aviso.
                $has_recommendations = false;

                // Comprobación para CDN/Proxy
                $remote_addr = $this->plugin->get_remote_addr();
                $client_ip = $this->plugin->get_client_ip();
                if ( $remote_addr && $client_ip !== $remote_addr && filter_var( $remote_addr, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
                    echo '<div class="notice notice-info inline"><p>';
                    /* translators: %1$s: Client's real IP. %2$s: Proxy/CDN IP. */
                    echo '<strong>' . esc_html__( 'Info:', 'advanced-ip-blocker' ) . '</strong> ' . sprintf( esc_html__( 'It seems your site is behind a reverse proxy or CDN. Your IP is correctly detected as %1$s, while your server connects through %2$s. This is a normal and correct configuration.', 'advanced-ip-blocker' ), '<code>' . esc_html( $client_ip ) . '</code>', '<code>' . esc_html( $remote_addr ) . '</code>' );
                    echo '</p></div>';
                    $has_recommendations = true;
                }

                // Comprobación de la IP del servidor
                if ( ! $this->plugin->get_server_ip() ) {
                     echo '<div class="notice notice-warning inline"><p>';
                    echo '<strong>' . esc_html__( 'Warning:', 'advanced-ip-blocker' ) . '</strong> ' . esc_html__( 'The plugin could not automatically determine your server\'s public IP. The feature that adds the server IP to the whitelist on activation will not work. Please add your server IP to the whitelist manually to prevent any issues with geoblocking or other functionalities.', 'advanced-ip-blocker' );
                    echo '</p></div>';
                    $has_recommendations = true;
                }
				
				$xmlrpc_plugins = $this->plugin->get_xmlrpc_dependent_plugins();
                if ( ! empty( $xmlrpc_plugins ) ) :
                ?>
                   <div class="notice notice-warning inline" style="margin-top:15px;">
                       <p>
                           <strong><?php esc_html_e( 'XML-RPC Dependency Detected:', 'advanced-ip-blocker' ); ?></strong><br>
                           <?php esc_html_e( 'The following active plugins may require the XML-RPC interface to function correctly. Disabling it in the settings might break their functionality:', 'advanced-ip-blocker' ); ?>
                      </p>
                      <ul style="list-style:disc; margin-left:20px;">
                           <?php foreach ( $xmlrpc_plugins as $plugin_name ) : ?>
                               <li><strong><?php echo esc_html( $plugin_name ); ?></strong></li>
                           <?php endforeach; ?>
                      </ul>
                   </div>
               <?php 
               endif;
                
                // Si no se ha mostrado ninguna recomendación, mostramos un mensaje de "todo OK".
                if ( ! $has_recommendations ) {
                    echo '<div class="notice notice-success inline"><p>';
                    echo '<strong>' . esc_html__( 'All Clear!', 'advanced-ip-blocker' ) . '</strong> ' . esc_html__( 'No potential configuration issues were detected.', 'advanced-ip-blocker' );
                    echo '</p></div>';
                }
                ?>
            </div>
			<div class="advaipbl-card">
            <h2><?php esc_html_e( 'Setup Wizard', 'advanced-ip-blocker' ); ?></h2>
            <p><?php esc_html_e( 'If you need to re-apply the recommended default settings or ensure your current IPs are whitelisted, you can run the setup wizard again at any time.', 'advanced-ip-blocker' ); ?></p>
            <p>
                <a href="<?php echo esc_url( admin_url( 'admin.php?page=advaipbl-setup-wizard' ) ); ?>" class="button button-secondary">
                    <?php esc_html_e( 'Run Setup Wizard Again', 'advanced-ip-blocker' ); ?>
                </a>
            </p>
            </div>
        </div>

        <?php
    }
	/**
 * Renderiza los controles de la interfaz de usuario para Importar y Exportar.
 */
public function render_import_export_controls_callback() {
    ?>
    <div class="advaipbl-import-export-wrap">
        
        <!-- SECCIÓN DE EXPORTACIÓN -->
        <h3><?php esc_html_e( 'Export Configuration', 'advanced-ip-blocker' ); ?></h3>
        <p><?php esc_html_e( 'Download a JSON file with your plugin configuration. Choose the appropriate format for your needs.', 'advanced-ip-blocker' ); ?></p>
        
        <div class="advaipbl-export-form">
            <?php wp_nonce_field( 'advaipbl_export_nonce', 'advaipbl_export_nonce_field' ); ?>

            <div class="advaipbl-export-option">
                <button type="button" id="advaipbl-export-template" data-export-type="template" class="button button-secondary">
                    <?php esc_html_e( 'Export Template (No API Keys)', 'advanced-ip-blocker' ); ?>
                </button>
                <p class="description">
                    <?php esc_html_e( 'Ideal for migrating your rules to another website. This file excludes all secret API keys.', 'advanced-ip-blocker' ); ?>
                </p>
            </div>

            <div class="advaipbl-export-option">
                <button type="button" id="advaipbl-export-full" data-export-type="full_backup" class="button button-secondary">
                    <?php esc_html_e( 'Export Full Backup (With API Keys)', 'advanced-ip-blocker' ); ?>
                </button>
                <p class="description">
                    <?php esc_html_e( 'Use this to create a complete backup for restoring on this same site only.', 'advanced-ip-blocker' ); ?>
                </p>
            </div>
        </div>

        <hr>

        <!-- SECCIÓN DE IMPORTACIÓN -->
        <h3><?php esc_html_e( 'Import Configuration', 'advanced-ip-blocker' ); ?></h3>
        
        <div class="notice notice-error inline">
            <p><strong><?php esc_html_e( 'WARNING:', 'advanced-ip-blocker' ); ?></strong> <?php esc_html_e( 'Importing a settings file will overwrite ALL your current plugin settings. This action cannot be undone. Please create a backup first.', 'advanced-ip-blocker' ); ?></p>
        </div>
        
        <form method="post" enctype="multipart/form-data" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
            <input type="hidden" name="action" value="advaipbl_import_settings">
            <?php wp_nonce_field( 'advaipbl_import_nonce', 'advaipbl_import_nonce_field' ); ?>
            <p>
                <label for="advaipbl_import_file"><?php esc_html_e( 'Select the JSON configuration file to import:', 'advanced-ip-blocker' ); ?></label><br>
                <input type="file" name="advaipbl_import_file" id="advaipbl_import_file" accept=".json" required>
            </p>
            <p class="submit">
                <button type="submit" name="submit" class="button button-primary">
                    <?php esc_html_e( 'Import and Overwrite Settings', 'advanced-ip-blocker' ); ?>
                </button>
            </p>
        </form>
    </div>
    <?php
}

 /**
     * Renderiza la página del asistente de configuración.
     */
    public function render_setup_wizard_page() {
        // phpcs:disable WordPress.Security.NonceVerification.Recommended
        $step = isset($_GET['step']) ? absint($_GET['step']) : 1;
        // phpcs:enable
        ?>
        <div class="wrap advaipbl-wizard-wrap">
            <h1><?php esc_html_e( 'Advanced IP Blocker Setup', 'advanced-ip-blocker' ); ?></h1>
            <?php 
            if ($step === 1) { 
                ?>
                <h2><?php esc_html_e( 'Step 1: Welcome & Whitelist Your IPs', 'advanced-ip-blocker' ); ?></h2>
                <p><?php esc_html_e( 'Welcome! This wizard will guide you through the essential security settings in under a minute.', 'advanced-ip-blocker' ); ?></p>
                <p><strong><?php esc_html_e( 'This first step is the most important.', 'advanced-ip-blocker' ); ?></strong> <?php esc_html_e( 'To prevent you from accidentally locking yourself out, we will add your current IP address and your server\'s IP to the permanent whitelist.', 'advanced-ip-blocker' ); ?></p>

                <?php
                    $admin_ip = $this->plugin->get_client_ip();
                    $server_ip = $this->plugin->get_server_ip();
                    $is_cloudflare = isset($_SERVER['HTTP_CF_CONNECTING_IP']);
                ?>

                <div class="advaipbl-wizard-ips">
                    <p><strong><?php esc_html_e( 'Your IP Address:', 'advanced-ip-blocker' ); ?></strong> <code><?php echo esc_html($admin_ip ?: 'Could not detect'); ?></code></p>
                    <p><strong><?php esc_html_e( 'Server IP Address:', 'advanced-ip-blocker' ); ?></strong> <code><?php echo esc_html($server_ip ?: 'Could not detect'); ?></code></p>
                </div>

                <?php if ($is_cloudflare): ?>
                    <div class="notice notice-success inline" style="margin-top: 15px;">
                        <p><strong><?php esc_html_e( 'Cloudflare Detected!', 'advanced-ip-blocker' ); ?></strong> <?php esc_html_e( 'We noticed you are using Cloudflare. We will automatically configure the correct IP detection settings to prevent false blocks.', 'advanced-ip-blocker' ); ?></p>
                    </div>
                <?php else: ?>
                    <div class="notice notice-info inline" style="margin-top: 15px;">
                        <p><strong><?php esc_html_e( 'Using a Proxy/CDN?', 'advanced-ip-blocker' ); ?></strong> <?php esc_html_e( 'If your traffic goes through proxies like Sucuri or AWS ELB, you must configure Trusted Proxies in the Settings tab later to avoid blocking yourself.', 'advanced-ip-blocker' ); ?></p>
                    </div>
                <?php endif; ?>

                <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
                    <input type="hidden" name="action" value="advaipbl_wizard_step_1">
                    <?php wp_nonce_field( 'advaipbl_wizard_step_1_nonce' ); ?>
                    
                    <p class="submit">
                        <button type="submit" name="submit" class="button button-primary button-hero">
                            <?php esc_html_e( 'Whitelist IPs & Continue', 'advanced-ip-blocker' ); ?>
                        </button>
                    </p>
                    <p class="skip-link">
                        <a href="<?php echo esc_url( admin_url( 'admin.php?page=advaipbl-setup-wizard&step=2' ) ); ?>"><?php esc_html_e( 'Skip this step (not recommended)', 'advanced-ip-blocker' ); ?></a>
                    </p>
                </form>
                <?php 
            } elseif ($step === 2) { 
                ?>
                <h2><?php esc_html_e( 'Step 2: Activate Bot & Scanner Traps', 'advanced-ip-blocker' ); ?></h2>
                <p><?php esc_html_e( 'These are low-risk, high-reward defenses. We will enable protections that instantly block known malicious bots and vulnerability scanners.', 'advanced-ip-blocker' ); ?></p>
                <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
                    <input type="hidden" name="action" value="advaipbl_wizard_step_2">
                    <?php wp_nonce_field( 'advaipbl_wizard_step_2_nonce' ); ?>
                    <div class="advaipbl-wizard-options">
                        
                        <div class="wizard-option-item">
                            <label>
                                <input type="checkbox" name="activate_user_agent_rules" value="1" checked>
                                <div>
                                    <strong><?php esc_html_e( 'Block Malicious User-Agents', 'advanced-ip-blocker' ); ?></strong>
                                    <p class="description"><?php esc_html_e( 'Applies a curated list of known bad bot and scanner user-agents to the blocklist.', 'advanced-ip-blocker' ); ?></p>
                                </div>
                            </label>
                        </div>
                        <div class="wizard-option-item">
                            <label>
                                <input type="checkbox" name="activate_honeypot_rules" value="1" checked>
                                <div>
                                    <strong><?php esc_html_e( 'Activate Honeypot Traps', 'advanced-ip-blocker' ); ?></strong>
                                    <p class="description"><?php esc_html_e( 'Applies a list of "bait" URLs. Any bot that tries to access them will be instantly blocked.', 'advanced-ip-blocker' ); ?></p>
                                </div>
                            </label>
                        </div>
                        <div class="wizard-option-item">
                            <label>
                                <input type="checkbox" name="activate_xmlrpc_smart" value="1" checked>
                                <div>
                                    <strong><?php esc_html_e( 'Enable Smart XML-RPC Protection', 'advanced-ip-blocker' ); ?></strong>
                                    <p class="description"><?php esc_html_e( '(Recommended) Blocks brute-force attacks on xmlrpc.php while allowing legitimate services like Jetpack to function.', 'advanced-ip-blocker' ); ?></p>
                                </div>
                            </label>
                        </div>
                        
                    </div>
                    <p class="submit">
                        <button type="submit" name="submit" class="button button-primary button-hero"><?php esc_html_e( 'Activate Recommended Defenses', 'advanced-ip-blocker' ); ?></button>
                    </p>
                    <p class="skip-link">
                        <a href="<?php echo esc_url( admin_url( 'admin.php?page=advaipbl-setup-wizard&step=3' ) ); ?>"><?php esc_html_e( 'Skip this step', 'advanced-ip-blocker' ); ?></a>
                    </p>
                </form>
                <?php 
            } elseif ($step === 3) {
                ?>
                <h2><?php esc_html_e( 'Step 3: Activate Proactive Defenses', 'advanced-ip-blocker' ); ?></h2>
                <p><?php esc_html_e( 'Now let\'s enable the firewall to protect your site from more advanced attacks like SQL injection and prevent server overload from aggressive bots.', 'advanced-ip-blocker' ); ?></p>
                <form id="advaipbl-wizard-step3-form" method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
                    <input type="hidden" name="action" value="advaipbl_wizard_step_3">
                    <?php wp_nonce_field( 'advaipbl_wizard_step_3_nonce' ); ?>
                    <div class="advaipbl-wizard-options">
                        
                        <div class="wizard-option-item">
                            <label>
                                <input type="checkbox" name="activate_waf" value="1" checked>
                                <div>
                                    <strong><?php esc_html_e( 'Enable Web Application Firewall (WAF)', 'advanced-ip-blocker' ); ?></strong>
                                    <p class="description"><?php esc_html_e( 'Applies our recommended set of WAF rules to block common hacking patterns.', 'advanced-ip-blocker' ); ?></p>
                                </div>
                            </label>
                        </div>
                        <div class="wizard-option-item">
                            <label>
                                <input type="checkbox" name="activate_rate_limiting" value="1" checked>
                                <div>
                                    <strong><?php esc_html_e( 'Enable Request Rate Limiting', 'advanced-ip-blocker' ); ?></strong>
                                    <p class="description"><?php esc_html_e( 'Temporarily blocks IPs that make an excessive number of requests, protecting against DoS attacks.', 'advanced-ip-blocker' ); ?></p>
                                </div>
                            </label>
                        </div>
                        <div class="wizard-option-item">
                            <label>
                                <input type="checkbox" name="activate_spamhaus" value="1" checked>
                                <div>
                                    <strong><?php esc_html_e( 'Enable Spamhaus ASN Protection', 'advanced-ip-blocker' ); ?></strong>
                                    <p class="description"><?php esc_html_e( 'Automatically blocks thousands of the most malicious networks on the internet.', 'advanced-ip-blocker' ); ?></p>
                                </div>
                            </label>
                        </div>
						<div class="wizard-option-item">
                            <label>
                                <input type="checkbox" name="activate_htaccess" value="1" checked>
                                <div>
                                    <strong><?php esc_html_e( 'Enable Server-Level Firewall (.htaccess)', 'advanced-ip-blocker' ); ?></strong>
                                    <p class="description"><?php esc_html_e( 'Automatically writes blocking rules and file hardening protections to your .htaccess file for maximum performance.', 'advanced-ip-blocker' ); ?></p>
                                </div>
                            </label>
                        </div>
                        <div class="wizard-option-item">
                            <label>
                                <input type="checkbox" name="activate_community_network" value="1" checked>
                                <div>
                                    <strong><?php esc_html_e( 'Join AIB Community Defense', 'advanced-ip-blocker' ); ?></strong>
                                    <p class="description"><?php esc_html_e( 'Protect your site with our global blocklist generated from community data, and share your own attack reports to help others.', 'advanced-ip-blocker' ); ?></p>
                                </div>
                            </label>
                        </div>
                        
                    </div>
                    
                    <div class="notice notice-info inline" style="margin-top: 15px;">
                        <p><strong><?php esc_html_e( 'Geolocation Note:', 'advanced-ip-blocker' ); ?></strong> <?php esc_html_e( 'Powered by ip-api.com for zero-setup convenience. For maximum privacy and local performance, we recommend switching to the MaxMind Local Database in the settings after completing this wizard.', 'advanced-ip-blocker' ); ?></p>
                    </div>

                    <p class="submit">
                        <button type="submit" name="submit" class="button button-primary button-hero"><?php esc_html_e( 'Activate Proactive Defenses', 'advanced-ip-blocker' ); ?></button>
                    </p>
                    <p class="skip-link">
                        <a href="<?php echo esc_url( admin_url( 'admin.php?page=advaipbl-setup-wizard&step=4' ) ); ?>"><?php esc_html_e( 'Skip this step', 'advanced-ip-blocker' ); ?></a>
                    </p>
                </form>
                <?php 
            } elseif ($step === 4) { 
            ?>
            <h2><?php esc_html_e( 'Step 4: Activate Intelligent Protection', 'advanced-ip-blocker' ); ?></h2>
            <p><?php esc_html_e( 'This is our most advanced defense. Instead of simple rules, the Threat Scoring System analyzes behavior over time, blocking only truly malicious visitors. It is more accurate and reduces false positives.', 'advanced-ip-blocker' ); ?></p>
            
            <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
                <input type="hidden" name="action" value="advaipbl_wizard_step_4">
                <?php wp_nonce_field( 'advaipbl_wizard_step_4_nonce' ); ?>
                
                <div class="advaipbl-wizard-options">
                    <label>
                        <input type="checkbox" name="activate_threat_scoring" value="1" checked>
                        <strong><?php esc_html_e( 'Enable IP Trust & Threat Scoring System', 'advanced-ip-blocker' ); ?></strong>
                        <p class="description"><?php esc_html_e( '(Recommended) Activates context-aware security that assigns threat points and blocks IPs based on their total score.', 'advanced-ip-blocker' ); ?></p>
                    </label>
                </div>

                <p class="submit">
                    <button type="submit" name="submit" class="button button-primary button-hero">
                        <?php esc_html_e( 'Activate & Finish Setup', 'advanced-ip-blocker' ); ?>
                    </button>
                </p>
                <p class="skip-link">
                    <a href="<?php echo esc_url( admin_url( 'admin.php?page=advaipbl-setup-wizard&step=5' ) ); ?>"><?php esc_html_e( 'Skip this step', 'advanced-ip-blocker' ); ?></a>
                </p>
            </form>
            <?php 
        } elseif ($step === 5) {
            ?>
            <div class="advaipbl-wizard-final-step">
                <span class="dashicons dashicons-shield-alt" style="font-size: 60px; width: 60px; height: 60px; color: #2271b1; margin-bottom: 20px;"></span>
                <h2><?php esc_html_e( 'Setup Complete! Your Site is Secure.', 'advanced-ip-blocker' ); ?></h2>
                <p><?php esc_html_e( 'The core defenses are now active. However, for maximum security, we recommend configuring these advanced integrations:', 'advanced-ip-blocker' ); ?></p>
                
                <div class="advaipbl-wizard-next-actions" style="text-align: left; max-width: 500px; margin: 30px auto; background: #fff; padding: 20px; border: 1px solid #ccd0d4; border-radius: 4px;">
                    <ul style="list-style: none; margin: 0; padding: 0;">
                        <li style="margin-bottom: 15px; display: flex; align-items: start;">
                            <span class="dashicons dashicons-cloud" style="color: #e67e22; margin-right: 10px; margin-top: 3px;"></span>
                            <div>
                                <strong><?php esc_html_e( 'Cloud Edge Defense', 'advanced-ip-blocker' ); ?></strong><br>
                                <small><?php esc_html_e( 'Connect your Cloudflare account to block threats before they reach your server.', 'advanced-ip-blocker' ); ?></small>
                            </div>
                        </li>
                        <li style="margin-bottom: 15px; display: flex; align-items: start;">
                            <span class="dashicons dashicons-database" style="color: #2271b1; margin-right: 10px; margin-top: 3px;"></span>
                            <div>
                                <strong><?php esc_html_e( 'AbuseIPDB Protection', 'advanced-ip-blocker' ); ?></strong><br>
                                <small><?php esc_html_e( 'Get a free API key to check visitor reputation against a global blacklist.', 'advanced-ip-blocker' ); ?></small>
                            </div>
                        </li>
                        <li style="display: flex; align-items: start;">
                            <span class="dashicons dashicons-smartphone" style="color: #2ecc71; margin-right: 10px; margin-top: 3px;"></span>
                            <div>
                                <strong><?php esc_html_e( 'Two-Factor Authentication', 'advanced-ip-blocker' ); ?></strong><br>
                                <small><?php esc_html_e( 'Protect your admin account by setting up 2FA in your profile.', 'advanced-ip-blocker' ); ?></small>
                            </div>
                        </li>
                    </ul>
                </div>

                <div class="advaipbl-wizard-buttons">
                    <a href="<?php echo esc_url( admin_url('admin.php?page=advaipbl_settings_page-settings') ); ?>" class="button button-primary button-hero">
                        <?php esc_html_e( 'Go to Settings & Configure Integrations', 'advanced-ip-blocker' ); ?>
                    </a>
                    <br><br>
                    <a href="<?php echo esc_url( admin_url('admin.php?page=advaipbl_settings_page') ); ?>" class="button button-secondary">
                        <?php esc_html_e( 'Go to Dashboard', 'advanced-ip-blocker' ); ?>
                    </a>
                </div>
            </div>

            <?php
        }
            ?>
        </div>
        <?php
    }

/**
 * Muestra la pestaña de Reglas Avanzadas.
 */
public function display_advanced_rules_tab() {
    ?>
    <?php
$is_threat_scoring_enabled = !empty($this->plugin->options['enable_threat_scoring']);
$is_geolocation_ready = !empty($this->plugin->options['geolocation_provider']);

$settings_base_url = admin_url('admin.php?page=advaipbl_settings_page-settings&sub-tab=general_settings');

$status_parts = [];

$status_parts[] = sprintf(
    '<strong>%1$s:</strong> <span class="advaipbl-status-tag %2$s">%3$s</span> (<a href="%4$s">%5$s</a>)',
    esc_html__('Threat Scoring', 'advanced-ip-blocker'),
    $is_threat_scoring_enabled ? 'enabled' : 'disabled',
    $is_threat_scoring_enabled ? esc_html__('Active', 'advanced-ip-blocker') : esc_html__('Inactive', 'advanced-ip-blocker'),
    esc_url($settings_base_url . '#section-ip_trust'),
    esc_html__('configure', 'advanced-ip-blocker')
);

$status_parts[] = sprintf(
    '<strong>%1$s:</strong> <span class="advaipbl-status-tag %2$s">%3$s</span> (<a href="%4$s">%5$s</a>)',
    esc_html__('Geolocation', 'advanced-ip-blocker'),
    $is_geolocation_ready ? 'enabled' : 'disabled',
    $is_geolocation_ready ? esc_html__('Ready', 'advanced-ip-blocker') : esc_html__('Not Configured', 'advanced-ip-blocker'),
    esc_url($settings_base_url . '#section-geolocation'),
    esc_html__('configure', 'advanced-ip-blocker')
);
?>
<div class="notice notice-info inline">
    <p>
        <strong><?php esc_html_e('Dependencies Status:', 'advanced-ip-blocker'); ?></strong><br>
        <?php 
        /* translators: %s: a status line for a module. */
        echo wp_kses(implode('<br>', $status_parts), [
            'strong' => [],
            'span'   => ['class' => true],
            'a'      => ['href' => []],
            'br'     => []
        ]);
        ?>
        <small style="display: block; margin-top: 8px;"><?php esc_html_e('Rules using a disabled or unconfigured module will not trigger.', 'advanced-ip-blocker'); ?></small>
    </p>
</div>
    <h2><?php esc_html_e('Advanced Rules Engine', 'advanced-ip-blocker'); ?></h2>
    <p><?php esc_html_e('Create custom, multi-conditional rules to block, challenge, or score traffic with precision.', 'advanced-ip-blocker'); ?></p>

    <div class="advaipbl-card">
    <h3><?php esc_html_e('Existing Rules', 'advanced-ip-blocker'); ?></h3>
    <div class="advaipbl-rules-nav-bar advaipbl-rules-nav-top">
    <div class="alignleft actions bulkactions">
        <label for="advaipbl-adv-rules-bulk-action-top" class="screen-reader-text"><?php esc_html_e('Select bulk action', 'advanced-ip-blocker'); ?></label>
        <select name="action" class="advaipbl-adv-rules-bulk-action">
            <option value="-1"><?php esc_html_e('Bulk Actions', 'advanced-ip-blocker'); ?></option>
            <option value="delete"><?php esc_html_e('Delete', 'advanced-ip-blocker'); ?></option>
        </select>
        <button type="button" class="button action advaipbl-apply-bulk-action"><?php esc_html_e('Apply', 'advanced-ip-blocker'); ?></button>
    </div>
    <div class="advaipbl-pagination-container">

    </div>
    </div>
    <div id="advaipbl-advanced-rules-list">
        <div class="advaipbl-loader-wrapper" style="text-align: center; padding: 20px;">
            <div class="advaipbl-loader"></div>
        </div>
    </div>
    <div class="advaipbl-rules-nav-bar advaipbl-rules-nav-bottom">
    <div class="alignleft actions bulkactions">
        <label for="advaipbl-adv-rules-bulk-action-bottom" class="screen-reader-text"><?php esc_html_e('Select bulk action', 'advanced-ip-blocker'); ?></label>
        <select name="action2" class="advaipbl-adv-rules-bulk-action">
            <option value="-1"><?php esc_html_e('Bulk Actions', 'advanced-ip-blocker'); ?></option>
            <option value="delete"><?php esc_html_e('Delete', 'advanced-ip-blocker'); ?></option>
        </select>
        <button type="button" class="button action advaipbl-apply-bulk-action"><?php esc_html_e('Apply', 'advanced-ip-blocker'); ?></button>
    </div>
    <div class="advaipbl-pagination-container">

    </div>
    </div>
    <button id="advaipbl-add-new-rule-btn" class="button button-primary" style="margin-top: 15px;">
        <span class="dashicons dashicons-plus-alt"></span>
        <?php esc_html_e('Add New Rule', 'advanced-ip-blocker'); ?>
    </button>
</div>


    <div id="advaipbl-rule-builder-modal" class="advaipbl-modal-overlay" style="display: none;">
        <div class="advaipbl-modal-content" style="max-width: 800px;">
            <h3 class="advaipbl-modal-title"><?php esc_html_e('Rule Builder', 'advanced-ip-blocker'); ?></h3>
            
            <div class="advaipbl-modal-body">
                <input type="hidden" id="advaipbl-rule-id" value="">
                
                <table class="form-table">
                    <tbody>
                        <tr>
                            <th scope="row"><label for="advaipbl-rule-name"><?php esc_html_e('Rule Name', 'advanced-ip-blocker'); ?></label></th>
                            <td><input type="text" id="advaipbl-rule-name" class="regular-text" placeholder="<?php esc_attr_e('e.g., Block PDFs from China', 'advanced-ip-blocker'); ?>"></td>
                        </tr>
                    </tbody>
                </table>
                
                <hr>
                <h4><?php esc_html_e('IF (All conditions must be met)', 'advanced-ip-blocker'); ?></h4>
                <div id="advaipbl-rule-conditions">
                </div>
                <button id="advaipbl-add-condition-btn" class="button button-secondary">
                    <span class="dashicons dashicons-plus"></span>
                    <?php esc_html_e('Add Condition (AND)', 'advanced-ip-blocker'); ?>
                </button>

                <hr>
                <h4><?php esc_html_e('THEN', 'advanced-ip-blocker'); ?></h4>
                <table class="form-table">
                    <tbody>
                        <tr>
                            <th scope="row"><label for="advaipbl-rule-action"><?php esc_html_e('Action', 'advanced-ip-blocker'); ?></label></th>
                            <td>
                                <select id="advaipbl-rule-action">
                                    <option value="allow"><?php esc_html_e('Allow (Bypass Security)', 'advanced-ip-blocker'); ?></option>
                                    <option value="block"><?php esc_html_e('Block', 'advanced-ip-blocker'); ?></option>
                                    <option value="challenge"><?php esc_html_e('Challenge with JavaScript (Managed)', 'advanced-ip-blocker'); ?></option>
                                    <option value="challenge_automatic"><?php esc_html_e('Challenge with JavaScript (Automatic)', 'advanced-ip-blocker'); ?></option>
                                    <option value="score"><?php esc_html_e('Add Threat Score', 'advanced-ip-blocker'); ?></option>									
                                </select>
                            </td>
                        </tr>
                        <tr id="advaipbl-rule-action-params-row">
                            <th scope="row"><label><?php esc_html_e('Parameters', 'advanced-ip-blocker'); ?></label></th>
                            <td id="advaipbl-rule-action-params">
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>

            <div class="advaipbl-modal-footer">
                <span id="advaipbl-rule-builder-feedback" style="margin-right: auto;"></span>
                <button class="button advaipbl-modal-cancel"><?php esc_html_e('Cancel', 'advanced-ip-blocker'); ?></button>
                <button id="advaipbl-save-rule-btn" class="button button-primary"><?php esc_html_e('Save Rule', 'advanced-ip-blocker'); ?></button>
            </div>
        </div>
    </div>


    <template id="advaipbl-condition-template">
        <div class="advaipbl-condition-row">
            <select class="condition-type">
                <option value="ip"><?php esc_html_e('IP Address', 'advanced-ip-blocker'); ?></option>
                <option value="ip_range"><?php esc_html_e('IP Range', 'advanced-ip-blocker'); ?></option>
                <option value="country"><?php esc_html_e('Country', 'advanced-ip-blocker'); ?></option>
                <option value="asn"><?php esc_html_e('ASN', 'advanced-ip-blocker'); ?></option>
                <option value="uri"><?php esc_html_e('Request URI', 'advanced-ip-blocker'); ?></option>
                <option value="user_agent"><?php esc_html_e('User-Agent', 'advanced-ip-blocker'); ?></option>
                <option value="username"><?php esc_html_e('Username (Login)', 'advanced-ip-blocker'); ?></option>
            </select>
            <select class="condition-operator"></select>
            <div class="condition-value-container"></div>
            <button class="button button-link-delete remove-condition" title="<?php esc_attr_e('Remove condition', 'advanced-ip-blocker'); ?>"><span class="dashicons dashicons-no-alt"></span></button>
        </div>
    </template>
    <?php
 }

public function display_scanner_tab() {
        $scan_data = $this->plugin->site_scanner->run_local_scan();
        

        $get_icon = function($status) {
            switch($status) {
                case 'good': return '<span class="dashicons dashicons-yes-alt" style="color:green;font-size:24px;"></span>';
                case 'warning': return '<span class="dashicons dashicons-warning" style="color:#f59e0b;font-size:24px;"></span>';
                case 'critical': return '<span class="dashicons dashicons-no-alt" style="color:#d63638;font-size:24px;"></span>';
                default: return '<span class="dashicons dashicons-info" style="color:#2271b1;font-size:24px;"></span>';
            }
        };
        ?>
        <div class="advaipbl-scanner-wrap">
            <h2><?php esc_html_e('Site Health & Security Scanner', 'advanced-ip-blocker'); ?></h2>
            <p><?php esc_html_e('A quick audit of your WordPress environment to identify potential security holes before they are exploited.', 'advanced-ip-blocker'); ?></p>

            <div class="advaipbl-dashboard-row">
                <!-- Environment Card -->
                <div class="advaipbl-dashboard-widget widget-third">
                    <h3><?php esc_html_e('Environment', 'advanced-ip-blocker'); ?></h3>
                    <table class="wp-list-table widefat fixed striped">
                        <tr>
                            <td><strong>PHP Version</strong></td>
                            <td>
                                <?php 
                                // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
                                echo $get_icon($scan_data['php']['status']); 
                                ?> 
                                <strong><?php echo esc_html($scan_data['php']['current']); ?></strong><br>
                                <small><?php echo esc_html($scan_data['php']['message']); ?></small>
                            </td>
                        </tr>
                        <tr>
                            <td><strong>Database</strong></td>
                            <td><?php echo esc_html($scan_data['database']['current']); ?></td>
                        </tr>
                        <tr>
                            <td><strong>SSL (HTTPS)</strong></td>
                            <td>
                                <?php 
                                // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
                                echo $get_icon($scan_data['ssl']['status']); 
                                ?> 
                                <?php echo esc_html($scan_data['ssl']['message']); ?>
                            </td>
                        </tr>
                    </table>
                </div>

                <!-- WordPress Core Card -->
                <div class="advaipbl-dashboard-widget widget-third">
                    <h3><?php esc_html_e('WordPress Core', 'advanced-ip-blocker'); ?></h3>
                    <table class="wp-list-table widefat fixed striped">
                        <tr>
                            <td><strong>Version</strong></td>
                            <td>
                                <?php 
                                // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
                                echo $get_icon($scan_data['wordpress']['status']); 
                                ?> 
                                <strong><?php echo esc_html($scan_data['wordpress']['current']); ?></strong><br>
                                <small><?php echo esc_html($scan_data['wordpress']['message']); ?></small>
                            </td>
                        </tr>
                        <tr>
                            <td><strong>Debug Mode</strong></td>
                            <td>
                                <?php 
                                // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
                                echo $get_icon($scan_data['debug_mode']['status']); 
                                ?> 
                                <?php echo esc_html($scan_data['debug_mode']['message']); ?>
                            </td>
                        </tr>
                    </table>
                </div>

                <!-- Updates Card -->
                <div class="advaipbl-dashboard-widget widget-third">
                    <h3><?php esc_html_e('Pending Updates', 'advanced-ip-blocker'); ?></h3>
                    <div style="text-align:center; padding: 10px;">
                        <?php 
                        // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
                        echo $get_icon($scan_data['updates']['status']); 
                        ?>
                        <h2 style="margin: 5px 0;"><?php echo intval($scan_data['updates']['plugins'] + $scan_data['updates']['themes']); ?></h2>
                        <p class="description"><?php esc_html_e('Total components needing update.', 'advanced-ip-blocker'); ?></p>
                        
                        <?php if ($scan_data['updates']['plugins'] > 0) : ?>
                            <div style="text-align:left; margin-top:10px; border-top:1px solid #eee; padding-top:10px;">
                                <strong><?php esc_html_e('Outdated Plugins:', 'advanced-ip-blocker'); ?></strong>
                                <ul style="margin:5px 0 0 15px; list-style:disc; font-size:11px;">
                                    <?php 
                                    $count = 0;
                                    foreach ($scan_data['updates']['details'] as $slug => $data) {
                                        if ($count >= 5) { echo '<li>...and more</li>'; break; }
                                        // Intentar obtener nombre legible si está disponible en el objeto, sino usar slug
                                        $name = $slug; 
                                        // (Nota: el objeto de update_plugins es complejo, usar slug es seguro por ahora)
                                        echo '<li>' . esc_html($slug) . '</li>';
                                        $count++;
                                    } 
                                    ?>
                                </ul>
                                <p style="text-align:center; margin-top:10px;"><a href="<?php echo esc_url(admin_url('update-core.php')); ?>" class="button button-small button-primary"><?php esc_html_e('Update Now', 'advanced-ip-blocker'); ?></a></p>
                            </div>
                        <?php else: ?>
                            <p style="color:green;"><?php esc_html_e('All plugins and themes are up to date.', 'advanced-ip-blocker'); ?></p>
                        <?php endif; ?>
                    </div>
                </div>

                <!-- Installed Themes Analysis Card (NEW) -->
                <div class="advaipbl-dashboard-widget widget-full" style="margin-top: 20px;">
                    <h3><?php esc_html_e('Installed Themes Analysis', 'advanced-ip-blocker'); ?></h3>
                    <div style="padding:0;">
                        <table class="wp-list-table widefat fixed striped">
                            <thead>
                                <tr>
                                    <th><?php esc_html_e('Theme', 'advanced-ip-blocker'); ?></th>
                                    <th><?php esc_html_e('Version', 'advanced-ip-blocker'); ?></th>
                                    <th><?php esc_html_e('Type', 'advanced-ip-blocker'); ?></th>
                                    <th><?php esc_html_e('Status', 'advanced-ip-blocker'); ?></th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php if (!empty($scan_data['themes_list']) && is_array($scan_data['themes_list'])) : ?>
                                    <?php foreach ($scan_data['themes_list'] as $slug => $theme) : ?><?php if(!is_array($theme)) continue; ?>
                                        <tr>
                                            <td>
                                                <strong><?php echo esc_html(is_string($theme['name'] ?? '') ? $theme['name'] : $slug); ?></strong>
                                                <?php if ($theme['is_active']) : ?>
                                                    <span style="background:#00a32a; color:#fff; padding:2px 5px; border-radius:3px; font-size:10px; margin-left:5px;"><?php esc_html_e('Active', 'advanced-ip-blocker'); ?></span>
                                                <?php endif; ?>
                                            </td>
                                            <td><?php echo esc_html($theme['version']); ?></td>
                                            <td>
                                                <?php 
                                                if ($theme['is_parent']) {
                                                    echo '<span style="color:#2271b1; font-weight:bold;">' . esc_html__('Parent Theme', 'advanced-ip-blocker') . '</span>';
                                                } elseif ($theme['is_active'] && !$theme['is_parent'] && $theme['is_active']) { // is child
                                                     // Simplificación: sies activo y no es padre, suele ser hijo o standalone. 
                                                     // La logica exacta de "padre" depende de si OTRO tema lo usa. 
                                                     // Aqui simplificamos: Si un active_theme tiene parent(), el active es Child.
                                                     // El parent fue marcado en el loop.
                                                     echo esc_html__('Standard / Child', 'advanced-ip-blocker'); 
                                                } else {
                                                    echo esc_html__('Inactive', 'advanced-ip-blocker');
                                                }
                                                ?>
                                            </td>
                                            <td>
                                                <?php if ($theme['has_update']) : ?>
                                                    <span style="color:#d63638; font-weight:bold;">
                                                        <span class="dashicons dashicons-warning" style="vertical-align:text-bottom;"></span>
                                                        <?php 
                                                        /* translators: %s: version number */
                                                        printf(esc_html__('Update available: %s', 'advanced-ip-blocker'), esc_html($theme['new_version'])); 
                                                        ?>
                                                    </span>
                                                <?php else : ?>
                                                    <span style="color:green; font-weight:bold;">
                                                        <span class="dashicons dashicons-yes" style="vertical-align:text-bottom;"></span>
                                                        <?php esc_html_e('Up to date', 'advanced-ip-blocker'); ?>
                                                    </span>
                                                <?php endif; ?>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                <?php else : ?>
                                    <tr><td colspan="4"><?php esc_html_e('No themes found.', 'advanced-ip-blocker'); ?></td></tr>
                                <?php endif; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
				
				<!-- Server Reputation Card -->
                <div class="advaipbl-dashboard-widget widget-full" style="margin-top: 20px;">
                    <h3><?php esc_html_e('Server Reputation Check', 'advanced-ip-blocker'); ?></h3>
                    <div class="advaipbl-reputation-check" style="padding: 20px; text-align: center;">
                        
                        <div id="advaipbl-rep-status-icon" style="font-size: 48px; color: #ccc; margin-bottom: 15px;">
                            <span class="dashicons dashicons-admin-network"></span>
                        </div>
                        
                        <div id="advaipbl-rep-message">
                            <p><?php esc_html_e('Check if your web server\'s IP address is listed on any major blocklists. A bad reputation can affect SEO and email deliverability.', 'advanced-ip-blocker'); ?></p>
                        </div>

                        <button type="button" id="advaipbl-run-rep-check" class="button button-secondary" data-nonce="<?php echo esc_attr(wp_create_nonce('advaipbl_reputation_nonce')); ?>">
                            <?php esc_html_e('Check Server IP', 'advanced-ip-blocker'); ?>
                        </button>
                        
                        <div id="advaipbl-rep-loading" style="display:none; margin-top:15px;">
                            <span class="spinner is-active" style="float:none; margin:0;"></span> <?php esc_html_e('Analyzing...', 'advanced-ip-blocker'); ?>
                        </div>

                        <!-- Resultados -->
                        <div id="advaipbl-rep-details" style="display:none; text-align: left; margin-top: 20px; border-top: 1px solid #eee; padding-top: 15px;">
                            <table class="wp-list-table widefat fixed striped">
                                <thead><tr><th>Blocklist / Service</th><th>Status</th><th>Details</th></tr></thead>
                                <tbody><!-- JS llenará esto --></tbody>
                            </table>
                        </div>
                    </div>
                </div>
				
				<!-- Vulnerability Audit Card -->
                <div class="advaipbl-dashboard-widget widget-full">
                    <h3><?php esc_html_e('Vulnerability Audit', 'advanced-ip-blocker'); ?></h3>
                    <div class="advaipbl-scan-results" style="padding: 20px; text-align: center;">
                        
                        <div id="advaipbl-scan-status-icon" style="font-size: 48px; color: #ccc; margin-bottom: 15px;">
                            <span class="dashicons dashicons-shield"></span>
                        </div>
                        
                        <div id="advaipbl-scan-message">
                            <p><?php esc_html_e('Scan your themes and plugins against a database of 30,000+ known vulnerabilities.', 'advanced-ip-blocker'); ?></p>
                        </div>

                        <button type="button" id="advaipbl-run-deep-scan" class="button button-primary button-hero" data-nonce="<?php echo esc_attr(wp_create_nonce('advaipbl_deep_scan_nonce')); ?>">
                            <?php esc_html_e('Run Deep Scan', 'advanced-ip-blocker'); ?>
                        </button>
                        
                        <div id="advaipbl-scan-loading" style="display:none; margin-top:15px;">
                            <span class="spinner is-active" style="float:none; margin:0;"></span> <?php esc_html_e('Scanning...', 'advanced-ip-blocker'); ?>
                        </div>

                        <!-- Resultados-->
                        <div id="advaipbl-scan-details" style="display:none; text-align: left; margin-top: 20px; border-top: 1px solid #eee; padding-top: 15px;">
                            <table class="wp-list-table widefat fixed striped">
                                <thead><tr><th style="width: 20px;"></th><th>Plugin</th><th>Severity</th><th>Issue</th><th>Fix</th></tr></thead>
                                <tbody><!-- JS llenará esto --></tbody>
                            </table>
                        </div>

                    </div>
                </div>
                </div>
            </div>
        <?php
    }
	
    /**
     * Display the Activity Audit Log tab.
     */
    public function display_audit_log_tab() {
        if (!current_user_can('manage_options')) {
            echo '<p>' . esc_html__('You do not have permission to view this log.', 'advanced-ip-blocker') . '</p>';
            return;
        }

        $is_enabled = !empty($this->plugin->options['enable_audit_log']) && '1' === $this->plugin->options['enable_audit_log'];
        $settings_url = admin_url('admin.php?page=advaipbl_settings_page&tab=settings&sub-tab=general_settings#section-internal_security');

        ?>
        <div class="notice notice-info inline">
            <p>
                <?php
                $status_tag = sprintf(
                    '<span class="advaipbl-status-tag %s">%s</span>',
                    $is_enabled ? 'enabled' : 'disabled',
                    $is_enabled ? esc_html__('Active', 'advanced-ip-blocker') : esc_html__('Inactive', 'advanced-ip-blocker')
                );

                printf(
                    wp_kses(
                        /* translators: 1: Status tag (Active/Inactive), 2: Link to settings page. */
                        __('Activity Logging is currently %1$s. You can configure this feature in the <a href="%2$s">Settings tab</a>.', 'advanced-ip-blocker'),
                        ['a' => ['href' => []], 'span' => ['class' => []]]
                    ),
                    wp_kses_post($status_tag),
                    esc_url($settings_url)
                );
                ?>
            </p>
        </div>
        <?php
        
        // Pagination vars
        $per_page = 20;
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $current_page = isset($_GET['paged']) ? absint($_GET['paged']) : 1;
        $offset = ($current_page - 1) * $per_page;
        
        // Check if table exists to avoid fatal errors if feature was never activated
        global $wpdb;
        $table_name = $wpdb->prefix . 'advaipbl_activity_log';
        
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        if ($wpdb->get_var("SHOW TABLES LIKE '$table_name'") != $table_name) {
             $logs = [];
             $total_items = 0;
             $total_pages = 0;
        } else {
             // Fetch logs
             $logs = $this->plugin->audit_logger->get_logs($per_page, $offset);
             
             // Count total for pagination (Simple implementation)
             // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
             $total_items = $wpdb->get_var("SELECT COUNT(id) FROM $table_name");
             $total_pages = ceil($total_items / $per_page);
        }
        
        ?>
        <div class="tablenav top">
            <div class="alignleft actions">
                <button type="button" id="advaipbl-clear-audit-log-btn" class="button button-secondary delete" data-nonce="<?php echo esc_attr(wp_create_nonce('advaipbl_clear_audit_logs_nonce')); ?>">
                    <?php esc_html_e('Clear Audit Log', 'advanced-ip-blocker'); ?>
                </button>
            </div>
            <div class="tablenav-pages">
                <span class="displaying-num"><?php echo esc_html(sprintf(
                    /* translators: %s: Number of items */
                    _n('%s item', '%s items', $total_items, 'advanced-ip-blocker'),
                    number_format_i18n($total_items)
                )); ?></span>
                <?php 
                $page_links = paginate_links([
                    'base' => add_query_arg('paged', '%#%'),
                    'format' => '',
                    'total' => $total_pages,
                    'current' => $current_page
                ]);
                if ($page_links) echo wp_kses_post($page_links); 
                ?>
            </div>
            <br class="clear">
        </div>

        <table class="wp-list-table widefat fixed striped table-view-list activities">
            <thead>
                <tr>
                    <th scope="col" id="date" class="manage-column column-date sortable desc" style="width: 15%"><?php esc_html_e('Date', 'advanced-ip-blocker'); ?></th>
                    <th scope="col" id="user" class="manage-column column-user" style="width: 10%"><?php esc_html_e('User', 'advanced-ip-blocker'); ?></th>
                    <th scope="col" id="event" class="manage-column column-event column-primary" style="width: 20%"><?php esc_html_e('Event', 'advanced-ip-blocker'); ?></th>
                    <th scope="col" id="severity" class="manage-column column-severity" style="width: 10%"><?php esc_html_e('Severity', 'advanced-ip-blocker'); ?></th>
                    <th scope="col" id="ip" class="manage-column column-ip" style="width: 15%"><?php esc_html_e('IP Address', 'advanced-ip-blocker'); ?></th>
                    <th scope="col" id="details" class="manage-column column-details"><?php esc_html_e('Details', 'advanced-ip-blocker'); ?></th>
                </tr>
            </thead>
            <tbody>
                <?php if (empty($logs)) : ?>
                    <tr><td colspan="6"><?php esc_html_e('No activity recorded yet.', 'advanced-ip-blocker'); ?></td></tr>
                <?php else : foreach ($logs as $log) : 
                    $user_info = $log['user_id'] ? get_userdata($log['user_id']) : null;
                    $username = $user_info ? $user_info->user_login : __('System/Guest', 'advanced-ip-blocker');
                    $details = json_decode($log['details'], true);
                    $formatted_details = $details ? '<pre style="margin:0; white-space:pre-wrap;">' . esc_html(json_encode($details, JSON_PRETTY_PRINT)) . '</pre>' : '';
                    ?>
                    <tr>
                        <td class="date column-date" data-colname="<?php esc_attr_e('Date', 'advanced-ip-blocker'); ?>"><?php echo esc_html($log['timestamp']); ?></td>
                        <td class="user column-user" data-colname="<?php esc_attr_e('User', 'advanced-ip-blocker'); ?>">
                            <?php echo esc_html($username); ?>
                            <?php if ($log['user_id']) : ?>
                                <br><small>(ID: <?php echo esc_html($log['user_id']); ?>)</small>
                            <?php endif; ?>
                        </td>
                        <td class="event column-event column-primary" data-colname="<?php esc_attr_e('Event', 'advanced-ip-blocker'); ?>">
                            <strong><?php echo esc_html($log['event_type']); ?></strong>
                            <button type="button" class="toggle-row"><span class="screen-reader-text"><?php esc_html_e('Show more details', 'advanced-ip-blocker'); ?></span></button>
                        </td>
                        <td class="severity column-severity" data-colname="<?php esc_attr_e('Severity', 'advanced-ip-blocker'); ?>">
                            <span class="advaipbl-badge advaipbl-severity-<?php echo esc_attr($log['severity']); ?>">
                                <?php echo esc_html(ucfirst($log['severity'])); ?>
                            </span>
                        </td>
                        <td class="ip column-ip" data-colname="<?php esc_attr_e('IP Address', 'advanced-ip-blocker'); ?>"><?php echo esc_html($log['ip_address']); ?></td>
                        <td class="details column-details" data-colname="<?php esc_attr_e('Details', 'advanced-ip-blocker'); ?>"><?php echo $formatted_details; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?></td>
                    </tr>
                <?php endforeach; endif; ?>
            </tbody>
        </table>
        <?php
    }

}