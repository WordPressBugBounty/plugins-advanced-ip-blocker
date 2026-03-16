<?php

if ( ! defined( 'ABSPATH' ) ) exit;

class ADVAIPBL_Site_Scanner {

    private $plugin;

    public function __construct( ADVAIPBL_Main $plugin_instance ) {
        $this->plugin = $plugin_instance;
    }

    /**
     * Realiza un escaneo completo del entorno local.
     * @return array Resultados del escaneo.
     */
    public function run_local_scan() {
        $results = [];

        // PHP Version
        if ( ($this->plugin->options['scan_check_php'] ?? '1') !== '0' ) {
            $results['php'] = $this->check_php_version();
        } else {
            $results['php'] = [ 'status' => 'skipped', 'message' => __( 'Skipped by settings.', 'advanced-ip-blocker' ), 'current' => phpversion() ];
        }

        // WordPress Version
        if ( ($this->plugin->options['scan_check_wp'] ?? '1') !== '0' ) {
            $results['wordpress'] = $this->check_wp_version();
        } else {
            $results['wordpress'] = [ 'status' => 'skipped', 'message' => __( 'Skipped by settings.', 'advanced-ip-blocker' ), 'current' => get_bloginfo( 'version' ) ];
        }

        $results['database'] = $this->check_db_version();

        // Debug Mode
        if ( ($this->plugin->options['scan_check_debug'] ?? '1') !== '0' ) {
            $results['debug_mode'] = $this->check_debug_mode();
        } else {
            $results['debug_mode'] = [ 'status' => 'skipped', 'message' => __( 'Skipped by settings.', 'advanced-ip-blocker' ) ];
        }

        // Pending Updates
        if ( ($this->plugin->options['scan_check_updates'] ?? '1') !== '0' ) {
            $results['updates'] = $this->check_pending_updates();
        } else {
            $results['updates'] = [
                'plugins' => 0, 
                'themes' => 0, 
                'status' => 'skipped', 
                'plugin_details' => [], 
                'theme_details' => [], 
                'details' => []
            ];
        }

        // SSL Check
        if ( ($this->plugin->options['scan_check_ssl'] ?? '1') !== '0' ) {
            $results['ssl'] = $this->check_ssl();
        } else {
            $results['ssl'] = [ 'status' => 'skipped', 'message' => __( 'Skipped by settings.', 'advanced-ip-blocker' ) ];
        }

        $results['themes_list'] = $this->get_themes_status_list();

        return apply_filters( 'advaipbl_site_scanner_results', $results );
    }

    /**
     * Get detailed status list of all installed themes.
     * @return array
     */
    private function get_themes_status_list() {
        $all_themes = wp_get_themes();
        $update_data = get_site_transient('update_themes');
        $active_theme = wp_get_theme();
        $parent_theme = $active_theme->parent();
        
        $themes_list = [];

        foreach ($all_themes as $slug => $theme) {
            $is_active = ($active_theme->get_stylesheet() === $slug);
            $is_parent = ($parent_theme && $parent_theme->get_stylesheet() === $slug);
            
            $has_update = false;
            $update_version = '';
            if (isset($update_data->response[$slug])) {
                $has_update = true;
                $update_info = $update_data->response[$slug];
                if (is_array($update_info)) {
                    $update_version = $update_info['new_version'] ?? '';
                } elseif (is_object($update_info)) {
                    $update_version = $update_info->new_version ?? '';
                }
            }

            $themes_list[$slug] = [
                'name' => $theme->get('Name'),
                'version' => $theme->get('Version'),
                'is_active' => $is_active,
                'is_parent' => $is_parent,
                'has_update' => $has_update,
                'new_version' => $update_version,
                'author' => $theme->get('Author'),
                'screenshot' => $theme->get_screenshot(),
            ];
        }

        return $themes_list;
    }

    private function check_php_version() {
        $version = phpversion();
        // Definición de versiones seguras (EOL Schedule)
        // Fuente: https://www.php.net/supported-versions.php
        $status = 'critical'; // Por defecto
        $message = __('Your PHP version is obsolete and insecure. Update immediately.', 'advanced-ip-blocker');

        if (version_compare($version, '8.2', '>=')) {
            $status = 'good';
            $message = __('Up to date and secure.', 'advanced-ip-blocker');
        } elseif (version_compare($version, '8.1', '>=')) {
            $status = 'warning';
            $message = __('Security updates only. Consider upgrading soon.', 'advanced-ip-blocker');
        } elseif (version_compare($version, '8.0', '>=')) {
            $status = 'critical'; // EOL desde Nov 2023
            $message = __('End of Life. No security updates. Upgrade needed.', 'advanced-ip-blocker');
        }

        return ['current' => $version, 'status' => $status, 'message' => $message];
    }

    private function check_wp_version() {
        global $wp_version;
        $core_updates = get_site_transient('update_core');
        
        $status = 'good';
        $message = __('You are running the latest version.', 'advanced-ip-blocker');

        if (isset($core_updates->updates) && !empty($core_updates->updates)) {
            foreach ($core_updates->updates as $update) {
                if ($update->response === 'upgrade') {
                    $status = 'critical';
					 /* translators: %s: The new WordPress version available. */
                    $message = sprintf(__('Outdated. New version %s is available.', 'advanced-ip-blocker'), $update->current);
                    break;
                }
            }
        }

        return ['current' => $wp_version, 'status' => $status, 'message' => $message];
    }
    
    private function check_db_version() {
        global $wpdb;
        // Obtenemos la versión directamente con una consulta SQL estándar a través de WPDB
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $version = $wpdb->get_var("SELECT VERSION()");
        
        return ['current' => $version, 'status' => 'info', 'message' => __('Database engine version.', 'advanced-ip-blocker')];
    }

    private function check_debug_mode() {
        if (defined('WP_DEBUG') && WP_DEBUG) {
            if (defined('WP_DEBUG_LOG') && WP_DEBUG_LOG && defined('WP_DEBUG_DISPLAY') && !WP_DEBUG_DISPLAY) {
                return ['status' => 'warning', 'message' => __('Enabled (Log Only). Good for dev, risky for prod.', 'advanced-ip-blocker')];
            }
            return ['status' => 'critical', 'message' => __('Enabled and displaying errors. Security risk!', 'advanced-ip-blocker')];
        }
        return ['status' => 'good', 'message' => __('Disabled. (Secure)', 'advanced-ip-blocker')];
    }

    private function check_pending_updates() {
        $plugin_updates = get_site_transient('update_plugins');
        $theme_updates = get_site_transient('update_themes');
        
        $p_count = isset($plugin_updates->response) ? count($plugin_updates->response) : 0;
        $t_count = isset($theme_updates->response) ? count($theme_updates->response) : 0;
        
        $status = ($p_count + $t_count === 0) ? 'good' : 'warning';
        if ($p_count + $t_count > 5) $status = 'critical'; // Acumulación peligrosa

        
        $details = [];
        if (isset($plugin_updates->response) && is_array($plugin_updates->response)) {
            $details = array_merge($details, $plugin_updates->response);
        }
        if (isset($theme_updates->response) && is_array($theme_updates->response)) {
            $details = array_merge($details, $theme_updates->response);
        }

        return [
            'plugins' => $p_count,
            'themes' => $t_count,
            'status' => $status,
            'plugin_details' => $plugin_updates->response ?? [],
            'theme_details'  => $theme_updates->response ?? [],
            'details'        => $details // Unified list for UI
        ];
    }
    
    private function check_ssl() {
        $site_url = get_site_url();
        $is_configured_ssl = (stripos($site_url, 'https://') === 0);

        return (is_ssl() || $is_configured_ssl)
            ? ['status' => 'good', 'message' => __('Active.', 'advanced-ip-blocker')]
            : ['status' => 'critical', 'message' => __('Inactive. Your site is not using HTTPS.', 'advanced-ip-blocker')];
    }
	
	/**
     * Escanea plugins instalados contra la API remota de AIB.
     * @return array
     */
    public function check_vulnerabilities_via_api() {
        if ( isset($this->plugin->options['scan_check_vulnerabilities']) && $this->plugin->options['scan_check_vulnerabilities'] === '0' ) {
            return ['status' => 'skipped', 'count' => 0, 'details' => [], 'message' => __('Skipped by settings.', 'advanced-ip-blocker')];
        }

        if ( ! function_exists( 'get_plugins' ) ) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }
        
        $payload = [];


        $all_plugins = get_plugins();
        foreach ( $all_plugins as $path => $data ) {
            $slug = dirname( $path );
            if ( $slug === '.' ) $slug = basename( $path, '.php' );
            $payload[$slug] = $data['Version'];
        }


        $all_themes = wp_get_themes();
        foreach ( $all_themes as $slug => $theme ) {
            $payload[$slug] = $theme->get('Version');
        }

        $api_url = 'https://advaipbl.com/wp-json/aib-scanner/v2/check';
        $site_hash = hash('sha256', get_site_url());
        
        $headers = [
            'Content-Type' => 'application/json',
            'X-AIB-Site-Hash' => $site_hash
        ];

        // Incluir V3 Token y saltar a endpoint V3 si existe
        if (!empty($this->plugin->options['api_token_v3'])) {
            $api_url = 'https://advaipbl.com/wp-json/aib-api/v3/scanner/check';
            $headers['Authorization'] = 'Bearer ' . $this->plugin->options['api_token_v3'];
        }

        $response = wp_remote_post( $api_url, [
            'body'    => wp_json_encode( $payload ),
            'headers' => $headers,
            'timeout' => 15 // Subimos un poco el timeout por si la lista es larga
        ]);

        if ( is_wp_error( $response ) ) {
            return ['status' => 'error', 'message' => 'API Error'];
        }
        
        $body = wp_remote_retrieve_body( $response );
        $vulnerabilities = json_decode( $body, true );
        
        if ( empty( $vulnerabilities ) ) {
            return ['status' => 'clean', 'count' => 0, 'details' => []];
        }

        return [
            'status' => 'vulnerable', 
            'count' => count( $vulnerabilities ), 
            'details' => $vulnerabilities
        ];
    }
	
	/**
     * Comprueba la reputación de la IP del servidor en las listas de bloqueo configuradas.
     * @return array Resultados del chequeo.
     */
    public function check_server_reputation() {
        $server_ip = $this->plugin->get_server_ip();
        
        if ( ! $server_ip ) {
            return [
                'status' => 'error',
                'message' => __('Could not determine server IP address.', 'advanced-ip-blocker')
            ];
        }

        $results = [
            'ip' => $server_ip,
            'status' => 'clean', // Asumimos limpio hasta demostrar lo contrario
            'checks' => []
        ];

        $aib_status = 'clean';
        $aib_detail = '';

        // 1. Remote Check (API Real)
        $api_check_url = 'https://advaipbl.com/wp-json/aib-scanner/v2/check-ip?ip=' . $server_ip;
        $site_hash = hash('sha256', get_site_url());

        $headers = [
            'X-AIB-Site-Hash' => $site_hash
        ];

        // Incluir V3 Token y saltar a endpoint V3 si existe
        if (!empty($this->plugin->options['api_token_v3'])) {
            $api_check_url = 'https://advaipbl.com/wp-json/aib-api/v3/scanner/check-ip?ip=' . $server_ip;
            $headers['Authorization'] = 'Bearer ' . $this->plugin->options['api_token_v3'];
        }
        
        $response = wp_remote_get($api_check_url, [
            'timeout' => 5,
            'headers' => $headers
        ]);
        
        if ( is_wp_error($response) ) {
            $aib_status = 'error';
            $aib_detail = __('API Error', 'advanced-ip-blocker');
        } else {
            $data = json_decode(wp_remote_retrieve_body($response), true);
            if (isset($data['listed']) && $data['listed'] === true) {
                $aib_status = 'listed';
                $results['status'] = 'blacklisted'; // Flags global status
            }
        }
        
        $results['checks']['aib'] = [
            'label' => __('AIB Community Network', 'advanced-ip-blocker'),
            'status' => $aib_status,
            'detail' => $aib_detail
        ];

        // 2. Local DB Check (Information only)
        $local_status = 'clean';
        if ( isset($this->plugin->community_manager) && $this->plugin->community_manager->is_ip_blocked($server_ip) ) {
            $local_status = 'listed';
            // We don't affect global result here to avoid the user Confusion
        }
        $results['checks']['local_db'] = [
            'label' => __('Local Firewall Database', 'advanced-ip-blocker'),
            'status' => $local_status,
            'detail' => $local_status === 'listed' ? __('Blocked locally (Aggregated)', 'advanced-ip-blocker') : ''
        ];

        $spamhaus_status = 'skipped';
        if ( ! empty($this->plugin->options['enable_spamhaus_asn']) && isset($this->plugin->asn_manager) ) {
             // Necesitamos geolocalizar la IP del servidor primero
             $location = $this->plugin->geolocation_manager->fetch_location($server_ip);
             $asn = $this->plugin->asn_manager->extract_asn_from_data($location);
             
             if ( $asn ) {
                 $spamhaus_list = get_option('advaipbl_spamhaus_asn_list', []);
                 if ( in_array($asn, $spamhaus_list, true) ) {
                     $spamhaus_status = 'listed';
                     $results['status'] = 'blacklisted';
                 } else {
                     $spamhaus_status = 'clean';
                 }
             } else {
                 $spamhaus_status = 'unknown'; // No se pudo obtener ASN
             }
        }
        $results['checks']['spamhaus'] = [
            'label' => __('Spamhaus ASN DROP', 'advanced-ip-blocker'),
            'status' => $spamhaus_status
        ];

        $abuse_status = 'skipped';
        if ( ! empty($this->plugin->options['enable_abuseipdb']) && ! empty($this->plugin->options['abuseipdb_api_key']) ) {
            $check = $this->plugin->abuseipdb_manager->check_ip($server_ip);
            if ( $check && isset($check['score']) ) {
                if ( $check['score'] > 0 ) {
                    $abuse_status = ($check['score'] > 20) ? 'listed' : 'warning'; // Umbral arbitrario
                    if ($check['score'] > 20) $results['status'] = 'blacklisted';
                } else {
                    $abuse_status = 'clean';
                }
                $results['checks']['abuseipdb'] = [
                    'label' => __('AbuseIPDB', 'advanced-ip-blocker'),
                    'status' => $abuse_status,
					/* translators: %d%%: Score, e.g. 100/100 */
                    'detail' => sprintf(__('Score: %d%%', 'advanced-ip-blocker'), $check['score'])
                ];
            }
        } else {
             $results['checks']['abuseipdb'] = [
                'label' => __('AbuseIPDB', 'advanced-ip-blocker'),
                'status' => 'skipped',
                'detail' => __('API Key not configured', 'advanced-ip-blocker')
            ];
        }

        return $results;
    }


    /**
     * Executes a full scan (Local + Server Reputation + Vulnerabilities) and sends an HTML report via email.
     * @param string $to_email Destination email address.
     * @param bool   $is_manual Whether the scan was triggered manually.
     */
    public function run_full_scan_and_email($to_email, $is_manual = false) {
        // Fallback for scheduled scans (where $to_email might be null)
        if (empty($to_email)) {
            $configured_email = $this->plugin->options['scan_notification_email'] ?? '';
            $to_email = !empty($configured_email) ? $configured_email : get_option('admin_email');
        }

        // 1. Run Scans
        $local_scan = $this->run_local_scan();
        $server_rep = $this->check_server_reputation();
        $vulns = $this->check_vulnerabilities_via_api();
        
        // 2. Conditional Sending Logic (DeepScan Automation)
        // If it's NOT a manual scan, we only send the report if there are issues.
        if ( ! $is_manual ) {
            $trigger = $this->plugin->options['scan_email_trigger'] ?? 'any_issue';
            
            $has_vuln_or_critical = false;
            $has_any_issue = false;

            // Evaluate Vulnerabilities & Blacklists (Agency triggers)
            if ($vulns['status'] === 'vulnerable' || $vulns['status'] === 'error') {
                $has_vuln_or_critical = true;
            }
            if ($server_rep['status'] === 'blacklisted' || $server_rep['status'] === 'error') {
                $has_vuln_or_critical = true;
            }
            
            // Evaluate Environment Criticals (also severe enough for agency alert)
            if ($local_scan['php']['status'] === 'critical' || $local_scan['wordpress']['status'] === 'critical' || $local_scan['debug_mode']['status'] === 'critical' || $local_scan['ssl']['status'] === 'critical') {
                 $has_vuln_or_critical = true;
            }

            // Evaluate general issues
            if ($has_vuln_or_critical) {
                $has_any_issue = true;
            } else {
                 if ($local_scan['updates']['status'] !== 'good' && $local_scan['updates']['status'] !== 'skipped') $has_any_issue = true;
                 if ($local_scan['php']['status'] !== 'good' && $local_scan['php']['status'] !== 'skipped') $has_any_issue = true;
                 if ($local_scan['wordpress']['status'] !== 'good' && $local_scan['wordpress']['status'] !== 'skipped') $has_any_issue = true;
                 if ($local_scan['ssl']['status'] !== 'good' && $local_scan['ssl']['status'] !== 'skipped') $has_any_issue = true;
                 if ($local_scan['debug_mode']['status'] !== 'good' && $local_scan['debug_mode']['status'] !== 'skipped') $has_any_issue = true;
            }

            // Apply Trigger Rules
            if ($trigger === 'vulnerabilities_only' && !$has_vuln_or_critical) {
                return; // Agency mode: silent unless strictly critical
            }
            
            if ($trigger === 'any_issue' && !$has_any_issue) {
                return; // Standard mode: silent if 100% clean
            }
            
            // if $trigger === 'always', we proceed regardless
        }

        // 3. Prepare Data for Email
        $site_url = get_site_url();
        $date = date_i18n(get_option('date_format') . ' ' . get_option('time_format'));
        
        // 4. Construct HTML Email using standard template
        /* translators: 1: Site Name, 2: Date */
        $subject = sprintf(__('[%1$s] DeepScan Security Report - %2$s', 'advanced-ip-blocker'), get_bloginfo('name'), $date);
        $template_title = __('Security Scan Report', 'advanced-ip-blocker');

        ob_start();
        ?>
        <p><?php 
        /* translators: %s: Site URL */
        printf(esc_html__('Site: %s', 'advanced-ip-blocker'), '<strong>' . esc_html($site_url) . '</strong>'); 
        ?><br>
        <?php 
        /* translators: %s: Date */
        printf(esc_html__('Date: %s', 'advanced-ip-blocker'), esc_html($date)); 
        ?></p>

        <!-- Pending Updates (New Section) -->
        <?php if ($local_scan['updates']['plugins'] > 0 || $local_scan['updates']['themes'] > 0): ?>
            <h3 style="margin-top: 20px; border-bottom: 1px solid #d63638; padding-bottom: 10px; color: #d63638;"><?php esc_html_e('Pending Updates', 'advanced-ip-blocker'); ?></h3>
            <p><strong><?php 
                /* translators: 1: Plugin count, 2: Theme count */
                printf(esc_html__('Warning: Found %1$d outdated plugins and %2$d outdated themes.', 'advanced-ip-blocker'), absint($local_scan['updates']['plugins']), absint($local_scan['updates']['themes'])); 
            ?></strong></p>
            
            <ul style="color: #d63638;">
                <?php 
                // Plugins
                if (!empty($local_scan['updates']['plugin_details'])) {
                    foreach ($local_scan['updates']['plugin_details'] as $slug => $data) {
                        $new_version = is_object($data) ? $data->new_version : ($data['new_version'] ?? '?');
                        /* translators: 1: Plugin Name, 2: Version */
                        echo '<li>' . sprintf(esc_html__('Plugin: %1$s (New: %2$s)', 'advanced-ip-blocker'), esc_html($slug), esc_html($new_version)) . '</li>';
                    }
                }
                // Themes
                if (!empty($local_scan['updates']['theme_details'])) {
                    foreach ($local_scan['updates']['theme_details'] as $slug => $data) {
                        $new_version = is_object($data) ? $data->new_version : ($data['new_version'] ?? '?');
                        /* translators: 1: Theme Name, 2: Version */
                        echo '<li>' . sprintf(esc_html__('Theme: %1$s (New: %2$s)', 'advanced-ip-blocker'), esc_html($slug), esc_html($new_version)) . '</li>';
                    }
                }
                ?>
            </ul>
        <?php else: ?>
            <h3 style="margin-top: 20px; border-bottom: 1px solid #00a32a; padding-bottom: 10px; color: #00a32a;"><?php esc_html_e('Updates Status', 'advanced-ip-blocker'); ?></h3>
            <p style="color: #00a32a;"><?php esc_html_e('All plugins and themes are up to date.', 'advanced-ip-blocker'); ?></p>
        <?php endif; ?>

        <!-- Environment Health -->
        <h3 style="margin-top: 20px; border-bottom: 1px solid #eee; padding-bottom: 10px;"><?php esc_html_e('Environment Health', 'advanced-ip-blocker'); ?></h3>
        <table style="width: 100%; border-collapse: collapse; margin-top: 10px;">
            <tr>
                <td style="padding: 8px; border-bottom: 1px solid #f0f0f1;">PHP Version</td>
                <td style="padding: 8px; border-bottom: 1px solid #f0f0f1;">
                    <?php echo esc_html($local_scan['php']['current']); ?>
                    <span style="display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; color: #fff; background-color: <?php echo ($local_scan['php']['status'] === 'good' ? '#00a32a' : ($local_scan['php']['status'] === 'warning' ? '#dba617' : '#d63638')); ?>;">
                        <?php echo esc_html(strtoupper($local_scan['php']['status'])); ?>
                    </span>
                </td>
            </tr>
            <tr>
                <td style="padding: 8px; border-bottom: 1px solid #f0f0f1;">WordPress</td>
                <td style="padding: 8px; border-bottom: 1px solid #f0f0f1;">
                    <?php echo esc_html($local_scan['wordpress']['current']); ?>
                    <span style="display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; color: #fff; background-color: <?php echo ($local_scan['wordpress']['status'] === 'good' ? '#00a32a' : ($local_scan['wordpress']['status'] === 'warning' ? '#dba617' : '#d63638')); ?>;">
                        <?php echo esc_html(strtoupper($local_scan['wordpress']['status'])); ?>
                    </span>
                </td>
            </tr>
             <tr>
                <td style="padding: 8px; border-bottom: 1px solid #f0f0f1;">SSL</td>
                <td style="padding: 8px; border-bottom: 1px solid #f0f0f1;">
                    <span style="display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; color: #fff; background-color: <?php echo ($local_scan['ssl']['status'] === 'good' ? '#00a32a' : ($local_scan['ssl']['status'] === 'warning' ? '#dba617' : '#d63638')); ?>;">
                        <?php echo esc_html(strtoupper($local_scan['ssl']['status'])); ?>
                    </span>
                </td>
            </tr>
             <tr>
                <td style="padding: 8px; border-bottom: 1px solid #f0f0f1;">Debug Mode</td>
                <td style="padding: 8px; border-bottom: 1px solid #f0f0f1;">
                    <span style="display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; color: #fff; background-color: <?php echo ($local_scan['debug_mode']['status'] === 'good' ? '#00a32a' : ($local_scan['debug_mode']['status'] === 'warning' ? '#dba617' : '#d63638')); ?>;">
                        <?php echo esc_html(strtoupper($local_scan['debug_mode']['status'])); ?>
                    </span>
                </td>
            </tr>
        </table>

        <!-- Server Reputation -->
        <h3 style="margin-top: 25px; border-bottom: 1px solid #eee; padding-bottom: 10px;"><?php esc_html_e('Server IP Reputation', 'advanced-ip-blocker'); ?></h3>
        <p><?php 
        /* translators: %s: Server IP Address */
        printf(esc_html__('Server IP: %s', 'advanced-ip-blocker'), esc_html($server_rep['ip'])); 
        ?></p>
        <table style="width: 100%; border-collapse: collapse; margin-top: 10px;">
            <?php foreach ($server_rep['checks'] as $check) : ?>
            <tr>
                <td style="padding: 8px; border-bottom: 1px solid #f0f0f1;"><?php echo esc_html($check['label']); ?></td>
                <td style="padding: 8px; border-bottom: 1px solid #f0f0f1;">
                    <?php 
                    $badge_bg = ($check['status'] === 'clean') ? '#00a32a' : (($check['status'] === 'skipped') ? '#2271b1' : '#d63638');
                    ?>
                    <span style="display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; color: #fff; background-color: <?php echo esc_attr($badge_bg); ?>;">
                        <?php echo esc_html(strtoupper($check['status'])); ?>
                    </span>
                    <?php if (!empty($check['detail'])) echo ' <small>(' . esc_html($check['detail']) . ')</small>'; ?>
                </td>
            </tr>
            <?php endforeach; ?>
        </table>
        
        <!-- Vulnerabilities -->
        <h3 style="margin-top: 25px; border-bottom: 1px solid #eee; padding-bottom: 10px;"><?php esc_html_e('Vulnerabilities', 'advanced-ip-blocker'); ?></h3>
        <?php if ($vulns['status'] === 'clean') : ?>
            <p style="color: #00a32a;"><strong><?php esc_html_e('No known vulnerabilities found in your plugins/themes.', 'advanced-ip-blocker'); ?></strong></p>
        <?php elseif ($vulns['status'] === 'error') : ?>
             <p style="color: #dba617;"><strong><?php esc_html_e('Could not check vulnerabilities (API Error).', 'advanced-ip-blocker'); ?></strong></p>
        <?php else : ?>
            <p style="color: #d63638;"><strong><?php 
            /* translators: %d: Number of vulnerabilities found */
            printf(esc_html__('Found %d vulnerabilities!', 'advanced-ip-blocker'), intval($vulns['count'])); 
            ?></strong></p>
            <?php foreach ($vulns['details'] as $slug => $info) : 
                // Normalize info if needed (it should be an array from json_decode)
                $v = is_array($info) ? $info : [];
                $title = $v['title'] ?? __('Unknown Vulnerability', 'advanced-ip-blocker');
                $severity = $v['severity'] ?? 'Unknown';
                $cve = $v['cve'] ?? '';
                $cve_link = $v['cve_link'] ?? '';
                $description = $v['description'] ?? '';
                $fix = $v['fix'] ?? __('No fix details available.', 'advanced-ip-blocker');

                // Color code for severity
                $severity_color = '#dba617'; // Medium/Low (Orange/Yellowish)
                if (stripos($severity, 'High') !== false || stripos($severity, 'Critical') !== false) {
                    $severity_color = '#d63638'; // Red
                }
            ?>
                <div style="margin-bottom: 20px; border-left: 4px solid <?php echo esc_attr($severity_color); ?>; padding-left: 15px;">
                    <p style="margin: 0 0 5px 0;"><strong><?php echo esc_html($slug); ?></strong></p>
                    <p style="margin: 0 0 5px 0; font-size: 14px; color: #333;"><strong><?php echo esc_html($title); ?></strong></p>
                    
                    <p style="margin: 0 0 5px 0; font-size: 12px;">
                        <span style="background-color: <?php echo esc_attr($severity_color); ?>; color: #fff; padding: 2px 6px; border-radius: 3px; font-weight: bold;"><?php echo esc_html($severity); ?></span>
                        <?php if ($cve): ?>
                            &nbsp; <a href="<?php echo esc_url($cve_link); ?>" target="_blank" style="color: #0073aa; text-decoration: none;"><?php echo esc_html($cve); ?></a>
                        <?php endif; ?>
                    </p>

                    <?php if ($description): ?>
                        <p style="margin: 5px 0; font-size: 13px; color: #666; font-style: italic;">
                            <?php echo wp_kses_post($description); ?>
                        </p>
                    <?php endif; ?>

                    <p style="margin: 5px 0; font-size: 12px;">
                        <strong><?php esc_html_e('Remediation:', 'advanced-ip-blocker'); ?></strong> <?php echo esc_html($fix); ?>
                    </p>
                </div>
            <?php endforeach; ?>
        <?php endif; ?>

        <?php
        $content_html = ob_get_clean();
        
        // Use the main plugin's template engine
        // Use the main plugin's template engine (Delegated to Notification Manager)
        if (isset($this->plugin->notification_manager)) {
            $body = $this->plugin->notification_manager->get_html_email_template($template_title, $content_html);
            // Set content type filter
            add_filter( 'wp_mail_content_type', [$this->plugin->notification_manager, 'set_html_mail_content_type'] );
            
            wp_mail($to_email, $subject, $body);
            
            // Remove filter
            remove_filter( 'wp_mail_content_type', [$this->plugin->notification_manager, 'set_html_mail_content_type'] );
        } else {
             // Fallback logic in case notification manager is inexplicably missing, preventing fatal error
             $body = $content_html; 
             wp_mail($to_email, $subject, $body);
        }
    }
}