<?php

if ( ! defined( 'ABSPATH' ) ) exit;

/**
 * Class ADVAIPBL_Live_Feed_Manager
 * 
 * Handles the Live Security Feed features:
 * - REST API Endpoints
 * - Shortcode rendering
 * - Enqueueing related assets
 */
class ADVAIPBL_Live_Feed_Manager {

    private $plugin;

    public function __construct( $plugin ) {
        $this->plugin = $plugin;
        
        // Hooks can be added here or in the Main class. 
        // For consistency with other managers in this codebase, hooks are usually in Main->add_hooks(),
        // but we can register internal logic here if needed.
    }

    /**
     * Registers the REST API endpoint for the live feed.
     */
    public function register_api_endpoint() {
        register_rest_route('advaipbl/v1', '/live-attacks', [
            'methods'  => 'GET',
            'callback' => [$this, 'get_live_attacks'],
            'permission_callback' => '__return_true', // Public endpoint (read-only logs)
        ]);

        register_rest_route('advaipbl/v1', '/live-feed-nonce', [
            'methods'             => 'GET',
            'callback'            => [$this, 'get_nonce'],
            'permission_callback' => '__return_true',
        ]);
    }

    /**
     * API Callback. Returns the latest attacks.
     * 
     * @param WP_REST_Request $request
     * @return WP_REST_Response
     */
    public function get_live_attacks( WP_REST_Request $request ) {
        global $wpdb;

        $since_id = $request->get_param('since');
        $since_id = isset($since_id) ? (int) $since_id : 0;
        
        $table_name = $wpdb->prefix . 'advaipbl_activity_log';
        if ($wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $table_name)) != $table_name) {
             return new WP_REST_Response(['attacks' => [], 'last_id' => 0], 200);
        }
        
        $table_name = $wpdb->prefix . 'advaipbl_logs'; 

        $sql = "SELECT log_id, ip, timestamp, log_type, message, details 
                FROM {$table_name} 
                WHERE level = 'critical' AND log_type != 'general'";

        $params = [];
        if ($since_id) {
            $sql .= " AND log_id > %d";
            $params[] = $since_id;
        }
        $sql .= " ORDER BY log_id DESC LIMIT 20";
        
        // Use separate prepare based on conditional params
        if (!empty($params)) {
             // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
             $query = $wpdb->prepare($sql, $params);
        } else {
             $query = $sql;
        }
        
        // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $results = $wpdb->get_results($query, ARRAY_A);
        
        $attacks = [];
        $last_id = 0;

        if (!empty($results)) {
            $last_id = (int) $results[0]['log_id'];
            foreach ($results as $row) {
                $details_data = json_decode($row['details'], true) ?: [];
                $location = 'Unknown Location';
                if (!empty($details_data['city']) && !empty($details_data['country'])) {
                    $location = $details_data['city'] . ', ' . $details_data['country'];
                } elseif (!empty($details_data['country'])) {
                    $location = $details_data['country'];
                }
              
                $details_message = $row['message']; 
                $log_type = $row['log_type'];
                
                switch ($log_type) {
                    case 'abuseipdb':
                        $score = $details_data['abuse_score'] ?? 'N/A';
						/* translators: %d: AbuseIPDB score. */
                        $details_message = sprintf(__('Blocked by AbuseIPDB with a score of %d%%.', 'advanced-ip-blocker'), $score);
                        break;
                    case 'advanced_rule':
                        $block_entry = $wpdb->get_row($wpdb->prepare("SELECT reason FROM {$wpdb->prefix}advaipbl_blocked_ips WHERE ip_range = %s", $row['ip']), ARRAY_A);
                        if ($block_entry && !empty($block_entry['reason'])) {
                            $details_message = $block_entry['reason'];
                        }
                        break;
                    case 'waf':
                        $rule_triggered = $details_data['rule'] ?? 'Unknown Rule';
						/* translators: %s: WAF rule name. */
                        $details_message = sprintf(__('Triggered WAF rule: %s', 'advanced-ip-blocker'), $rule_triggered);
                        break;
                    case 'asn':
                        $asn_number = $details_data['asn_number'] ?? 'N/A';
						/* translators: %s: ASN number. */
                        $details_message = sprintf(__('Blocked ASN: %s', 'advanced-ip-blocker'), $asn_number);
                        break;
                }
                
                $attacks[] = [
                    'id'          => (int) $row['log_id'],
                    'time'        => human_time_diff(strtotime($row['timestamp'])) . ' ago',
                    'ip'          => esc_html($row['ip']),
                    'type'        => esc_html(ucwords(str_replace('_', ' ', $log_type))),
                    'location'    => esc_html($location),
                    'method'      => esc_html($details_data['method'] ?? 'N/A'),
                    'details'     => esc_html($details_message),
                    'user_agent'  => esc_html($details_data['user_agent'] ?? 'N/A'),
                    'uri'         => esc_html($details_data['uri'] ?? ($details_data['url'] ?? '')),
                ];
            }
        }
        
        return new WP_REST_Response([
            'attacks'  => $attacks,
            'last_id'  => $last_id,
        ], 200);
    }

    /**
     * API Callback for Nonce.
     */
    public function get_nonce() {
        return new WP_REST_Response( [
            'nonce' => wp_create_nonce( 'wp_rest' )
        ], 200 );
    }

    /**
     * Shortcode renderer [advaipbl_live_feed]
     */
    public function render_shortcode($atts) {
        // Use the proper paths relative to this file's location in includes/
        // Original: plugin_dir_url(dirname(__FILE__)) . 'js/...'
        // If this file is in includes/, dirname is includes. 
        // plugin_dir_url(includes) -> yields URL to includes.
        // But 'js/' is usually at the root of the plugin or assets/.
        // Original main was in includes/ too? checking...
        // Main path: .../includes/class-advaipbl-main.php
        // The original code used: plugin_dir_url(dirname(__FILE__)) . 'js/advaipbl-live-feed.js'
        // dirname(__FILE__) = .../includes
        // plugin_dir_url via dirname would point to the includes folder URL.
        // BUT 'js' folder is likely parallel to 'includes', not inside it.
        // Original code logic: plugin_dir_url(...) returns URL with trailing slash.
        // If dirname is .../includes, url is https://.../includes/
        // Then . 'js/...' -> https://.../includes/js/...
        // This implies /includes/js/ exists?
        // Re-checking list_dir: js is at logical root, includes is at logical root.
        // Wait, list_dir of includes showed 'lib' inside.
        // list_dir of root (implicit from previous context) showed 'js' folder.
        // So 'js' is a sibling of 'includes'.
        // So the original code `plugin_dir_url(dirname(__FILE__))` pointing to includes/ seems wrong if it appends 'js/' directly, unless 'js' IS inside includes.
        // Let's use `plugin_dir_url( dirname( __DIR__ ) )` to go up one level safely.
        // dirname(__DIR__) from includes/class... -> .../plugin-root
        
        $root_url = plugin_dir_url( dirname( __FILE__ ) ); // Points to .../includes/ OR plugin root?
        // plugin_dir_url accepts a FILE path.
        // plugin_dir_url( __FILE__ ) ->  .../includes/
        // plugin_dir_url( dirname( __FILE__ ) . '/../advanced-ip-blocker.php' ) -> Root.
        
        // Safer approach used in many plugins:
        $root_url = plugins_url( '/', dirname( __FILE__ ) ); 

        wp_enqueue_script('advaipbl-live-feed-js', $root_url . 'js/advaipbl-live-feed.js', ['jquery'], ADVAIPBL_VERSION, true);

        wp_localize_script('advaipbl-live-feed-js', 'advaipbl_feed_data', [
            'api_url' => get_rest_url(null, 'advaipbl/v1/live-attacks'),
            'nonce_url' => get_rest_url(null, 'advaipbl/v1/live-feed-nonce'),
            'text'    => [
                'blocked_from' => __('blocked from', 'advanced-ip-blocker'),
                'type'         => __('Type', 'advanced-ip-blocker'),
                'method'       => __('Method', 'advanced-ip-blocker'),
                'details'      => __('Details', 'advanced-ip-blocker'),
                'uri'          => __('URI', 'advanced-ip-blocker'),
                'user_agent'   => __('User Agent', 'advanced-ip-blocker'),
            ]
        ]);

        $logo_url_desktop = $root_url . 'assets/img/logo-ligth.png';
        $logo_url_mobile = $root_url . 'assets/img/icon-256x256.png';

        $css = '<style type="text/css">#advaipbl-live-feed-container{background-color:#1e293b;color:#e2e8f0;font-family:SFMono-Regular,Consolas,"Liberation Mono",Menlo,Courier,monospace;padding:20px;border-radius:8px;border:1px solid #334155;box-shadow:0 4px 15px rgba(0,0,0,.3);overflow:hidden;margin:2em 0}#advaipbl-live-feed-container h3{color:#fff;margin-top:0;margin-bottom:15px;font-size:16px;border-bottom:1px solid #334155;padding-bottom:10px;display:flex;align-items:center;justify-content:space-between}.advaipbl-feed-title{display:flex;align-items:center}.live-dot{font-size:10px;margin-right:10px;color:#22c55e;animation:advaipbl-blink 1.5s infinite}.advaipbl-feed-logo a{display:block;line-height:0}.advaipbl-feed-logo img{max-height:24px;width:auto;display:block}.advaipbl-feed-logo .logo-desktop{display:block}.advaipbl-feed-logo .logo-mobile{display:none}#advaipbl-live-feed-container #advaipbl-live-feed-list{list-style-type:none;margin:0;padding:0;max-height:400px;overflow-y:auto;font-size:13px}.feed-item{padding:12px 5px;border-bottom:1px solid #334155;animation:advaipbl-fade-in .5s ease-out}.feed-item:first-child{border-top:1px solid #334155}.feed-item .feed-main-line{display:flex;flex-wrap:wrap;gap:5px 15px;align-items:center;margin-bottom:8px}.feed-item .feed-details-grid{display:grid;grid-template-columns:100px 1fr;gap:4px 10px;padding-left:10px;color:#94a3b8}.feed-item .feed-label{font-weight:700;color:#64748b}.feed-item .feed-value{word-break:break-all}.feed-item .feed-value code{background:#334155;padding:1px 4px;border-radius:3px;color:#cbd5e1}.feed-item .ip{font-weight:700;color:#f87171}.feed-item .type-tag{background-color:#475569;color:#e2e8f0;padding:2px 6px;border-radius:4px;font-size:11px;font-weight:700}.feed-item .location{color:#94a3b8}.feed-item .time{color:#64748b;font-style:italic;margin-left:auto}.feed-item.placeholder{color:#64748b;justify-content:center;font-style:italic;display:flex}@keyframes advaipbl-blink{0%,to{opacity:1}50%{opacity:.3}}@keyframes advaipbl-fade-in{from{opacity:0;transform:translateY(-10px)}to{opacity:1;transform:translateY(0)}}@media screen and (max-width:600px){.advaipbl-feed-logo .logo-desktop{display:none}.advaipbl-feed-logo .logo-mobile{display:block}.feed-item .feed-details-grid{grid-template-columns:80px 1fr}}</style>';
        
        $html = '
        <div id="advaipbl-live-feed-container">
            <h3>
                <span class="advaipbl-feed-title">
                    <span class="live-dot">⬤</span>
                    Live Security Feed
                </span>
                <span class="advaipbl-feed-logo">
                    <a href="https://advaipbl.com/" target="_blank" rel="noopener">
                        <img src="' . esc_url($logo_url_desktop) . '" alt="Advanced IP Blocker" class="logo-desktop">
                        <img src="' . esc_url($logo_url_mobile) . '" alt="Advanced IP Blocker" class="logo-mobile">
                    </a>
                </span>
            </h3>
            <ul id="advaipbl-live-feed-list">
                <li class="feed-item placeholder">Awaiting security events...</li>
            </ul>
        </div>';

        return $css . $html;
    }
}
