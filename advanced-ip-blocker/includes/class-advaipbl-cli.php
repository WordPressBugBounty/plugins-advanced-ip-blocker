<?php
/**
 * Manages the Advanced IP Blocker plugin.
 *
 * Provides a complete set of commands to manage all aspects of the
 * plugin, including blocking, whitelisting, session management,
 * configuration, and logs, without needing to access the WordPress admin panel.
 *
 * @package advaipbl
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
    return;
}

class ADVAIPBL_CLI extends WP_CLI_Command {

    private $tfa_manager;

    public function __construct() {
    if ( function_exists( 'switch_to_locale' ) ) {
        switch_to_locale( 'en_US' );
    }

    // Instanciamos el manager de 2FA solo si la clase existe (cargada condicionalmente).
    if ( class_exists('ADVAIPBL_2FA_Manager') ) {
        $main_instance = ADVAIPBL_Main::get_instance();
        $this->tfa_manager = new ADVAIPBL_2FA_Manager($main_instance);
    } else {
        $this->tfa_manager = null;
    }
}

    private function is_valid_ip_or_range($input) {
        $input = trim($input);
        if (filter_var($input, FILTER_VALIDATE_IP)) { return true; }
        if (strpos($input, '/') !== false) {
            list($subnet, $bits) = explode('/', $input, 2);
            return filter_var($subnet, FILTER_VALIDATE_IP) && is_numeric($bits) && $bits >= 0 && $bits <= 32;
        }
        if (strpos($input, '-') !== false) {
            list($start_ip, $end_ip) = explode('-', $input, 2);
            return filter_var(trim($start_ip), FILTER_VALIDATE_IP) && filter_var(trim($end_ip), FILTER_VALIDATE_IP);
        }
        return false;
    }

    private function is_ip_in_range( $ip, $range ) {
        if (strpos($range, '/') !== false) {
            list($subnet, $bits) = explode('/', $range, 2);
            if (filter_var($subnet, FILTER_VALIDATE_IP) && is_numeric($bits)) {
                $ip_long = ip2long($ip);
                $subnet_long = ip2long($subnet);
                $mask = -1 << (32 - (int) $bits);
                $subnet_masked = $subnet_long & $mask;
                return ($ip_long & $mask) === $subnet_masked;
            }
        }
        if (strpos($range, '-') !== false) {
            list($start_ip, $end_ip) = explode('-', $range, 2);
            $start_ip = trim($start_ip);
            $end_ip = trim($end_ip);
            if (filter_var($start_ip, FILTER_VALIDATE_IP) && filter_var($end_ip, FILTER_VALIDATE_IP)) {
                $ip_long = ip2long($ip);
                $start_long = ip2long($start_ip);
                $end_long = ip2long($end_ip);
                return $ip_long >= $start_long && $ip_long <= $end_long;
            }
        }
        return $ip === $range;
    }

    private function unblock_ip_autonomo( $ip_to_unblock ) {
        $option_key_map = [
            'geoblock'   => ADVAIPBL_Main::OPTION_BLOCKED_GEO,
            'honeypot'   => ADVAIPBL_Main::OPTION_BLOCKED_HONEYPOT,
            'user_agent' => ADVAIPBL_Main::OPTION_BLOCKED_USER_AGENT,
            'manual'     => ADVAIPBL_Main::OPTION_BLOCKED_MANUAL,
            '404'        => ADVAIPBL_Main::OPTION_BLOCKED_404,
            '403'        => ADVAIPBL_Main::OPTION_BLOCKED_403,
            'login'      => ADVAIPBL_Main::OPTION_BLOCKED_LOGIN,
			'waf'        => ADVAIPBL_Main::OPTION_BLOCKED_WAF,
			'rate_limit' => ADVAIPBL_Main::OPTION_BLOCKED_RATE_LIMIT,
			'asn'        => ADVAIPBL_Main::OPTION_BLOCKED_ASN,
			'xmlrpc_block' => ADVAIPBL_Main::OPTION_BLOCKED_XMLRPC,
        ];
        $unblocked_from = [];

        foreach ( $option_key_map as $type => $option_key ) {
            delete_transient( 'advaipbl_bloqueo_' . $type . '_' . md5( $ip_to_unblock ) );
            if ( in_array( $type, [ '404', '403', 'login' ], true ) ) {
                delete_transient( 'advaipbl_errores_' . $type . '_' . md5( $ip_to_unblock ) );
                delete_transient( 'advaipbl_detail_' . $type . '_' . md5( $ip_to_unblock ) );
            }
            
            $list = get_option( $option_key, [] );
            if ( ! is_array( $list ) || empty($list) ) {
                continue;
            }

            $list_changed = false;
            foreach ( array_keys($list) as $blocked_entry ) {
                if ( $this->is_ip_in_range( $ip_to_unblock, $blocked_entry ) ) {
                    unset( $list[ $blocked_entry ] );
                    $list_changed = true;
                    $unblocked_from[] = "{$type} (entry: {$blocked_entry})";
                }
            }

            if ( $list_changed ) {
                update_option( $option_key, $list );
            }
        }

        if ( ! empty( $unblocked_from ) ) {
			/* translators: %1$s: IP, %2$s: Security event type. */
            $this->log_event_autonomo( sprintf( __( 'IP %1$s unblocked from lists: %2$s. Action via WP-CLI.', 'advanced-ip-blocker' ), $ip_to_unblock, implode( ', ', $unblocked_from ) ), 'info', $ip_to_unblock );
        }
    }

    private function log_event_autonomo( $message, $level = 'info', $ip = '127.0.0.1' ) {
        $options = get_option( ADVAIPBL_Main::OPTION_SETTINGS, [] );
        if ( empty( $options['enable_logging'] ) ) return;
        global $wpdb;
        $table_name = $wpdb->prefix . 'advaipbl_logs';
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
        @$wpdb->insert( $table_name, [ 'timestamp' => current_time( 'mysql', 1 ), 'ip' => is_array($ip) ? wp_json_encode($ip) : $ip, 'log_type' => 'general', 'level' => $level, 'message' => $message, 'details' => wp_json_encode( [ 'source' => 'WP-CLI' ] ) ] );
    }

	/**
	 * Manually blocks an IP address or range.
	 *
	 * ## OPTIONS
	 *
	 * <ip-or-range>
	 * : The IP address, CIDR range, or hyphenated range to block.
	 *
	 * [--reason=<reason>]
	 * : An optional reason for the block.
	 * ---
	 * default: Blocked via WP-CLI
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     # Block a single IP
	 *     $ wp advaipbl block 1.2.3.4
	 *
     *     # Block a CIDR range with a reason
     *     $ wp advaipbl block 10.0.0.0/24 --reason="Internal network"
	 */
		public function block( $args, $assoc_args ) {
		if ( empty( $args[0] ) ) {
            WP_CLI::error( 'Usage: wp advaipbl block <ip-or-range> [--reason=<reason>]' );
            return;
        }
		$ip_or_range = trim($args[0]);
		$reason = $assoc_args['reason'] ?? 'Blocked via WP-CLI';

		if ( ! $this->is_valid_ip_or_range( $ip_or_range ) ) {
            WP_CLI::error( "'{$ip_or_range}' is not a valid IP or range." );
            return;
        }
		
        $main_instance = ADVAIPBL_Main::get_instance();

        // Comprobamos si ya está bloqueado en la nueva tabla.
        global $wpdb;
        $table_name = $wpdb->prefix . 'advaipbl_blocked_ips';
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $exists = $wpdb->get_var($wpdb->prepare("SELECT id FROM {$table_name} WHERE ip_range = %s", $ip_or_range));

        if ($exists) {
            WP_CLI::warning( "Entry '{$ip_or_range}' is already blocked." );
            return;
        }

        // Usamos la función centralizada. El contexto 'admin_action' es adecuado para CLI.
        $main_instance->block_ip_instantly($ip_or_range, 'manual', $reason, [], 'admin_action');
        
		WP_CLI::success( "Entry '{$ip_or_range}' blocked successfully." );
	}

		/**
	 * Unblocks a specific IP/range or all IPs from all blocklists.
	 *
	 * ## OPTIONS
	 *
	 * [<ip-or-range>]
	 * : The specific IP address to unblock, or the exact range entry to remove.
	 *
	 * [--all]
	 * : Use this flag to unblock ALL IPs from all blocklists. This is a destructive action.
	 *
	 * ## EXAMPLES
	 *
	 *     # Rescue command: unblocks your current IP from any list.
	 *     $ wp advaipbl unblock 1.2.3.4
	 * 
	 *     # Nuke command: unblocks absolutely everything.
	 *     $ wp advaipbl unblock --all
	 */
    public function unblock( $args, $assoc_args ) {
        $main_instance = ADVAIPBL_Main::get_instance();

        // Comprobamos si se ha usado el flag --all
        if (isset($assoc_args['all'])) {
            WP_CLI::confirm('Are you sure you want to unblock ALL IPs from ALL blocklists? This action cannot be undone.');
            
            $main_instance->unblock_all_ips('WP-CLI');
            
            WP_CLI::success('All IPs have been unblocked and all block transients have been cleared.');
            return;
        }

        if ( empty( $args ) ) {
            WP_CLI::error( "Usage: wp advaipbl unblock <ip-or-range> OR wp advaipbl unblock --all" );
            return;
        }
        $ip_or_range_to_remove = $args[0];
    
        if ( ! $this->is_valid_ip_or_range( $ip_or_range_to_remove ) ) {
            WP_CLI::error( "'{$ip_or_range_to_remove}' is not a valid IP or range format." );
            return;
        }
    
        if ( filter_var( $ip_or_range_to_remove, FILTER_VALIDATE_IP ) ) {
            $main_instance->desbloquear_ip( $ip_or_range_to_remove );
            WP_CLI::success( "Attempted to unblock IP {$ip_or_range_to_remove} from all lists (including ranges)." );
        } else {
            $all_block_definitions = $main_instance->get_all_block_type_definitions();
            $was_removed = false;
            foreach ($all_block_definitions as $type => $definition) {
                $option_key = $definition['option'];
                $list = get_option( $option_key, [] );
                if ( is_array($list) && array_key_exists( $ip_or_range_to_remove, $list ) ) {
                    unset($list[$ip_or_range_to_remove]);
                    update_option($option_key, $list);
                    $was_removed = true;
                    $this->log_event_autonomo( sprintf( 'Exact entry %s removed from %s blocklist via WP-CLI.', $ip_or_range_to_remove, $type ), 'info', 'WP-CLI' );
                }
            }
            
            if ($was_removed) {
                WP_CLI::success( "Successfully removed the exact entry '{$ip_or_range_to_remove}' from the blocklists." );
            } else {
                WP_CLI::warning( "The exact entry '{$ip_or_range_to_remove}' was not found in any blocklist." );
            }
        }
    }

		/**
	 * Displays a list of currently blocked IPs and ranges.
	 *
	 * ## OPTIONS
	 * 
	 * [--type=<type>]
	 * : Filter the list by a specific block type.
	 * ---
	 * default: all
	 * options:
	 *   - all
	 *   - geoblock
	 *   - manual
	 *   - honeypot
	 *   - user_agent
	 *   - 404
	 *   - 403
	 *   - login
	 *   - waf
	 *   - rate_limit
	 *   - asn
	 *   - xmlrpc_block
	 * ---
	 *
	 * [--format=<format>]
	 * : Render output in a particular format.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 *   - csv
	 *   - yaml
	 * ---
	 * 
	 * ## EXAMPLES
	 * 
	 *     # List all blocked IPs and ranges
	 *     $ wp advaipbl blocked
	 * 
	 *     # List only IPs blocked by the WAF in JSON format
	 *     $ wp advaipbl blocked --type=waf --format=json
	 */
	public function blocked( $args, $assoc_args ) {
        // Obtenemos la instancia principal del plugin
        $main_instance = ADVAIPBL_Main::get_instance();
        $all_blocked_data = $main_instance->get_all_blocked_entries();   
        $filter_type = \WP_CLI\Utils\get_flag_value( $assoc_args, 'type', 'all' );
    
        // Si el usuario especifica un filtro, lo aplicamos.
        if ( 'all' !== $filter_type ) {
            $all_blocked_data = array_filter($all_blocked_data, function($entry) use ($filter_type) {
                return $entry['type'] === $filter_type;
            });
        }
    
        if ( empty( $all_blocked_data ) ) {
            WP_CLI::line( 'No blocked IPs found for the selected filter.' );
            return;
        }

        // Formateamos los datos para la salida de WP-CLI.
        $formatted_items = array_map(function($item){
            $item['timestamp'] = ADVAIPBL_Main::get_formatted_datetime($item['timestamp']);
            return $item;
        }, $all_blocked_data);
    
        // Mostramos los resultados.
        WP_CLI\Utils\format_items( $assoc_args['format'] ?? 'table', array_values( $formatted_items ), [ 'ip', 'type_label', 'timestamp', 'detail' ] );
    }

    /**
	 * Manages active user sessions.
	 *
	 * ## SYNOPSIS
	 *
	 *     wp advaipbl session <list|terminate> [--<field>=<value>]
	 *
	 * ## SUBCOMMANDS
	 * 
	 *     list
	 *       : Lists all currently active user sessions.
	 *         [--role=<role>]
	 *         : Filter sessions by a specific user role.
	 *         [--format=<format>]
	 *         : Render output in a particular format (table, json, csv, yaml).
	 * 
	 *     terminate
	 *       : Terminates user sessions. Must specify one condition.
	 *         [--user-id=<id>]
	 *         : Terminate all sessions for a specific user ID.
	 *         [--user-login=<login>]
	 *         : Terminate all sessions for a specific user login.
	 *         [--role=<role>]
	 *         : Terminate all sessions for all users with a specific role.
	 *         [--all]
	 *         : Terminate all sessions for all users.
	 *
	 * ## EXAMPLES
	 *
	 *     # List all active sessions
	 *     $ wp advaipbl session list
	 *
	 *     # Terminate all sessions for the user with ID 2
	 *     $ wp advaipbl session terminate --user-id=2
     * 
     *     # Terminate all sessions for all administrator users
	 *     $ wp advaipbl session terminate --role=administrator
	 * 
	 * @subcommand session
	 */
	public function session( $args, $assoc_args ) {
        $subcommand = array_shift( $args );
		if ( ! in_array( $subcommand, ['list', 'terminate'], true ) ) { WP_CLI::error( "Invalid subcommand. Use 'list' or 'terminate'." ); return; }
		
        if ( 'list' === $subcommand ) {
            // Obtenemos la instancia principal del plugin que ya tiene todo inicializado.
            $main_instance = ADVAIPBL_Main::get_instance();
            
            $session_manager = $main_instance->session_manager; 
            
            if (!$session_manager) {
                WP_CLI::error( "Session manager is not available." );
                return;
            }

            $sessions = $session_manager->get_active_sessions();
            $role_filter = \WP_CLI\Utils\get_flag_value( $assoc_args, 'role' );
            if ( $role_filter ) { $sessions = array_filter($sessions, function($session) use ($role_filter) { return in_array($role_filter, explode(', ', $session['role']), true); }); }
            if (empty($sessions)) { WP_CLI::line('No active user sessions found.'); return; }
            WP_CLI\Utils\format_items($assoc_args['format'] ?? 'table', $sessions, ['user_id', 'username', 'role', 'ip', 'last_activity']);
        } elseif ( 'terminate' === $subcommand ) {
            $user_ids_to_logout = [];
            $log_message = '';
            $log_level = 'warning'; // Nivel por defecto para acciones específicas.

            if ( isset($assoc_args['user-id']) ) {
                $user_id_to_logout = absint($assoc_args['user-id']);
                if ($user_id_to_logout > 0) {
                    $user_ids_to_logout[] = $user_id_to_logout;
					/* translators: %d: user ID. */
                    $log_message = sprintf( __( 'Sessions for user ID %d terminated via WP-CLI.', 'advanced-ip-blocker' ), $user_id_to_logout );
                }
            } elseif ( isset($assoc_args['user-login']) ) {
                $user = get_user_by('login', $assoc_args['user-login']);
                if ($user) {
                    $user_ids_to_logout[] = $user->ID;
					/* translators: %s: Username. */
                    $log_message = sprintf( __( 'Sessions for user \'%s\' terminated via WP-CLI.', 'advanced-ip-blocker' ), $assoc_args['user-login'] );
                }
            } elseif ( isset($assoc_args['role']) ) {
                $user_ids_to_logout = get_users(['role' => $assoc_args['role'], 'fields' => 'ID']);
				/* translators: %s: Role. */
                $log_message = sprintf( __( 'All sessions for role \'%s\' terminated via WP-CLI.', 'advanced-ip-blocker' ), $assoc_args['role'] );
            } elseif ( isset($assoc_args['all']) ) {
                $user_ids_to_logout = get_users(['fields' => 'ID']);
				/* translators: All user sessions terminated. */
                $log_message = __( 'All user sessions terminated via WP-CLI.', 'advanced-ip-blocker' );
                $log_level = 'critical';
            } else {
                WP_CLI::error('Please specify a condition: --user-id=<id>, --user-login=<login>, --role=<role>, or --all.');
                return;
            }

            if (empty($user_ids_to_logout)) {
                WP_CLI::warning('No users found matching the criteria.');
                return;
            }

            WP_CLI::confirm(sprintf('This will terminate sessions for %d user(s). Are you sure?', count($user_ids_to_logout)), $assoc_args);
            
            $terminated_count = 0;
            foreach ($user_ids_to_logout as $uid) {
                $valid_uid = absint($uid);
                if ($valid_uid > 0) {
                    WP_Session_Tokens::get_instance($valid_uid)->destroy_all();
                    $terminated_count++;
                }
            }
            
            $this->log_event_autonomo($log_message, $log_level, 'WP-CLI');
            WP_CLI::success(sprintf('Successfully terminated sessions for %d user(s).', $terminated_count));
        }
	}

	/**
	 * Manages the IP whitelist.
	 *
	 * ## OPTIONS
	 *
	 * <add|remove|list>
	 * : The action to perform.
	 *
	 * [<ip-or-range>]
	 * : The IP or range to add or remove. Required for 'add' and 'remove' actions.
	 *
	 * [--detail=<detail>]
	 * : An optional detail/reason for adding the entry.
	 * ---
	 * default: Added via WP-CLI
	 * ---
	 *
	 * [--format=<format>]
	 * : Render output in a particular format. Only applies to the 'list' action.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 *   - csv
	 *   - yaml
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     # List all entries in the whitelist
	 *     $ wp advaipbl whitelist list
	 *
	 *     # Add a new IP to the whitelist and unblock it from all lists
	 *     $ wp advaipbl whitelist add 192.168.1.100
	 *
	 * @subcommand whitelist
	 */
    public function whitelist( $args, $assoc_args ) {
        $subcommand = array_shift( $args );
        if ( ! in_array( $subcommand, [ 'add', 'remove', 'list' ], true ) ) { WP_CLI::error( 'Invalid subcommand. Use: add, remove, or list.' ); }

        if ( in_array( $subcommand, [ 'add', 'remove' ], true ) ) {
            if ( empty( $args[0] ) ) { WP_CLI::error( 'Please provide an IP or range.' ); return; }
            $ip_or_range = trim($args[0]);
            if ( ! $this->is_valid_ip_or_range( $ip_or_range ) ) { WP_CLI::error( "'{$ip_or_range}' is not a valid IP or range." ); return; }
        }

        $option_key = ADVAIPBL_Main::OPTION_WHITELIST;
        $list       = get_option( $option_key, [] );

        switch ( $subcommand ) {
            case 'add':
                $detail = $assoc_args['detail'] ?? 'Added via WP-CLI';
                $main_instance = ADVAIPBL_Main::get_instance();
                $success = $main_instance->add_to_whitelist_and_unblock($ip_or_range, $detail);

                if ($success) {
                    WP_CLI::success( "Entry '{$ip_or_range}' added to whitelist." );
                } else {
                    WP_CLI::warning( "Entry '{$ip_or_range}' is already in the whitelist or is invalid." );
                }
                break;
            case 'remove':
                if ( ! array_key_exists( $ip_or_range, $list ) ) { WP_CLI::warning( "Entry '{$ip_or_range}' was not in the whitelist." ); return; }
                unset( $list[ $ip_or_range ] );
                update_option( $option_key, $list );
				/* translators: %s: IP. */
                $this->log_event_autonomo( sprintf( __( 'Entry %s removed from whitelist via WP-CLI.', 'advanced-ip-blocker' ), $ip_or_range ), 'info', $ip_or_range );
                WP_CLI::success( "Entry '{$ip_or_range}' removed from whitelist." );
                break;
            case 'list':
                if ( empty( $list ) ) { WP_CLI::line( 'The whitelist is empty.' ); return; }
                $items = [];
                foreach ( $list as $ip_addr => $data ) {
                    $timestamp = 0; $detail = 'N/A';
                    if ( is_array($data) && isset($data['timestamp']) ) {
                        $timestamp = $data['timestamp']; $detail = $data['detail'] ?? '';
                    } elseif ( is_numeric($data) ) {
                        $timestamp = $data; $detail = 'Migrated from old format';
                    }
                    $items[] = [ 'ip' => $ip_addr, 'detail' => $detail, 'added_on' => ADVAIPBL_Main::get_formatted_datetime( $timestamp ) ];
                }
                WP_CLI\Utils\format_items( $assoc_args['format'] ?? 'table', $items, [ 'ip', 'detail', 'added_on' ] );
                break;
        }
    }
    
	/**
     * Manages Geolocation API providers and their keys.
     *
     * ## SYNOPSIS
     *
     *     wp advaipbl provider <list|set|set_key|remove_key> [<provider>] [<api_key>]
     *
     * @subcommand provider
     */
     public function provider( $args, $assoc_args ) {
		if ( ! class_exists('GeoIp2\Database\Reader') ) {
            WP_CLI::error( "This command's full functionality requires PHP 8.1 or higher to run via WP-CLI. Your current PHP-CLI version is " . PHP_VERSION . "." );
            return;
        } 
        $subcommand = array_shift( $args );
        $valid_subcommands = ['list', 'set', 'set_key', 'remove_key'];

        if ( ! in_array( $subcommand, $valid_subcommands, true ) ) {
            WP_CLI::error( "Invalid subcommand. Use: " . implode(', ', $valid_subcommands) );
            return;
        }

        $providers_map = [
            'ip-api.com'      => 'api_key_ip_apicom',
            'geoiplookup.net' => null,
            'ipinfo.io'       => 'api_key_ipinfocom',
            'ipapi.com'       => 'api_key_ipapicom',
            'ipstack.com'     => 'api_key_ipstackcom',
        ];

        switch ($subcommand) {
            case 'list': $this->provider_list($providers_map); break;
            case 'set': $this->provider_set($args, $providers_map); break;
            case 'set_key': $this->provider_set_key($args, $providers_map); break;
            case 'remove_key': $this->provider_remove_key($args, $providers_map); break;
        }
    }

    private function provider_list($providers_map) {
        $settings = get_option(ADVAIPBL_Main::OPTION_SETTINGS, []);
        $current_provider = $settings['geolocation_provider'] ?? 'geoiplookup.net';
        $display_items = [];
        foreach ($providers_map as $provider => $key_name) {
            $api_key_status = 'Not Required';
            if ($key_name !== null) { $api_key_status = !empty($settings[$key_name]) ? 'Set' : 'Not Set'; }
            $display_items[] = [ 'provider' => $provider, 'status' => ($provider === $current_provider) ? 'Active' : '', 'api_key' => $api_key_status, ];
        }
        WP_CLI\Utils\format_items('table', $display_items, ['provider', 'status', 'api_key']);
    }

    private function provider_set($args, $providers_map) {
        if (empty($args[0])) { WP_CLI::error("Please specify a provider. Usage: wp advaipbl provider set <provider-name>"); return; }
        $new_provider = $args[0];
        if (!array_key_exists($new_provider, $providers_map)) { WP_CLI::error("Invalid provider. Available providers are: " . implode(', ', array_keys($providers_map))); return; }
        $settings = get_option(ADVAIPBL_Main::OPTION_SETTINGS, []);
        $settings['geolocation_provider'] = $new_provider;
        update_option(ADVAIPBL_Main::OPTION_SETTINGS, $settings);
        $this->log_event_autonomo( sprintf( "Geolocation provider set to '%s' via WP-CLI.", $new_provider ), 'info' );
        WP_CLI::success(sprintf("Geolocation provider successfully set to '%s'.", $new_provider));
    }

    private function provider_set_key($args, $providers_map) {
        if (count($args) < 2) { WP_CLI::error("Usage: wp advaipbl provider set_key <provider-name> <api-key>"); return; }
        list($provider, $api_key) = $args;
        if (!isset($providers_map[$provider]) || $providers_map[$provider] === null) { WP_CLI::error("'{$provider}' is not a valid provider or does not support API keys."); return; }
        $settings = get_option(ADVAIPBL_Main::OPTION_SETTINGS, []);
        $key_name = $providers_map[$provider];
        $settings[$key_name] = sanitize_text_field($api_key);
        update_option(ADVAIPBL_Main::OPTION_SETTINGS, $settings);
        $this->log_event_autonomo( sprintf( "API key for '%s' updated via WP-CLI.", $provider ), 'info' );
        WP_CLI::success(sprintf("API key for '%s' has been set.", $provider));
    }

    private function provider_remove_key($args, $providers_map) {
        if (empty($args[0])) { WP_CLI::error("Usage: wp advaipbl provider remove_key <provider-name>"); return; }
        $provider = $args[0];
        if (!isset($providers_map[$provider]) || $providers_map[$provider] === null) { WP_CLI::error("'{$provider}' is not a valid provider or does not support API keys."); return; }
        $settings = get_option(ADVAIPBL_Main::OPTION_SETTINGS, []);
        $key_name = $providers_map[$provider];
        if (isset($settings[$key_name])) {
            $settings[$key_name] = '';
            update_option(ADVAIPBL_Main::OPTION_SETTINGS, $settings);
            $this->log_event_autonomo( sprintf( "API key for '%s' removed via WP-CLI.", $provider ), 'info' );
            WP_CLI::success(sprintf("API key for '%s' has been removed.", $provider));
        } else {
            WP_CLI::warning(sprintf("No API key was set for '%s'. Nothing to remove.", $provider));
        }
    }
	
    /**
	 * Manages the list of blocked countries.
	 * @subcommand geoblock
	 */
    public function geoblock( $args, $assoc_args ) {
		if ( ! class_exists('GeoIp2\Database\Reader') ) {
            WP_CLI::error( "This command's full functionality requires PHP 8.1 or higher to run via WP-CLI. Your current PHP-CLI version is " . PHP_VERSION . "." );
            return;
        }
        $subcommand = array_shift( $args );
        if ( ! in_array( $subcommand, [ 'add', 'remove', 'list' ], true ) ) { WP_CLI::error( 'Invalid subcommand. Use: add, remove, or list.' ); return; }
        $settings = get_option(ADVAIPBL_Main::OPTION_SETTINGS, []);
        $blocked_countries_raw = $settings['geoblock_countries'] ?? [];
        if ( ! is_array($blocked_countries_raw) ) { $blocked_countries = empty($blocked_countries_raw) ? [] : [ (string) $blocked_countries_raw ]; } else { $blocked_countries = $blocked_countries_raw; }
        switch ( $subcommand ) {
            case 'add':
                if ( count($args) < 1 ) { WP_CLI::error( 'Please provide a 2-letter country code. Usage: wp advaipbl geoblock add <country_code>' ); return; }
                $country_code = strtoupper($args[0]);
                if ( strlen($country_code) !== 2 ) { WP_CLI::error( 'Country code must be 2 letters (e.g., US, DE, CN).' ); return; }
                if ( in_array($country_code, $blocked_countries, true) ) { WP_CLI::warning( "Country {$country_code} is already in the block list." ); return; }
                $blocked_countries[] = $country_code;
                $settings['geoblock_countries'] = array_values(array_unique($blocked_countries));
                update_option(ADVAIPBL_Main::OPTION_SETTINGS, $settings);
				/* translators: %s: Country. */
                $this->log_event_autonomo( sprintf( __( 'Country %s added to geoblock list via WP-CLI.', 'advanced-ip-blocker' ), strtoupper($country_code) ), 'warning' );
                WP_CLI::success( "Country {$country_code} added to the block list." );
                break;
            case 'remove':
                if ( count($args) < 1 ) { WP_CLI::error( 'Please provide a country code to remove.' ); return; }
                $country_code = strtoupper($args[0]);
                $key = array_search($country_code, $blocked_countries, true);
                if ( false === $key ) { WP_CLI::warning( "Country {$country_code} was not found in the block list." ); return; }
                unset($blocked_countries[$key]);
                $settings['geoblock_countries'] = array_values($blocked_countries);
                update_option(ADVAIPBL_Main::OPTION_SETTINGS, $settings);
				/* translators: %s: Country. */
                $this->log_event_autonomo( sprintf( __( 'Country %s removed from geoblock list via WP-CLI.', 'advanced-ip-blocker' ), strtoupper($country_code) ), 'info' );
                WP_CLI::success( "Country {$country_code} removed from the block list." );
                break;
            case 'list':
                if ( empty($blocked_countries) ) { WP_CLI::line('The country block list is empty.'); return; }
                WP_CLI::line('Blocked country codes:');
                foreach ($blocked_countries as $code) { WP_CLI::line("- {$code}"); }
                break;
        }
    }

	/**
	 * Manages the plugin's security and event logs.
	 * @subcommand log
	 */
	public function log( $args, $assoc_args ) {
		$subcommand = array_shift( $args );
		switch ( $subcommand ) {
			case 'list': $this->log_list( $args, $assoc_args ); break;
			case 'clear': $this->log_clear( $args, $assoc_args ); break;
			default: WP_CLI::error( "Please specify a subcommand for 'log': list or clear. Use 'wp help advaipbl log' for more information." );
		}
	}

	private function log_list( $args, $assoc_args ) {
		global $wpdb; $table_name = $wpdb->prefix . 'advaipbl_logs'; $type = $assoc_args['type'] ?? 'general'; $count = $assoc_args['count'] ?? 20;
        $where_clause = '1=1'; if ( 'all' !== $type ) { $where_clause = $wpdb->prepare( 'log_type = %s', $type ); }
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
		$logs = $wpdb->get_results( $wpdb->prepare( "SELECT timestamp, level, ip, message, details FROM $table_name WHERE $where_clause ORDER BY timestamp DESC LIMIT %d", $count ), ARRAY_A );
		if ( empty( $logs ) ) { WP_CLI::line( 'No log entries found for the specified type.' ); return; }
		WP_CLI\Utils\format_items( $assoc_args['format'] ?? 'table', $logs, [ 'timestamp', 'level', 'ip', 'message' ] );
	}

	private function log_clear( $args, $assoc_args ) {
        $type = $assoc_args['type'] ?? 'all';
		if ( ! isset( $assoc_args['force'] ) ) { $confirm_message = ( 'all' === $type ) ? 'Are you sure you want to clear ALL logs? This action cannot be undone.' : "Are you sure you want to clear all '{$type}' logs?"; WP_CLI::confirm( $confirm_message ); }
		global $wpdb; $table_name = $wpdb->prefix . 'advaipbl_logs'; $this->log_event_autonomo( "WP-CLI: Clearing logs of type '{$type}'.", 'warning' );
		if ( 'all' !== $type ) { 
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $deleted = $wpdb->delete( $table_name, [ 'log_type' => $type ], [ '%s' ] ); 
            WP_CLI::success( "{$deleted} logs of type '{$type}' have been cleared." ); 
        } else { 
            // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $wpdb->query( "TRUNCATE TABLE $table_name" ); WP_CLI::success( 'All logs have been cleared.' ); }
	}

	/**
    * Gets or sets plugin configuration options.
    * @subcommand config
    */
    public function config( $args, $assoc_args ) {
        if ( empty($args[0]) ) { WP_CLI::error( "Please specify a subcommand: 'get' or 'set'." ); return; }
        $subcommand = array_shift( $args );
        switch ( $subcommand ) {
            case 'get':
                $options = get_option( ADVAIPBL_Main::OPTION_SETTINGS, [] ); $key = array_shift( $args );
                if ( $key ) {
                    if ( isset( $options[ $key ] ) ) { $value = $options[ $key ]; if (is_array($value)) { WP_CLI::line( wp_json_encode($value) ); } else { WP_CLI::line( $value ); } } else { WP_CLI::error( "Option '{$key}' not found in advaipbl_settings." ); }
                } else {
                    $display_items = []; foreach ($options as $option_key => $option_value) { $display_items[] = [ 'key' => $option_key, 'value' => is_array($option_value) ? wp_json_encode($option_value) : $option_value, ]; }
                    WP_CLI\Utils\format_items( 'table', $display_items, [ 'key', 'value' ] );
                }
                break;
            case 'set':
                if ( count( $args ) < 2 ) { WP_CLI::error( 'Usage: wp advaipbl config set <key> <value>' ); return; }
                $main_instance = ADVAIPBL_Main::get_instance(); $options = get_option( ADVAIPBL_Main::OPTION_SETTINGS, [] ); list($key, $value) = $args;
                $old_sanitized_value = $options[$key] ?? null; $input_to_sanitize = array_merge($options, [$key => $value]);
                $sanitized_options = $main_instance->settings_manager->sanitize_settings($input_to_sanitize);
                if ( !isset($sanitized_options[$key]) ) { WP_CLI::error("Invalid key '{$key}'."); return; }
                $new_sanitized_value = $sanitized_options[$key];
                if ($old_sanitized_value === $new_sanitized_value && $value !== (string)$old_sanitized_value) { WP_CLI::error("Invalid value '{$value}' provided for key '{$key}'. Please provide a valid value."); return; }
                update_option( ADVAIPBL_Main::OPTION_SETTINGS, $sanitized_options );
                $log_value = is_array($new_sanitized_value) ? wp_json_encode($new_sanitized_value) : $new_sanitized_value;
				/* translators: %1$s: Setting option, %2$s: Option updated. */
                $this->log_event_autonomo( sprintf( __( 'Option \'%1$s\' updated to \'%2$s\' via WP-CLI.', 'advanced-ip-blocker' ), $key, $log_value ), 'info' );
                WP_CLI::success( "Option '{$key}' updated." );
                break;
            default: WP_CLI::error( "Invalid subcommand '{$subcommand}'. Use 'get' or 'set'." );
        }
    }

    /**
     * Enables the Web Application Firewall (WAF).
     */
    public function waf_enable( $args, $assoc_args ) {
        $this->config( ['set', 'enable_waf', '1'], [] );
        WP_CLI::success( 'Web Application Firewall (WAF) has been enabled.' );
    }

    /**
     * Disables the Web Application Firewall (WAF).
     */
    public function waf_disable( $args, $assoc_args ) {
        $this->config( ['set', 'enable_waf', '0'], [] );
        WP_CLI::success( 'Web Application Firewall (WAF) has been disabled.' );
    }

    /**
     * Enables automated blocking using the Spamhaus ASN DROP list.
     */
    public function spamhaus_enable( $args, $assoc_args ) {
        $this->config( ['set', 'enable_spamhaus_asn', '1'], [] );
        WP_CLI::success( 'Automated protection using the Spamhaus ASN DROP list has been enabled.' );
    }

    /**
     * Disables automated blocking using the Spamhaus ASN DROP list.
     */
    public function spamhaus_disable( $args, $assoc_args ) {
        $this->config( ['set', 'enable_spamhaus_asn', '0'], [] );
        WP_CLI::success( 'Automated protection using the Spamhaus ASN DROP list has been disabled.' );
    }
	
    /**
     * Enables blocking using the Manual ASN Blocklist.
     */
    public function manual_asn_enable( $args, $assoc_args ) {
        $this->config( ['set', 'enable_manual_asn', '1'], [] );
        WP_CLI::success( 'Protection using the Manual ASN Blocklist has been enabled.' );
    }

    /**
     * Disables blocking using the Manual ASN Blocklist.
     */
    public function manual_asn_disable( $args, $assoc_args ) {
        $this->config( ['set', 'enable_manual_asn', '0'], [] );
        WP_CLI::success( 'Protection using the Manual ASN Blocklist has been disabled.' );
    }

        /**
     * Manages the Web Application Firewall (WAF) rules and exclusions.
     * @subcommand waf
     */
    public function waf( $args, $assoc_args ) {
        $subcommand = array_shift( $args );
        // Añadimos 'exclude' a la lista de subcomandos válidos.
        if ( ! in_array( $subcommand, [ 'add', 'remove', 'list', 'exclude' ], true ) ) {
            WP_CLI::error( "Invalid subcommand. Use: add, remove, list, or exclude." );
            return;
        }

        // Si el subcomando es 'exclude', lo delegamos a su propia función.
        if ( 'exclude' === $subcommand ) {
            $this->waf_exclude( $args, $assoc_args );
            return;
        }
        
        $option_key = ADVAIPBL_Main::OPTION_WAF_RULES;
        $raw_rules = get_option( $option_key, '' );
        $rules = empty(trim($raw_rules)) ? [] : array_filter(array_map('trim', explode("\n", $raw_rules)));

        switch ( $subcommand ) {
            case 'add':
                $file_path = \WP_CLI\Utils\get_flag_value( $assoc_args, 'from-file' );
                $new_rules_to_add = [];
                if ( $file_path ) {
                    if ( ! file_exists( $file_path ) ) { WP_CLI::error( "File not found: {$file_path}" ); return; }
                    $file_content = file_get_contents( $file_path );
                    $new_rules_to_add = array_filter(array_map('trim', explode("\n", $file_content)));
                } elseif ( ! empty( $args[0] ) ) {
                    $new_rules_to_add[] = $args[0];
                } else {
                    WP_CLI::error( "Please provide a rule to add, or use the --from-file=<file> flag." ); return;
                }
                $added_count = 0;
                foreach( $new_rules_to_add as $new_rule ) {
                    if ( ! in_array( $new_rule, $rules, true ) ) { $rules[] = $new_rule; $added_count++; }
                }
                if ($added_count > 0) {
                    update_option( $option_key, implode( "\n", $rules ) );
					/* translators: %d: WAF rule(s). */
                    $this->log_event_autonomo( sprintf( __('%d WAF rule(s) added via WP-CLI.', 'advanced-ip-blocker'), $added_count ), 'info' );
                    WP_CLI::success( sprintf( "%d new rule(s) added to the WAF.", $added_count ) );
                } else {
                    WP_CLI::warning( "The provided rule(s) already exist. No changes were made." );
                }
                break;
            case 'remove':
                if ( empty( $args[0] ) ) { WP_CLI::error( 'Please provide a rule to remove.' ); return; }
                $rule_to_remove = $args[0];
                $key_to_remove = array_search( $rule_to_remove, $rules, true );
                if ( $key_to_remove === false ) { WP_CLI::warning( "Rule not found: '{$rule_to_remove}'" ); return; }
                unset( $rules[ $key_to_remove ] );
                update_option( $option_key, implode( "\n", $rules ) );
				/* translators: %d: The nume of WAF rule that were deleted. */
                $this->log_event_autonomo( sprintf( __('WAF rule "%s" removed via WP-CLI.', 'advanced-ip-blocker'), $rule_to_remove ), 'info' );
                WP_CLI::success( "Rule removed successfully." );
                break;
            case 'list':
                if ( empty( $rules ) ) { WP_CLI::line( 'The WAF ruleset is empty.' ); return; }
                WP_CLI::line( 'Current WAF Rules:' );
                foreach ( $rules as $rule ) { WP_CLI::line( "- {$rule}" ); }
                break;
        }
    }
	
	    /**
     * Manages the WAF exclusion list.
     * Es una función privada llamada por el comando público 'waf'.
     */
    private function waf_exclude( $args, $assoc_args ) {
        $action = array_shift( $args );
        if ( ! in_array( $action, [ 'add', 'remove', 'list' ], true ) ) {
            WP_CLI::error( "Invalid action for 'waf exclude'. Use: list, add, or remove." );
            return;
        }

        $settings = get_option( ADVAIPBL_Main::OPTION_SETTINGS, [] );
        $raw_exclusions = $settings['waf_excluded_urls'] ?? '';
        $exclusions = empty(trim($raw_exclusions)) ? [] : array_filter(array_map('trim', explode("\n", $raw_exclusions)));

        switch ( $action ) {
            case 'list':
                if ( empty( $exclusions ) ) {
                    WP_CLI::line( 'The WAF exclusion list is empty.' );
                } else {
                    WP_CLI::line( 'Current WAF Excluded URL Fragments:' );
                    foreach ( $exclusions as $url_fragment ) {
                        WP_CLI::line( "- {$url_fragment}" );
                    }
                }
                break;
            
            case 'add':
                if ( empty( $args[0] ) ) { WP_CLI::error( 'Please provide a URL fragment to add.' ); return; }
                $url_to_add = trim($args[0]);
                if ( in_array( $url_to_add, $exclusions, true ) ) {
                    WP_CLI::warning( "URL fragment '{$url_to_add}' is already in the exclusion list." );
                    return;
                }
                $exclusions[] = $url_to_add;
                $settings['waf_excluded_urls'] = implode("\n", $exclusions);
                update_option( ADVAIPBL_Main::OPTION_SETTINGS, $settings );
                $this->log_event_autonomo( sprintf( 'WAF exclusion for "%s" added via WP-CLI.', $url_to_add ), 'info' );
                WP_CLI::success( "URL fragment '{$url_to_add}' added to the WAF exclusion list." );
                break;

            case 'remove':
                if ( empty( $args[0] ) ) { WP_CLI::error( 'Please provide a URL fragment to remove.' ); return; }
                $url_to_remove = trim($args[0]);
                $key = array_search( $url_to_remove, $exclusions, true );
                if ( false === $key ) {
                    WP_CLI::warning( "URL fragment '{$url_to_remove}' not found in the exclusion list." );
                    return;
                }
                unset( $exclusions[$key] );
                $settings['waf_excluded_urls'] = implode("\n", $exclusions);
                update_option( ADVAIPBL_Main::OPTION_SETTINGS, $settings );
                $this->log_event_autonomo( sprintf( 'WAF exclusion for "%s" removed via WP-CLI.', $url_to_remove ), 'info' );
                WP_CLI::success( "URL fragment '{$url_to_remove}' removed from the WAF exclusion list." );
                break;
        }
    }

    /**
     * Manages the list of blocked Autonomous System Numbers (ASNs).
     * @subcommand asn
     */
    public function asn( $args, $assoc_args ) {
		if ( ! class_exists('GeoIp2\Database\Reader') ) {
            WP_CLI::error( "This command's full functionality requires PHP 8.1 or higher to run via WP-CLI. Your current PHP-CLI version is " . PHP_VERSION . "." );
            return;
        }
        $subcommand = array_shift( $args );
        if ( ! in_array( $subcommand, [ 'add', 'remove', 'list' ], true ) ) { WP_CLI::error( 'Invalid subcommand. Use: add, remove, or list.' ); return; }
        $option_key = ADVAIPBL_Main::OPTION_BLOCKED_ASNS;
        $blocked_asns = get_option( $option_key, [] );
        if (!is_array($blocked_asns)) $blocked_asns = [];
        switch ( $subcommand ) {
            case 'add':
                if ( empty( $args[0] ) ) { WP_CLI::error( 'Please provide an ASN to add (e.g., AS12345).' ); return; }
                $asn_to_add = strtoupper(trim($args[0]));
                if ( ! preg_match('/^AS\d+$/i', $asn_to_add) ) { WP_CLI::error( "Invalid ASN format. Please use the format 'AS' followed by numbers (e.g., AS15169)." ); return; }
                if ( in_array($asn_to_add, $blocked_asns, true) ) { WP_CLI::warning( "ASN {$asn_to_add} is already in the block list." ); return; }
                $blocked_asns[] = $asn_to_add;
                update_option($option_key, array_unique($blocked_asns));
                $this->log_event_autonomo( sprintf( 'ASN %s added to blocklist via WP-CLI.', $asn_to_add ), 'warning' );
                WP_CLI::success( "ASN {$asn_to_add} added to the block list." );
                break;
            case 'remove':
                if ( empty( $args[0] ) ) { WP_CLI::error( 'Please provide an ASN to remove.' ); return; }
                $asn_to_remove = strtoupper(trim($args[0]));
                $key = array_search($asn_to_remove, $blocked_asns, true);
                if ( false === $key ) { WP_CLI::warning( "ASN {$asn_to_remove} was not found in the block list." ); return; }
                unset($blocked_asns[$key]);
                update_option($option_key, array_values($blocked_asns));
                $this->log_event_autonomo( sprintf( 'ASN %s removed from blocklist via WP-CLI.', $asn_to_remove ), 'info' );
                WP_CLI::success( "ASN {$asn_to_remove} removed from the block list." );
                break;
            case 'list':
                if ( empty($blocked_asns) ) { WP_CLI::line('The ASN block list is empty.'); return; }
                WP_CLI::line('Blocked ASNs:');
                foreach ($blocked_asns as $asn) { WP_CLI::line("- {$asn}"); }
                break;
        }
    }

    /**
     * Sets the protection mode for the XML-RPC interface.
     */
    public function xmlrpc_mode( $args, $assoc_args ) {
        if ( empty( $args[0] ) ) { WP_CLI::error( "Please specify a mode. Usage: wp advaipbl xmlrpc-mode <enabled|smart|disabled>" ); return; }
        $mode = strtolower( $args[0] );
        $valid_modes = ['enabled', 'smart', 'disabled'];
        if ( ! in_array( $mode, $valid_modes, true ) ) { WP_CLI::error( "Invalid mode '{$mode}'. Please use 'enabled', 'smart', or 'disabled'." ); return; }
        $this->config( ['set', 'xmlrpc_protection_mode', $mode], [] );
        WP_CLI::success( "XML-RPC protection mode has been set to '{$mode}'." );
    }

        /**
     * Manages the Threat Scoring system.
     *
     * ## SYNOPSIS
     *
     *     wp advaipbl score <list|get|reset|decay-run> [--<field>=<value>]
     *
     * @subcommand score
     */
    public function score( $args, $assoc_args ) {
        $subcommand = array_shift( $args );
        if ( ! in_array( $subcommand, ['list', 'get', 'reset', 'decay-run'], true ) ) {
            WP_CLI::error( "Invalid subcommand. Use: list, get, reset, or decay-run." );
            return;
        }

        switch ($subcommand) {
            case 'list':
                $this->score_list($args, $assoc_args);
                break;
            case 'get':
                $this->score_get($args, $assoc_args);
                break;
            case 'reset':
                $this->score_reset($args, $assoc_args);
                break;
            case 'decay-run':
                $this->score_decay_run($args, $assoc_args);
                break;
        }
    }

    private function score_list( $args, $assoc_args ) {
        global $wpdb;
        $table_name = $wpdb->prefix . 'advaipbl_ip_scores';

        $orderby = $assoc_args['orderby'] ?? 'score';
        $order   = $assoc_args['order'] ?? 'desc';
        $format  = $assoc_args['format'] ?? 'table';

        if (!in_array($orderby, ['ip', 'score', 'last_event_timestamp'])) {
            $orderby = 'score';
        }
        if (!in_array($order, ['asc', 'desc'])) {
            $order = 'desc';
        }

        // phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        $items = $wpdb->get_results(
            "SELECT ip, score, FROM_UNIXTIME(last_event_timestamp) as last_activity FROM {$table_name} WHERE score > 0 ORDER BY " . esc_sql($orderby) . " " . esc_sql($order)
        );
        // phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared

        if ( empty( $items ) ) {
            WP_CLI::line( 'No IPs currently have an active threat score.' );
            return;
        }

        WP_CLI\Utils\format_items( $format, $items, ['ip', 'score', 'last_activity'] );
    }

    private function score_get( $args, $assoc_args ) {
        if (empty($args[0])) {
            WP_CLI::error('Please provide an IP address. Usage: wp advaipbl score get <ip>');
            return;
        }
        list( $ip ) = $args;
        $main = ADVAIPBL_Main::get_instance();

        $score = $main->threat_score_manager->get_score( $ip );
        
        // Comprobamos también si está bloqueado, por si el score es 0 pero sigue bloqueado.
        $blocked_list = get_option('advaipbl_blocked_ips_threat_score', []);
        
        if ( $score === 0 && !isset($blocked_list[$ip]) ) {
            WP_CLI::warning( "IP {$ip} does not have an active threat score and is not blocked by it." );
            return;
        }

        WP_CLI::line( "Threat Score for {$ip}: " . $score );
        
        $history = $main->threat_score_manager->get_log_details( $ip );
        if ( empty($history) ) {
            WP_CLI::line( 'No event history found.' );
            return;
        }

        $formatted_history = [];
        foreach($history as $event) {
            $details_str = '';
            if (!empty($event['details'])) {
                if (isset($event['details']['rule'])) $details_str = 'Rule: ' . $event['details']['rule'];
                elseif (isset($event['details']['url'])) $details_str = 'URL: ' . $event['details']['url'];
                elseif (isset($event['details']['uri'])) $details_str = 'URI: ' . $event['details']['uri'];
                elseif (isset($event['details']['username'])) $details_str = 'User: ' . $event['details']['username'];
            }

            $formatted_history[] = [
                'timestamp' => gmdate('Y-m-d H:i:s', $event['ts']),
                'event'     => $event['event'],
                'points'    => '+' . $event['points'],
                'details'   => $details_str,
            ];
        }

        WP_CLI\Utils\format_items( 'table', $formatted_history, ['timestamp', 'event', 'points', 'details'] );
    }

    private function score_reset( $args, $assoc_args ) {
        $ip = $args[0] ?? null;
        $all = WP_CLI\Utils\get_flag_value( $assoc_args, 'all', false );
        $main = ADVAIPBL_Main::get_instance();

        if ( !$ip && !$all ) {
            WP_CLI::error( 'Please provide an IP address or use the --all flag.' );
        }

        if ( $ip ) {
            if ( $main->threat_score_manager->reset_score($ip) ) {
                $main->desbloquear_ip($ip);
                WP_CLI::success( "Threat score for IP {$ip} has been reset and IP unblocked." );
            } else {
                WP_CLI::error( "Failed to reset score for IP {$ip}." );
            }
        }

        if ( $all ) {
            WP_CLI::confirm('Are you sure you want to reset ALL threat scores? This will not unblock IPs, only reset their scores to 0.');
            global $wpdb;
            $table_name = $wpdb->prefix . 'advaipbl_ip_scores';
            // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
            $wpdb->query( "TRUNCATE TABLE {$table_name}" );
            WP_CLI::success( 'All threat scores have been reset to 0.' );
        }
    }

    private function score_decay_run( $args, $assoc_args ) {
        WP_CLI::line( 'Manually running threat score decay process...' );
        $main = ADVAIPBL_Main::get_instance();
        $main->execute_threat_score_decay();
        WP_CLI::success( 'Decay process finished. Check the General Log for details.' );
    }

    /**
     * Checks the 2FA status for a specific user.
     *
     * ## OPTIONS
     *
     * <user>
     * : The user login, user email, or user ID.
     *
     * ## EXAMPLES
     *
     *     # Check 2FA status for user 'admin'
     *     $ wp advaipbl tfa_status admin
     */
        public function tfa_status( $args, $assoc_args ) {
    if ( ! $this->tfa_manager ) {
        WP_CLI::error( "The 2FA commands require PHP 8.1 or higher to run via WP-CLI. Your current PHP-CLI version is " . PHP_VERSION . "." );
        return;
    }

    if ( empty( $args[0] ) ) { WP_CLI::error( "Please specify a user login, email, or ID." ); return; }
    
    $user = get_user_by( 'id', $args[0] ) ?: get_user_by( 'login', $args[0] ) ?: get_user_by( 'email', $args[0] );
    if ( ! $user ) { WP_CLI::error( "User '{$args[0]}' not found." ); return; }

    $is_enabled = $this->tfa_manager->is_2fa_enabled_for_user( $user->ID );
    if ( $is_enabled ) {
        WP_CLI::success( "2FA is ACTIVE for user '{$user->user_login}' (ID: {$user->ID})." );
    } else {
        WP_CLI::line( "2FA is INACTIVE for user '{$user->user_login}' (ID: {$user->ID})." );
    }
}

    /**
     * Resets (deactivates) 2FA for a user.
     *
     * ## OPTIONS
     *
     * <user>
     * : The user login, user email, or user ID.
     *
     * ## EXAMPLES
     *
     *     # Reset 2FA for user with ID 123
     *     $ wp advaipbl tfa_reset 123
     */
        public function tfa_reset( $args, $assoc_args ) {
    if ( ! $this->tfa_manager ) {
        WP_CLI::error( "The 2FA commands require PHP 8.1 or higher to run via WP-CLI. Your current PHP-CLI version is " . PHP_VERSION . "." );
        return;
    }

    if ( empty( $args[0] ) ) { WP_CLI::error( "Please specify a user login, email, or ID." ); return; }
    
    $user = get_user_by( 'id', $args[0] ) ?: get_user_by( 'login', $args[0] ) ?: get_user_by( 'email', $args[0] );
    if ( ! $user ) { WP_CLI::error( "User '{$args[0]}' not found." ); return; }

    if ( ! $this->tfa_manager->is_2fa_enabled_for_user( $user->ID ) ) {
        WP_CLI::warning( "2FA is already inactive for user '{$user->user_login}'. No action taken." );
        return;
    }
    
    WP_CLI::confirm( "Are you sure you want to reset 2FA for user '{$user->user_login}'?" );
    
    $this->tfa_manager->admin_reset_for_user( $user->ID );

    WP_CLI::success( "2FA has been successfully reset for user '{$user->user_login}' (ID: {$user->ID})." );
}

    /**
     * Manages the list of Trusted Proxies.
     *
     * This list contains IPs, CIDR ranges, and ASNs of proxies (like Cloudflare or Varnish)
     * that are trusted to provide the real visitor IP via HTTP headers.
     *
     * ## OPTIONS
     *
     * <list|add|remove>
     * : The action to perform.
     * ---
     * options:
     *   - list
     *   - add
     *   - remove
     * ---
     *
     * [<entry>]
     * : The entry to add or remove (e.g., 1.2.3.4, 10.0.0.0/24, AS13335).
     * Required for 'add' and 'remove' actions.
     *
     * ## EXAMPLES
     *
     *     # List all trusted proxies
     *     $ wp advaipbl trusted-proxy list
     *
     *     # Add the Cloudflare ASN to the trusted list
     *     $ wp advaipbl trusted-proxy add AS13335
     *
     *     # Remove a specific IP from the trusted list
     *     $ wp advaipbl trusted-proxy remove 192.168.0.1
     *
     * @subcommand trusted-proxy
     */
    public function trusted_proxy( $args, $assoc_args ) {
        $subcommand = array_shift( $args );
        if ( ! in_array( $subcommand, [ 'list', 'add', 'remove' ], true ) ) {
            WP_CLI::error( "Invalid subcommand. Use 'list', 'add', or 'remove'." );
            return;
        }

        $settings = get_option( ADVAIPBL_Main::OPTION_SETTINGS, [] );
        $raw_list = $settings['trusted_proxies'] ?? '';
        $list = empty(trim($raw_list)) ? [] : array_filter(array_map('trim', explode("\n", $raw_list)));

        switch ( $subcommand ) {
            case 'list':
                if ( empty($list) ) {
                    WP_CLI::line( 'The trusted proxies list is empty.' );
                } else {
                    WP_CLI::line( 'Current Trusted Proxies:' );
                    foreach ($list as $entry) {
                        WP_CLI::line( "- {$entry}" );
                    }
                }
                break;

            case 'add':
                if ( empty( $args[0] ) ) {
                    WP_CLI::error( 'Please provide an entry (IP, CIDR, or ASN) to add.' );
                    return;
                }
                $entry_to_add = trim($args[0]);

                if ( in_array( $entry_to_add, $list, true ) ) {
                    WP_CLI::warning( "Entry '{$entry_to_add}' is already in the trusted proxies list." );
                    return;
                }

                $list[] = $entry_to_add;
                $settings['trusted_proxies'] = implode("\n", array_unique($list));
                update_option( ADVAIPBL_Main::OPTION_SETTINGS, $settings );
                $this->log_event_autonomo( sprintf( 'Trusted proxy entry "%s" added via WP-CLI.', $entry_to_add ), 'info' );
                WP_CLI::success( "Entry '{$entry_to_add}' added to the trusted proxies list." );
                break;

            case 'remove':
                if ( empty( $args[0] ) ) {
                    WP_CLI::error( 'Please provide an entry to remove.' );
                    return;
                }
                $entry_to_remove = trim($args[0]);
                $key = array_search( $entry_to_remove, $list, true );

                if ( false === $key ) {
                    WP_CLI::warning( "Entry '{$entry_to_remove}' not found in the trusted proxies list." );
                    return;
                }

                unset($list[$key]);
                $settings['trusted_proxies'] = implode("\n", $list);
                update_option( ADVAIPBL_Main::OPTION_SETTINGS, $settings );
                $this->log_event_autonomo( sprintf( 'Trusted proxy entry "%s" removed via WP-CLI.', $entry_to_remove ), 'info' );
                WP_CLI::success( "Entry '{$entry_to_remove}' removed from the trusted proxies list." );
                break;
        }
    }
	
	    /**
     * Manages the Geo-Challenge feature.
     *
     * Allows enabling/disabling the feature and managing the list of countries
     * whose visitors will be presented with a JavaScript challenge.
     *
     * ## SYNOPSIS
     *
     *     wp advaipbl geo-challenge <enable|disable|add|remove|list> [<country_code>]
     *
     * ## SUBCOMMANDS
     *
     *     enable
     *       : Enables the Geo-Challenge feature.
     *
     *     disable
     *       : Disables the Geo-Challenge feature.
     *
     *     list
     *       : Lists all countries currently in the challenge list.
     *
     *     add <country_code>
     *       : Adds a 2-letter country code to the challenge list.
     *
     *     remove <country_code>
     *       : Removes a 2-letter country code from the challenge list.
     *
     * ## EXAMPLES
     *
     *     # Enable the Geo-Challenge feature
     *     $ wp advaipbl geo-challenge enable
     *
     *     # Add United States to the challenge list
     *     $ wp advaipbl geo-challenge add US
     *
     *     # List all challenged countries
     *     $ wp advaipbl geo-challenge list
     *
     * @subcommand geo-challenge
     */
    public function geo_challenge( $args, $assoc_args ) {
        $subcommand = array_shift( $args );
        $valid_subcommands = ['enable', 'disable', 'add', 'remove', 'list'];
        if ( ! in_array( $subcommand, $valid_subcommands, true ) ) {
            WP_CLI::error( "Invalid subcommand. Use: " . implode(', ', $valid_subcommands) );
            return;
        }

        if ( in_array($subcommand, ['enable', 'disable']) ) {
            $new_value = ($subcommand === 'enable') ? '1' : '0';
            $this->config(['set', 'enable_geo_challenge', $new_value], []);
            WP_CLI::success( "Geo-Challenge has been {$subcommand}d." );
            return;
        }

        $settings = get_option(ADVAIPBL_Main::OPTION_SETTINGS, []);
        $challenged_countries = $settings['geo_challenge_countries'] ?? [];

        switch ( $subcommand ) {
            case 'add':
                if ( count($args) < 1 ) { WP_CLI::error( 'Please provide a 2-letter country code. Usage: wp advaipbl geo-challenge add <country_code>' ); return; }
                $country_code = strtoupper($args[0]);
                if ( strlen($country_code) !== 2 ) { WP_CLI::error( 'Country code must be 2 letters (e.g., US, DE, CN).' ); return; }
                if ( in_array($country_code, $challenged_countries, true) ) { WP_CLI::warning( "Country {$country_code} is already in the challenge list." ); return; }
                
                $challenged_countries[] = $country_code;
                $settings['geo_challenge_countries'] = array_values(array_unique($challenged_countries));
                update_option(ADVAIPBL_Main::OPTION_SETTINGS, $settings);
                $this->log_event_autonomo( sprintf( 'Country %s added to Geo-Challenge list via WP-CLI.', $country_code ), 'info' );
                WP_CLI::success( "Country {$country_code} added to the challenge list." );
                break;

            case 'remove':
                if ( count($args) < 1 ) { WP_CLI::error( 'Please provide a country code to remove.' ); return; }
                $country_code = strtoupper($args[0]);
                $key = array_search($country_code, $challenged_countries, true);
                if ( false === $key ) { WP_CLI::warning( "Country {$country_code} was not found in the challenge list." ); return; }
                
                unset($challenged_countries[$key]);
                $settings['geo_challenge_countries'] = array_values($challenged_countries);
                update_option(ADVAIPBL_Main::OPTION_SETTINGS, $settings);
                $this->log_event_autonomo( sprintf( 'Country %s removed from Geo-Challenge list via WP-CLI.', $country_code ), 'info' );
                WP_CLI::success( "Country {$country_code} removed from the challenge list." );
                break;

            case 'list':
                if ( empty($challenged_countries) ) {
                    WP_CLI::line('The Geo-Challenge country list is empty.');
                } else {
                    WP_CLI::line('Challenged country codes:');
                    foreach ($challenged_countries as $code) {
                        WP_CLI::line("- {$code}");
                    }
                }
                break;
        }
    }
	
	    /**
     * Manages the list of whitelisted Autonomous System Numbers (ASNs).
     *
     * Traffic from whitelisted ASNs will bypass ALL other blocking rules,
     * including the WAF and Signature Engine. Use this for trusted services
     * like Google (AS15169) or Cloudflare (AS13335).
     *
     * ## OPTIONS
     *
     * <list|add|remove>
     * : The action to perform.
     *
     * [<asn>]
     * : The ASN to add or remove (e.g., AS15169).
     * Required for 'add' and 'remove' actions.
     *
     * ## EXAMPLES
     *
     *     # Whitelist Google's ASN
     *     $ wp advaipbl asn-whitelist add AS15169
     *
     *     # List all whitelisted ASNs
     *     $ wp advaipbl asn-whitelist list
     *
     * @subcommand asn-whitelist
     */
    public function asn_whitelist( $args, $assoc_args ) {
        if ( ! class_exists('GeoIp2\Database\Reader') ) {
            WP_CLI::error( "This command requires PHP 8.1 or higher to run via WP-CLI. Your current PHP-CLI version is " . PHP_VERSION . "." );
            return;
        }

        $subcommand = array_shift( $args );
        if ( ! in_array( $subcommand, [ 'add', 'remove', 'list' ], true ) ) { WP_CLI::error( 'Invalid subcommand. Use: add, remove, or list.' ); return; }
        
        $option_key = ADVAIPBL_Main::OPTION_WHITELISTED_ASNS;
        $whitelisted_asns = get_option( $option_key, [] );
        if (!is_array($whitelisted_asns)) $whitelisted_asns = [];

        switch ( $subcommand ) {
            case 'add':
                if ( empty( $args[0] ) ) { WP_CLI::error( 'Please provide an ASN to add (e.g., AS12345).' ); return; }
                $asn_to_add = strtoupper(trim($args[0]));
                if ( ! preg_match('/^AS\d+$/i', $asn_to_add) ) { WP_CLI::error( "Invalid ASN format. Please use the format 'AS' followed by numbers (e.g., AS15169)." ); return; }
                if ( in_array($asn_to_add, $whitelisted_asns, true) ) { WP_CLI::warning( "ASN {$asn_to_add} is already in the whitelist." ); return; }
                
                $whitelisted_asns[] = $asn_to_add;
                update_option($option_key, array_unique($whitelisted_asns));
                $this->log_event_autonomo( sprintf( 'ASN %s added to whitelist via WP-CLI.', $asn_to_add ), 'info' );
                WP_CLI::success( "ASN {$asn_to_add} added to the whitelist." );
                break;

            case 'remove':
                if ( empty( $args[0] ) ) { WP_CLI::error( 'Please provide an ASN to remove.' ); return; }
                $asn_to_remove = strtoupper(trim($args[0]));
                $key = array_search($asn_to_remove, $whitelisted_asns, true);
                if ( false === $key ) { WP_CLI::warning( "ASN {$asn_to_remove} was not found in the whitelist." ); return; }
                
                unset($whitelisted_asns[$key]);
                update_option($option_key, array_values($whitelisted_asns));
                $this->log_event_autonomo( sprintf( 'ASN %s removed from whitelist via WP-CLI.', $asn_to_remove ), 'info' );
                WP_CLI::success( "ASN {$asn_to_remove} removed from the whitelist." );
                break;

            case 'list':
                if ( empty($whitelisted_asns) ) {
                    WP_CLI::line('The ASN whitelist is empty.');
                } else {
                    WP_CLI::line('Whitelisted ASNs:');
                    foreach ($whitelisted_asns as $asn) {
                        WP_CLI::line("- {$asn}");
                    }
                }
                break;
        }
    }
	
	    /**
     * Manages the Attack Signature engine.
     *
     * ## OPTIONS
     *
     * <list|delete|whitelist>
     * : The action to perform on signatures.
     * ---
     * options:
     *   - list
     *   - delete
     *   - whitelist
     * ---
     *
     * [--hash=<hash>]
     * : The full 64-character signature hash. Required for 'delete' and 'whitelist'.
     *
     * [--format=<format>]
     * : Render output for 'list' action.
     * ---
     * default: table
     * options:
     *   - table
     *   - json
     *   - csv
     * ---
     *
     * ## EXAMPLES
     *
     *     # List all currently active malicious signatures
     *     $ wp advaipbl signature list
     *
     *     # Whitelist a specific signature to always allow it
     *     $ wp advaipbl signature whitelist --hash=d455b...
     *
     *     # Delete a specific malicious signature rule
     *     $ wp advaipbl signature delete --hash=c2d7b...
     *
     * @subcommand signature
     */
    public function signature( $args, $assoc_args ) {
        $subcommand = array_shift( $args );
        if ( ! in_array( $subcommand, [ 'list', 'delete', 'whitelist' ], true ) ) {
            WP_CLI::error( "Invalid subcommand. Use 'list', 'delete', or 'whitelist'." );
            return;
        }

        $main_instance = ADVAIPBL_Main::get_instance();

        switch ( $subcommand ) {
            case 'list':
                global $wpdb;
                $table_name = $wpdb->prefix . 'advaipbl_malicious_signatures';
                // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
                $items = $wpdb->get_results("SELECT signature_hash, reason, FROM_UNIXTIME(last_seen) as last_seen, FROM_UNIXTIME(expires_at) as expires_at FROM {$table_name}", ARRAY_A);
                
                if (empty($items)) {
                    WP_CLI::line('No active malicious signatures found.');
                    return;
                }
                WP_CLI\Utils\format_items( $assoc_args['format'] ?? 'table', $items, ['signature_hash', 'reason', 'last_seen', 'expires_at'] );
                break;

            case 'delete':
            case 'whitelist':
                $hash = $assoc_args['hash'] ?? null;
                if ( empty($hash) || strlen($hash) !== 64 ) {
                    WP_CLI::error( "A valid 64-character --hash is required for this action." );
                    return;
                }
                
                if ($subcommand === 'delete') {
                    if ( $main_instance->fingerprint_manager->delete_signature($hash) ) {
                        WP_CLI::success( "Signature '{$hash}' deleted successfully." );
                    } else {
                        WP_CLI::error( "Failed to delete signature '{$hash}'. It may not exist." );
                    }
                } else { // Whitelist
                    $options = get_option(ADVAIPBL_Main::OPTION_SETTINGS, []);
                    $current_whitelist = $options['trusted_signature_hashes'] ?? '';
                    if (strpos($current_whitelist, $hash) !== false) {
                        WP_CLI::warning("Signature '{$hash}' is already in the whitelist.");
                        return;
                    }
                    $options['trusted_signature_hashes'] = trim($current_whitelist . "\n" . $hash);
                    update_option(ADVAIPBL_Main::OPTION_SETTINGS, $options);
                    $main_instance->fingerprint_manager->delete_signature($hash); // Also delete from malicious list
                    WP_CLI::success( "Signature '{$hash}' whitelisted and removed from the active block list." );
                }
                break;
        }
    }

    /**
     * Manually triggers the signature analysis process.
     *
     * This command forces the plugin to analyze the recent request logs
     * to identify and flag new malicious attack signatures.
     *
     * ## EXAMPLES
     *
     *     $ wp advaipbl signature-analyze
     *
     * @subcommand signature-analyze
     */
    public function signature_analyze( $args, $assoc_args ) {
        $main_instance = ADVAIPBL_Main::get_instance();
        if (empty($main_instance->options['enable_signature_analysis'])) {
            WP_CLI::warning( "Signature analysis is disabled in the settings. The command will run, but no new signatures will be flagged unless you enable it." );
        }
        
        WP_CLI::line('Starting signature analysis...');
        $main_instance->execute_signature_analysis();
        WP_CLI::success('Signature analysis process finished. Check the General Log for details and the Blocked Signatures page for any newly flagged signatures.');
    }
	
}