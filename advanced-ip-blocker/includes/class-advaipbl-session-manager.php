<?php

if ( ! defined( 'ABSPATH' ) ) exit;

class ADVAIPBL_User_Session_Manager{
	private $geolocation_manager;
	private $plugin_instance;

	public function __construct( $plugin_instance, ADVAIPBL_Geolocation_Manager $geolocation_manager ){
        $this->plugin_instance = $plugin_instance;
        $this->geolocation_manager = $geolocation_manager;
		add_action('wp_ajax_advaipbl_close_user_session',[$this,'ajax_close_user_session']);
		add_action('wp_ajax_advaipbl_close_all_user_sessions',[$this,'ajax_close_all_user_sessions']);
		add_action('wp_ajax_advaipbl_close_sessions_by_role',[$this,'ajax_close_sessions_by_role']);
		add_action('admin_post_advaipbl_usm_save_settings',[$this,'save_settings']);
	}

	public function enqueue_scripts_styles(){
    wp_enqueue_style('advaipbl-styles', plugin_dir_url(dirname(__FILE__)) . 'css/advaipbl-styles.css', [], ADVAIPBL_VERSION);
    wp_enqueue_script('advaipbl-script', plugin_dir_url(dirname(__FILE__)) . 'js/advaipbl-script.js', ['jquery', 'advaipbl-admin-core-js'], ADVAIPBL_VERSION, true);
    
    // Usamos la función de traducción __() para cada cadena.
    wp_localize_script('advaipbl-script','advaipbl_ajax_obj',[
        'ajax_url'              => admin_url('admin-ajax.php'),
        'nonce_close_session'   => wp_create_nonce('advaipbl_close_session_nonce'),
        'nonce_close_all'       => wp_create_nonce('advaipbl_close_all_sessions_nonce'),
        'nonce_close_by_role'   => wp_create_nonce('advaipbl_close_sessions_by_role_nonce'),
        
        // Textos para los mensajes del cuerpo del modal
        'text_confirm_close_user' => __('Close all sessions for this user?', 'advanced-ip-blocker'),
        'text_confirm_close_all'  => __('Close ALL sessions for ALL users?', 'advanced-ip-blocker'),
        'text_confirm_close_role' => __('Close all sessions for the selected role?', 'advanced-ip-blocker'),
        'text_select_role'        => __('Please select a role.', 'advanced-ip-blocker'),
        'title_close_user'        => __('Close User Sessions', 'advanced-ip-blocker'),
        'title_close_all'         => __('Close All Sessions', 'advanced-ip-blocker'),
        'title_close_role'        => __('Close Sessions by Role', 'advanced-ip-blocker'),        
        'btn_close_user'          => __('Yes, Close Sessions', 'advanced-ip-blocker'),
        'btn_close_all'           => __('Yes, Close All', 'advanced-ip-blocker'),
        'btn_close_role'          => __('Yes, Close for This Role', 'advanced-ip-blocker'),
        'title_clear_cache'       => __('Clear Location Cache', 'advanced-ip-blocker'),
        'text_confirm_clear_cache'=> __('Are you sure you want to clear the location cache?', 'advanced-ip-blocker'),
        'btn_clear_cache'         => __('Yes, Clear Cache', 'advanced-ip-blocker'),
    ]);
}

    public function display_admin_page() {
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( esc_html__( 'You do not have permission to access this page.', 'advanced-ip-blocker' ) );
    }

    $this->enqueue_scripts_styles();

    // 1. Obtener parámetros de la URL de forma segura.
    // phpcs:disable WordPress.Security.NonceVerification.Recommended
    $search_term  = isset( $_GET['s'] ) ? sanitize_text_field( wp_unslash( $_GET['s'] ) ) : '';
    $orderby      = isset( $_GET['orderby'] ) ? sanitize_key( $_GET['orderby'] ) : 'last_activity';
    $order        = isset( $_GET['order'] ) ? strtolower( sanitize_key( $_GET['order'] ) ) : 'desc';
    $current_page = isset( $_GET['paged'] ) ? absint( $_GET['paged'] ) : 1;
    $per_page     = isset( $_GET['advaipbl_per_page'] ) ? absint( $_GET['advaipbl_per_page'] ) : 20;
    // phpcs:enable

    // 2. Obtener y filtrar datos.
    $all_sessions = $this->get_active_sessions();
    $sessions_to_display = $all_sessions;
    if ( ! empty( $search_term ) ) {
        $sessions_to_display = array_filter(
            $all_sessions,
            function ( $session ) use ( $search_term ) {
                $search_in = [ $session['username'] ?? '', $session['email'] ?? '', $session['ip'] ?? '' ];
                foreach ( $search_in as $field ) {
                    if ( stripos( $field, $search_term ) !== false ) {
                        return true;
                    }
                }
                return false;
            }
        );
    }

    // 3. Ordenar datos
    $sortable_columns = [ 'username', 'role', 'ip', 'last_activity' ];
    if( !in_array($orderby, $sortable_columns, true) ) $orderby = 'last_activity';
    if( !in_array($order, ['asc', 'desc'], true) ) $order = 'desc';

    // La llamada a usort()
    usort(
        $sessions_to_display,
        function ( $a, $b ) use ( $orderby, $order ) {
            $a_val = $a[ $orderby ] ?? '';
            $b_val = $b[ $orderby ] ?? '';
            if ( 'last_activity' === $orderby ) {
                $a_val = strtotime( $a_val );
                $b_val = strtotime( $b_val );
            }
            if ( $a_val == $b_val ) return 0;
            return ( 'asc' === $order ) ? ( $a_val <=> $b_val ) : ( $b_val <=> $a_val );
        }
    );

    // 4. Paginación
    $total_items   = count( $sessions_to_display );
    $total_pages   = ceil( $total_items / $per_page );
    $sessions_page = array_slice( $sessions_to_display, ( $current_page - 1 ) * $per_page, $per_page );
    
    // 5. Preparar datos adicionales
    $all_roles = [];
    if ( ! empty( $all_sessions ) ) {
        foreach ( $all_sessions as $session ) {
            if ( isset( $session['role'] ) ) {
                foreach ( explode( ', ', $session['role'] ) as $r ) {
                    if ( ! empty( $r ) ) $all_roles[ $r ] = true;
                }
            }
        }
    }
    $locations = $this->get_cached_locations( array_column( $sessions_page, 'ip' ) );
    ?>
    
    <h2><?php esc_html_e( 'Active User Sessions', 'advanced-ip-blocker' ); ?></h2>
    
    <div class="tablenav top">
        <div class="alignleft actions bulkactions">
            <form method="get">
                <?php // phpcs:ignore WordPress.Security.NonceVerification.Recommended ?>
                <input type="hidden" name="page" value="<?php echo esc_attr( isset($_REQUEST['page']) ? sanitize_text_field(wp_unslash($_REQUEST['page'])) : '' ); ?>">
                <input type="hidden" name="tab" value="logs">
                <input type="hidden" name="sub-tab" value="user_sessions">
                
                <?php 
                // Asegurarse de que $this->plugin_instance no es null antes de llamar al método.
                if ( $this->plugin_instance ) {
                    $this->plugin_instance->render_per_page_selector( $per_page ); 
                }
                ?>
                
                <label class="screen-reader-text" for="session-search-input"><?php esc_html_e( 'Search (user, email, IP):', 'advanced-ip-blocker' ); ?></label>
                <input type="search" id="session-search-input" name="s" value="<?php echo esc_attr( $search_term ); ?>" placeholder="<?php esc_attr_e( 'Search by user, email, IP...', 'advanced-ip-blocker' ); ?>">	

                <input type="submit" class="button" value="<?php esc_attr_e( 'Search', 'advanced-ip-blocker' ); ?>">
            </form>
        </div>
        
        <div class="alignleft actions">
            <form id="advaipbl-clear-location-cache-form" method="post" action="">
                <input type="hidden" name="action_type" value="clear_location_cache">
                <?php wp_nonce_field('advaipbl_admin_nonce_action', 'advaipbl_admin_nonce_action'); ?>
                <button type="button" id="advaipbl-btn-clear-location-cache" class="button"><?php esc_html_e('Clear Location Cache', 'advanced-ip-blocker'); ?></button>
            </form>
        </div>

        <div class="tablenav-pages">
            <span class="displaying-num">
                <?php /* translators: %s: Sesions number. */ printf( esc_html( _n( '%s session', '%s sessions', $total_items, 'advanced-ip-blocker' ) ), esc_html( number_format_i18n( $total_items ) ) ); ?>
            </span>
            <?php 
            $page_links = paginate_links(['base' => add_query_arg(['paged' => '%#%', 's' => $search_term]), 'format' => '', 'total' => $total_pages, 'current' => $current_page]); 
            if ($page_links) echo '<span class="pagination-links">' . wp_kses_post($page_links) . '</span>'; 
            ?>
        </div>
        <br class="clear">
    </div>
    
	<div class="advaipbl-table-responsive-wrapper">
    <table class="widefat fixed striped advaipbl-sessions-table" style="margin-top:1em;">
        <thead>
            <tr>
                <?php $this->print_sortable_header( __( 'User', 'advanced-ip-blocker' ), 'username', $orderby, $order, $search_term ); ?>
                <?php $this->print_sortable_header( __( 'Role', 'advanced-ip-blocker' ), 'role', $orderby, $order, $search_term ); ?>
                <?php $this->print_sortable_header( __( 'IP', 'advanced-ip-blocker' ), 'ip', $orderby, $order, $search_term ); ?>
                <th><?php esc_html_e( 'Location', 'advanced-ip-blocker' ); ?></th>
                <th><?php esc_html_e( 'ISP / Organization', 'advanced-ip-blocker' ); ?></th>
                <?php $this->print_sortable_header( __( 'Last Activity', 'advanced-ip-blocker' ), 'last_activity', $orderby, $order, $search_term ); ?>
                <th><?php esc_html_e( 'Actions', 'advanced-ip-blocker' ); ?></th>
            </tr>
        </thead>
        <tbody>
            <?php if ( empty( $sessions_page ) ) : ?>
                <tr><td colspan="7"><?php echo empty( $search_term ) ? esc_html__( 'No active sessions.', 'advanced-ip-blocker' ) : esc_html__( 'No results found.', 'advanced-ip-blocker' ); ?></td></tr>
            <?php else : foreach ( $sessions_page as $session ) :
                $location = $locations[ $session['ip'] ] ?? null;
                $location_parts = [];
                if ( $location ) {
                    if ( ! empty( $location['city'] ) ) $location_parts[] = $location['city'];
                    if ( ! empty( $location['region'] ) ) $location_parts[] = $location['region'];
                    if ( ! empty( $location['country'] ) ) $location_parts[] = $location['country'] . (!empty($location['country_code']) ? ' (' . $location['country_code'] . ')' : '');
                } ?>
                <tr>
                    <td><?php echo esc_html( $session['username'] ); ?><br><small><?php echo esc_html( $session['email'] ); ?></small></td>
                    <td><?php echo esc_html( $session['role'] ); ?></td><td><?php echo esc_html( $session['ip'] ); ?></td>
                    <td><?php if ( ! empty( $location_parts ) ) : echo esc_html( implode( ', ', $location_parts ) ); ?><br><button class="button button-small advaipbl-btn-map" data-lat="<?php echo esc_attr( $location['lat'] ?? '' ); ?>" data-lon="<?php echo esc_attr( $location['lon'] ?? '' ); ?>"><?php esc_html_e( 'View Map', 'advanced-ip-blocker' ); ?></button><?php else : esc_html_e( 'Not available', 'advanced-ip-blocker' ); endif; ?></td>
                    <td><?php echo esc_html( $location['isp'] ?? 'N/A' ); ?></td>
                    <td><?php echo esc_html( ADVAIPBL_Main::get_formatted_datetime( strtotime( $session['last_activity'] ) ) ); ?><br><small><?php echo esc_html( $this->parse_user_agent( $session['device'] ) ); ?></small></td>
                    <td><button class="button advaipbl-btn-close-user" data-user-id="<?php echo esc_attr( $session['user_id'] ); ?>"><?php esc_html_e( 'Close Sessions', 'advanced-ip-blocker' ); ?></button></td>
                </tr>
            <?php endforeach; endif; ?>
        </tbody>
    </table>
	</div>
    
    <div style="margin-top:20px;"><button id="advaipbl-close-all-btn" class="button button-primary"><?php esc_html_e( 'Close All Sessions', 'advanced-ip-blocker' ); ?></button></div>
    <div style="margin-top:20px;">
        <h2><?php esc_html_e( 'Close sessions by role', 'advanced-ip-blocker' ); ?></h2>
        <select id="role-selector"><option value=""><?php esc_html_e( '-- Select a Role --', 'advanced-ip-blocker' ); ?></option>
            <?php foreach ( array_keys( $all_roles ) as $role ) : if ( empty( $role ) ) continue; ?>
                <option value="<?php echo esc_attr( $role ); ?>"><?php echo esc_html( translate_user_role( $role ) ); ?></option>
            <?php endforeach; ?>
        </select>
        <button id="advaipbl-close-role-btn" class="button"><?php esc_html_e( 'Close sessions for this role', 'advanced-ip-blocker' ); ?></button>
    </div>
    
    <div id="mapModal"><div id="mapModalContent"><div id="mapModalHeader"><button id="closeModalBtn" class="button"><?php esc_html_e( 'Close', 'advanced-ip-blocker' ); ?></button></div><iframe id="mapModalFrame" loading="lazy"></iframe></div></div>
    <?php
    }
	
	private function print_sortable_header($label, $column_key, $orderby, $order, $search_term = '') {
		if ($orderby === $column_key) {
			$next_order = ($order === 'desc') ? 'asc' : 'desc';
			$arrow_class = 'sorted ' . $order;
		} else {
			$next_order = 'desc';
			$arrow_class = 'sortable desc';
		}
		$url = add_query_arg([
			'orderby' => $column_key,
			'order'   => $next_order,
			's'       => $search_term
		]);
		echo '<th scope="col" class="manage-column column-primary ' . esc_attr($arrow_class) . '">';
		echo '<a href="' . esc_url($url) . '"><span>' . esc_html($label) . '</span><span class="sorting-indicator"></span></a>';
		echo '</th>';
	}
	
	public function ajax_close_user_session(){ 
    check_ajax_referer('advaipbl_close_session_nonce', 'nonce');
    if(!current_user_can('manage_options')){ wp_send_json_error(['message' => __('Permission denied.', 'advanced-ip-blocker')]); } 
    $user_id = isset($_POST['user_id']) ? intval($_POST['user_id']) : 0; 
    if ($user_id > 0) { 
        $user_to_logout = get_userdata($user_id); 
        WP_Session_Tokens::get_instance($user_id)->destroy_all(); 
        
        // Invalidar la caché
        delete_transient( 'advaipbl_active_sessions_cache' );

        if ($user_to_logout) { 
            /* translators: 1: Username being logged out, 2: Admin username performing the action. */ 
            $message = sprintf( __('Sessions for user "%1$s" were closed by %2$s.', 'advanced-ip-blocker'), $user_to_logout->user_login, wp_get_current_user()->user_login ); 
            if (isset($this->plugin_instance)) $this->plugin_instance->log_event($message, 'warning'); 
        } 
        wp_send_json_success(); 
    } else { 
        wp_send_json_error(['message' => __('Invalid user ID.', 'advanced-ip-blocker')]); 
    } 
}

	public function ajax_close_all_user_sessions(){ 
    check_ajax_referer('advaipbl_close_all_sessions_nonce', 'nonce');
    if(!current_user_can('manage_options')){ wp_send_json_error(['message' => __('Permission denied.', 'advanced-ip-blocker')]); } 
    foreach(get_users(['fields'=>'ID']) as $user_id) { 
        WP_Session_Tokens::get_instance($user_id)->destroy_all(); 
    } 
    
    // Invalidar la caché
    delete_transient( 'advaipbl_active_sessions_cache' );

    /* translators: %s: Admin username performing the action. */ 
    $message = sprintf( __('All sessions for ALL users were closed by %s.', 'advanced-ip-blocker'), wp_get_current_user()->user_login ); 
    if (isset($this->plugin_instance)) $this->plugin_instance->log_event($message, 'critical'); 
    wp_send_json_success(); 
}
	
	public function ajax_close_sessions_by_role(){ 
    check_ajax_referer('advaipbl_close_sessions_by_role_nonce', 'nonce');
    if(!current_user_can('manage_options')){ wp_send_json_error(['message' => __('Permission denied.', 'advanced-ip-blocker')]); } 
    $role = isset($_POST['role']) ? sanitize_text_field(wp_unslash($_POST['role'])) : ''; 
    if(!empty($role)){ 
        foreach(get_users(['role'=>$role, 'fields'=>'ID']) as $user_id) { 
            WP_Session_Tokens::get_instance($user_id)->destroy_all(); 
        } 

        // Invalidar la caché
        delete_transient( 'advaipbl_active_sessions_cache' );

        /* translators: 1: The user role, 2: Admin username performing the action. */ 
        $message = sprintf( __('All sessions for role "%1$s" were closed by %2$s.', 'advanced-ip-blocker'), $role, wp_get_current_user()->user_login ); 
        if (isset($this->plugin_instance)) $this->plugin_instance->log_event($message, 'warning'); 
    } 
    wp_send_json_success(); 
}
	public function save_settings(){if(!current_user_can('manage_options')||!check_admin_referer('advaipbl_usm_save_settings_nonce'))wp_die(esc_html__('Action not allowed.', 'advanced-ip-blocker'));$per_page=isset($_POST['sessions_per_page'])?intval(wp_unslash($_POST['sessions_per_page'])):10;update_option('advaipbl_usm_sessions_per_page',max(1,min(100,$per_page)));wp_safe_redirect(admin_url('options-general.php?page=advaipbl_settings_page&tab=user_sessions'));exit;}
	public function get_active_sessions() {
    // Definimos una clave única para nuestra caché.
    $cache_key = 'advaipbl_active_sessions_cache';

    // Intentamos obtener los datos de la caché primero.
    $cached_sessions = get_transient( $cache_key );

    // Si la caché existe y no está vacía, la devolvemos inmediatamente.
    if ( false !== $cached_sessions ) {
        return $cached_sessions;
    }

    // --- Si la caché no existe, ejecutamos la lógica original ---
    global $wpdb;
    $sessions = [];

    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
    $results  = $wpdb->get_results( "SELECT user_id, meta_value FROM {$wpdb->usermeta} WHERE meta_key = 'session_tokens'" );

    foreach ( $results as $row ) {
        $tokens = maybe_unserialize( $row->meta_value );
        if ( ! is_array( $tokens ) ) {
            continue;
        }

        $user = get_userdata( $row->user_id );
        if ( ! $user ) {
            continue;
        }

        $role = implode( ', ', $user->roles );

        foreach ( $tokens as $token_data ) {
            if ( isset( $token_data['expiration'] ) && $token_data['expiration'] > time() ) {
                $sessions[] = [
                    'user_id'       => $user->ID,
                    'username'      => $user->user_login,
                    'email'         => $user->user_email,
                    'role'          => $role,
                    'ip'            => $token_data['ip'] ?? __( 'Unknown', 'advanced-ip-blocker' ),
                    'device'        => $token_data['ua'] ?? __( 'Unknown', 'advanced-ip-blocker' ),
                    'last_activity' => date_i18n( 'Y-m-d H:i:s', $token_data['login'] ?? time() ),
                ];
            }
        }
    }
    
    // Guardamos los resultados en la caché antes de devolverlos.
    // 60 segundos es un buen valor para no sobrecargar la BD pero mantener los datos relativamente frescos.
    set_transient( $cache_key, $sessions, 60 );

    return $sessions;
}
    /**
     * Obtiene las ubicaciones para un array de IPs, utilizando nuestra tabla de caché personalizada.
     *
     * @param array $ips Un array de direcciones IP a localizar.
     * @return array Un array asociativo de [ip => location_data].
     */
    public function get_cached_locations( $ips ) {
        if ( ! $this->plugin_instance ) {
            // Salvaguarda por si la instancia principal no está disponible.
            return [];
        }
        
        // La clave de caché ahora es un identificador simple para todo el grupo de localizaciones.
        $cache_key = ADVAIPBL_USM_LOCATION_CACHE_KEY;
        $cache = $this->plugin_instance->get_from_custom_cache( $cache_key );

        if ( ! is_array( $cache ) ) {
            $cache = [];
        }

        $unique_ips = array_unique( array_filter( $ips ) );
        $ips_to_fetch = array_filter( $unique_ips, function( $ip ) use ( $cache ) {
            return ! isset( $cache[ $ip ] ) || ! is_array( $cache[ $ip ] );
        });

        if ( empty( $ips_to_fetch ) ) {
            return $cache;
        }

        foreach ( $ips_to_fetch as $ip ) {
            if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
                $location = $this->geolocation_manager->fetch_location( $ip );
                if ( is_array( $location ) ) {
                    $cache[ $ip ] = $location;
                }
            }
        }
        
        // El TTL (Time To Live) se define en una constante.
        $ttl = ADVAIPBL_USM_LOCATION_CACHE_TTL;
        $this->plugin_instance->set_in_custom_cache( $cache_key, $cache, $ttl );

        return $cache;
    }
	
    public function parse_user_agent($ua){
    if(empty($ua)||$ua===__('Unknown', 'advanced-ip-blocker'))return __('Unknown', 'advanced-ip-blocker');
    $os=__('Unknown OS', 'advanced-ip-blocker');
    $browser=__('Unknown Browser', 'advanced-ip-blocker');
    if(preg_match('/(Windows|Macintosh|Android|iPhone|iPad|Linux)/i',$ua,$matches))$os=$matches[1];
    if(preg_match('/(Chrome|Firefox|Safari|Edge|MSIE|Trident)/i',$ua,$matches)){
        $browser=$matches[1]=='Trident'||$matches[1]=='MSIE'?'IE':$matches[1];
    }
    if($browser=='Safari'&&preg_match('/Chrome/i',$ua))$browser='Chrome';
    /* translators: 1: Browser name, 2: Operating System name. */
    return sprintf(__('%1$s on %2$s', 'advanced-ip-blocker'), $browser, $os);
    }
}