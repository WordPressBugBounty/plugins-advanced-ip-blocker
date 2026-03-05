<?php

if ( ! defined( 'ABSPATH' ) ) exit;

if ( ! class_exists( 'WP_List_Table' ) ) {
    require_once( ABSPATH . 'wp-admin/includes/class-wp-list-table.php' );
}

class ADVAIPBL_2FA_Users_List_Table extends WP_List_Table {

    public function __construct() {
    parent::__construct([
        'singular' => 'User',
        'plural'   => 'Users',
        'ajax'     => false
    ]);
}

        public function prepare_items() {
        // phpcs:disable WordPress.Security.NonceVerification.Recommended
		$this->_column_headers = [ $this->get_columns(), [], $this->get_sortable_columns() ];
        $this->_args['singular'] = __( 'User', 'advanced-ip-blocker' );
        $this->_args['plural'] = __( 'Users', 'advanced-ip-blocker' );	
        $columns = $this->get_columns();
        $hidden = [];
        $sortable = $this->get_sortable_columns();
        $this->_column_headers = [$columns, $hidden, $sortable];

        $per_page = 20;
        $current_page = $this->get_pagenum();

        $args = [
            'number' => $per_page,
            'offset' => ( $current_page - 1 ) * $per_page,
            'orderby' => isset($_REQUEST['orderby']) ? sanitize_text_field(wp_unslash($_REQUEST['orderby'])) : 'login',
            'order' => isset($_REQUEST['order']) ? sanitize_text_field(wp_unslash($_REQUEST['order'])) : 'ASC',
        ];

        // 1. Añadir lógica de búsqueda
        if ( ! empty( $_REQUEST['s'] ) ) {
            $args['search'] = '*' . sanitize_text_field(wp_unslash($_REQUEST['s'])) . '*';
            $args['search_columns'] = ['user_login', 'user_email', 'display_name'];
        }

        // 2. Añadir lógica de filtro por rol
        if ( ! empty( $_REQUEST['role'] ) ) {
            $args['role'] = sanitize_key(wp_unslash($_REQUEST['role']));
        }
        
        // 3. Añadir lógica de filtro por estado 2FA
        $tfa_status_filter = isset($_REQUEST['tfa_status']) ? sanitize_text_field(wp_unslash($_REQUEST['tfa_status'])) : 'all';
        if ( in_array( $tfa_status_filter, ['active', 'inactive'] ) ) {
            $args['meta_key'] = ADVAIPBL_2fa_Manager::META_ENABLED_AT;
            if ( 'active' === $tfa_status_filter ) {
                $args['meta_compare'] = 'EXISTS';
            } else { // 'inactive'
                $args['meta_compare'] = 'NOT EXISTS';
            }
        }
        
        $user_query = new WP_User_Query( $args );
        $this->items = $user_query->get_results();
        
        $total_items = $user_query->get_total();
        $this->set_pagination_args([
            'total_items' => $total_items,
            'per_page'    => $per_page,
            'total_pages' => ceil( $total_items / $per_page )
        ]);
        // phpcs:enable WordPress.Security.NonceVerification.Recommended
    }

    public function get_columns() {		
        return [
		    'cb'       => '<input type="checkbox" />',
            'username' => __( 'Username', 'advanced-ip-blocker' ),
            'name'     => __( 'Name', 'advanced-ip-blocker' ),
            'email'    => __( 'Email', 'advanced-ip-blocker' ),
            'role'     => __( 'Role', 'advanced-ip-blocker' ),
            'status'   => __( '2FA Status', 'advanced-ip-blocker' ),
            'actions'  => __( 'Actions', 'advanced-ip-blocker' ),
        ];
    }
    
	protected function column_cb( $item ) {
        return sprintf(
            '<input type="checkbox" name="users[]" value="%s" />', $item->ID
        );
    }
	
	protected function get_bulk_actions() {
        return [
            'advaipbl_reset_2fa_bulk' => __( 'Reset 2FA', 'advanced-ip-blocker' )
        ];
    }
	
	    /**
     * Procesa las acciones en lote.
     */
         public function process_bulk_action() {
        $action = $this->current_action();
        
        if ( 'advaipbl_reset_2fa_bulk' === $action ) {
            // Verificamos el nonce del formulario POST.
            check_admin_referer( 'advaipbl_2fa_bulk_action_nonce', 'advaipbl_2fa_nonce_field' );

            $user_ids = isset( $_POST['users'] ) ? array_map( 'absint', (array) $_POST['users'] ) : [];
            
            if ( empty( $user_ids ) ) {
                return;
            }

            $tfa_manager = ADVAIPBL_Main::get_instance()->tfa_manager;
            if ( $tfa_manager ) {
                foreach ( $user_ids as $user_id ) {
                    if ( current_user_can( 'edit_user', $user_id ) ) {
                        $tfa_manager->admin_reset_for_user( $user_id );
                    }
                }
            }
            // El cambio de estado en la tabla es la confirmación.
        }
    }
	
    public function get_sortable_columns() {
        return [
            'username' => ['user_login', false],
            'name'     => ['display_name', false],
            'email'    => ['user_email', false],
        ];
    }

    protected function column_default( $item, $column_name ) {
        switch ( $column_name ) {
            case 'name':
                return $item->display_name;
            case 'email':
                return $item->user_email;
            case 'role':
                return implode( ', ', array_map( 'translate_user_role', $item->roles ) );
            default:
                return '–';
        }
    }

    protected function column_username( $item ) {
        $avatar = get_avatar( $item->ID, 32 );
        $edit_link = esc_url( get_edit_user_link( $item->ID ) );
        return sprintf( '%1$s <strong><a class="row-title" href="%2$s">%3$s</a></strong>', $avatar, $edit_link, $item->user_login );
    }

        protected function column_status( $item ) {
        $main_instance = ADVAIPBL_Main::get_instance();
        $tfa_manager = $main_instance->tfa_manager;

        if ( ! $tfa_manager ) {
            return '–';
        }

        // El usuario tiene 2FA configurado y activo.
        if ( $tfa_manager->is_2fa_enabled_for_user( $item->ID ) ) {
            return '<span style="color: #228b22; font-weight: bold;">' . __( 'Active', 'advanced-ip-blocker' ) . '</span>';
        }

        // El usuario NO tiene 2FA. ¿Está obligado a tenerlo?
        $is_forced = $tfa_manager->is_2fa_forced_for_user( $item );
        $global_enabled = ! empty( $main_instance->options['enable_2fa'] ) && '1' === $main_instance->options['enable_2fa'];

        if ( $global_enabled && $is_forced ) {
            return '<span style="color: #f59e0b; font-weight: bold;">' . __( 'Inactive (Required)', 'advanced-ip-blocker' ) . '</span>';
        }

        // No tiene 2FA y no está obligado.
        return '<span style="color: #999;">' . __( 'Inactive', 'advanced-ip-blocker' ) . '</span>';
    }

     protected function column_actions( $item ) {
     $tfa_manager = ADVAIPBL_Main::get_instance()->tfa_manager;
     if ( $tfa_manager && $tfa_manager->is_2fa_enabled_for_user( $item->ID ) ) {
         // Creamos una URL de acción simple. El nonce se añade por separado.
         $reset_url = add_query_arg([
             // phpcs:ignore WordPress.Security.NonceVerification.Recommended
             'page' => isset($_REQUEST['page']) ? sanitize_text_field(wp_unslash($_REQUEST['page'])) : '',
             'tab' => 'settings',
             'sub-tab' => '2fa_management',
             'action' => 'advaipbl_reset_2fa', // Acción simple
             'user_id' => $item->ID,
         ]);
         // Añadimos el nonce de forma segura con la función de WordPress
         $nonce_url = wp_nonce_url( $reset_url, 'advaipbl_reset_2fa_' . $item->ID, 'advaipbl_2fa_nonce' );
         
         return sprintf( '<a href="%s" class="button button-secondary button-small">%s</a>', esc_url( $nonce_url ), __( 'Reset 2FA', 'advanced-ip-blocker' ) );
     }
     return '–';
 }
 
     /**
     * Muestra los controles de filtro encima de la tabla.
     */
    protected function get_views() {
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $current_status = isset($_REQUEST['tfa_status']) ? sanitize_text_field(wp_unslash($_REQUEST['tfa_status'])) : 'all';
        $total_users = count_users()['total_users'];
        
        // Contar usuarios con 2FA activo
        $active_users_count = count( get_users([
            'meta_key' => ADVAIPBL_2fa_Manager::META_ENABLED_AT,
            'meta_compare' => 'EXISTS',
            'fields' => 'ID',
        ]) );
        
        $inactive_users_count = $total_users - $active_users_count;

        $base_url = remove_query_arg('tfa_status');
        
        $views = [
            'all' => sprintf(
                '<a href="%s" class="%s">%s <span class="count">(%d)</span></a>',
                esc_url( $base_url ),
                $current_status === 'all' ? 'current' : '',
                __( 'All', 'advanced-ip-blocker' ),
                $total_users
            ),
            'active' => sprintf(
                '<a href="%s" class="%s">%s <span class="count">(%d)</span></a>',
                esc_url( add_query_arg( 'tfa_status', 'active', $base_url ) ),
                $current_status === 'active' ? 'current' : '',
                __( '2FA Active', 'advanced-ip-blocker' ),
                $active_users_count
            ),
            'inactive' => sprintf(
                '<a href="%s" class="%s">%s <span class="count">(%d)</span></a>',
                esc_url( add_query_arg( 'tfa_status', 'inactive', $base_url ) ),
                $current_status === 'inactive' ? 'current' : '',
                __( '2FA Inactive', 'advanced-ip-blocker' ),
                $inactive_users_count
            ),
        ];

        return $views;
    }

    /**
     * Muestra los controles extra, como el filtro por rol.
     * @param string $which 'top' or 'bottom'
     */
    protected function extra_tablenav( $which ) {
        if ( 'top' !== $which ) {
            return;
        }
        ?>
        <div class="alignleft actions">
            <?php
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            $current_role = isset($_REQUEST['role']) ? sanitize_text_field(wp_unslash($_REQUEST['role'])) : '';
            $roles = get_editable_roles();
            ?>
            <label for="filter-by-role" class="screen-reader-text"><?php esc_html_e( 'Filter by role', 'advanced-ip-blocker' ); ?></label>
            <select name="role" id="filter-by-role">
                <option value=""><?php esc_html_e( 'All Roles', 'advanced-ip-blocker' ); ?></option>
                <?php foreach ( $roles as $role_slug => $role_details ) : ?>
                    <option value="<?php echo esc_attr( $role_slug ); ?>" <?php selected( $current_role, $role_slug ); ?>>
                        <?php echo esc_html( translate_user_role( $role_details['name'] ) ); ?>
                    </option>
                <?php endforeach; ?>
            </select>
            <input type="submit" name="filter_action" id="post-query-submit" class="button" value="<?php esc_attr_e( 'Filter', 'advanced-ip-blocker' ); ?>">
        </div>
        <?php
    }
	
	    /**
     * Muestra el cuadro de búsqueda.
     * @param string $text El texto del botón.
     * @param string $input_id El ID del campo de búsqueda.
     */
    public function search_box( $text, $input_id ) {
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $search_query = isset( $_REQUEST['s'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['s'] ) ) : '';
        ?>
        <p class="search-box">
            <label class="screen-reader-text" for="<?php echo esc_attr( $input_id ); ?>"><?php echo esc_html( $text ); ?>:</label>
            <input type="search" id="<?php echo esc_attr( $input_id ); ?>" name="s" value="<?php echo esc_attr( $search_query ); ?>" />
            <?php submit_button( $text, 'button', false, false, ['id' => 'search-submit'] ); ?>
        </p>
        <?php
    }
 
}