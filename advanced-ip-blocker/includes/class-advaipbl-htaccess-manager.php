<?php

if ( ! defined( 'ABSPATH' ) ) exit;

class ADVAIPBL_Htaccess_Manager {

    private $plugin;
    private $marker = 'Advanced IP Blocker';

    public function __construct( ADVAIPBL_Main $plugin_instance ) {
        $this->plugin = $plugin_instance;
    }

    /**
     * Obtiene la ruta completa al archivo .htaccess.
     *
     * @return string
     */
    public function get_htaccess_path() {
        if ( ! function_exists( 'get_home_path' ) ) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }
        return get_home_path() . '.htaccess';
    }

    /**
     * Verifica si el archivo .htaccess existe y es escribible.
     * Utiliza wp_is_writable() para cumplir con los estándares de WP.
     *
     * @return bool
     */
    public function is_writable() {
        $path = $this->get_htaccess_path();
        return ( file_exists( $path ) && wp_is_writable( $path ) ) || ( ! file_exists( $path ) && wp_is_writable( dirname( $path ) ) );
    }

    /**
     * Crea una copia de seguridad del archivo .htaccess actual en una carpeta segura.
     * Mantiene solo los últimos 30 backups.
     *
     * @return bool|string Ruta del backup si tiene éxito, false si falla.
     */
    public function create_backup() {
        $htaccess_path = $this->get_htaccess_path();
        if ( ! file_exists( $htaccess_path ) ) {
            return false;
        }

        $upload_dir = wp_upload_dir();
        $backup_dir = $upload_dir['basedir'] . '/advaipbl-backups';

        if ( ! file_exists( $backup_dir ) ) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_mkdir
            if ( ! wp_mkdir_p( $backup_dir ) ) {
                $this->plugin->log_event( 'Backup failed: Could not create directory ' . $backup_dir, 'error' );
                return false;
            }
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
            file_put_contents( $backup_dir . '/.htaccess', 'deny from all' );
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
            file_put_contents( $backup_dir . '/index.php', '<?php // Silence is golden' );
        }

        if ( ! wp_is_writable( $backup_dir ) ) {
            $this->plugin->log_event( 'Backup failed: Directory ' . $backup_dir . ' is not writable.', 'error' );
            return false;
        }

        // Usamos gmdate() para evitar problemas de zona horaria (Standard WP).
        $backup_filename = 'htaccess_backup_' . gmdate( 'Y-m-d_H-i-s' ) . '.txt';
        $backup_path = $backup_dir . '/' . $backup_filename;

        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_copy
        if ( copy( $htaccess_path, $backup_path ) ) {
            $files = glob( $backup_dir . '/htaccess_backup_*.txt' );
            // AUMENTADO: Mantenemos las últimas 30 copias en lugar de 5.
            if ( $files && count( $files ) > 30 ) {
                array_multisort( array_map( 'filemtime', $files ), SORT_NUMERIC, SORT_ASC, $files );
                $to_delete = array_slice( $files, 0, count( $files ) - 30 );
                foreach ( $to_delete as $file ) {
                    // Usamos wp_delete_file() en lugar de unlink() (Standard WP).
                    wp_delete_file( $file );
                }
            }
            return $backup_path;
        } else {
            $this->plugin->log_event( 'Backup failed: Could not copy .htaccess to ' . $backup_path, 'error' );
        }

        return false;
    }

    /**
     * Obtiene las IPs para bloquear.
     * Excluye rangos con guión (-) ya que Apache no los soporta nativamente en Require ip.
     */
    private function get_ips_to_block() {
        global $wpdb;
        $table_name = $wpdb->prefix . 'advaipbl_blocked_ips';
        
        // Opciones
        $include_all = !empty($this->plugin->options['enable_htaccess_all_ips']);
        
        // Construcción de la Query
        $sql = "SELECT ip_range FROM {$table_name} WHERE ip_range NOT LIKE '%-%'";
        
        // Si NO está marcado "Include Temporary", filtramos solo manuales, importaciones masivas o permanentes
        if ( ! $include_all ) {
            $sql .= " AND (block_type IN ('manual', 'bulk_import') OR expires_at = 0)";
        }
        
        // Siempre aplicamos un límite de seguridad para proteger Apache
        // Si incluimos temporales, subimos un poco el límite a 2000 para ser más agresivos,
        // pero manteniendo la seguridad de que el archivo no pese 10MB.
        $limit = $include_all ? 2000 : 1000;
        
        $sql .= " ORDER BY id DESC LIMIT %d";
        
        // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $results = $wpdb->get_col( $wpdb->prepare( $sql, $limit ) );
        
        return $results ? $results : [];
    }

    public function generate_rules_content() {
        $rules = [];
        $options = $this->plugin->options;

        // 1. Hardening Rules
        $hardening_active = false;
        if ( ! empty( $options['htaccess_protect_system_files'] ) ) {
            $rules[] = 'RedirectMatch 403 (?i)\.(7z|bak|bz2|com|conf|dist|fla|git|env|inc|ini|log|old|psd|rar|tar|tgz|save|sh|sql|svn|swo|swp)$';
            $rules[] = 'RedirectMatch 403 (?i)/\.ds_store$';
            $hardening_active = true;
        }
        if ( ! empty( $options['htaccess_protect_wp_config'] ) ) {
            $rules[] = 'RedirectMatch 403 (?i)/wp-config\.php$';
            $rules[] = 'RedirectMatch 403 (?i)/wp-config-sample\.php$';
            $hardening_active = true;
        }
        if ( ! empty( $options['htaccess_protect_readme'] ) ) {
            $rules[] = 'RedirectMatch 403 (?i)/readme\.(html|txt)$';
            $hardening_active = true;
        }

        if ( $hardening_active ) {
            array_unshift( $rules, '<IfModule mod_alias.c>' );
            $rules[] = '</IfModule>';
            $rules[] = ''; 
        }

        // 2. IP Blocking Rules
        $ips_to_block = [];
        if ( ! empty( $options['enable_htaccess_ip_blocking'] ) ) {
            $ips_to_block = $this->get_ips_to_block();
        }

        if ( ! empty( $ips_to_block ) ) {
            
            $rules[] = '# IP Blocking Rules';
            
            // Generar reglas SetEnvIF SOLO para IPs únicas (sin CIDR)
            foreach ( $ips_to_block as $ip ) {
                if ( strpos( $ip, '/' ) === false ) {
                    $ip_regex = str_replace( '.', '\.', $ip );
                    $ip_regex = '^' . $ip_regex . '$';
                    
                    $rules[] = 'SetEnvIF REMOTE_ADDR "' . $ip_regex . '" DenyAccess';
                    $rules[] = 'SetEnvIF X-FORWARDED-FOR "' . $ip_regex . '" DenyAccess';
                    $rules[] = 'SetEnvIF X-CLUSTER-CLIENT-IP "' . $ip_regex . '" DenyAccess';
                }
            }
            
            $rules[] = '';

            // Apache 2.4
            $rules[] = '<IfModule mod_authz_core.c>';
            $rules[] = '    <RequireAll>';
            $rules[] = '        Require all granted';
            $rules[] = '        Require not env DenyAccess';
            foreach ( $ips_to_block as $ip ) {
                $rules[] = '        Require not ip ' . $ip;
            }
            $rules[] = '    </RequireAll>';
            $rules[] = '</IfModule>';

            // Apache 2.2
            $rules[] = '<IfModule !mod_authz_core.c>';
            $rules[] = '    Order allow,deny';
            $rules[] = '    Allow from all';
            $rules[] = '    Deny from env=DenyAccess';
            foreach ( $ips_to_block as $ip ) {
                $rules[] = '    Deny from ' . $ip;
            }
            $rules[] = '</IfModule>';
        } elseif ( empty($rules) ) {
             return "# No active rules selected in Advanced IP Blocker settings.";
        }

        return implode( "\n", $rules );
    }

    public function update_htaccess() {
        if ( ! $this->is_writable() ) {
            return new WP_Error( 'file_not_writable', 'The .htaccess file is not writable.' );
        }

        $this->create_backup();

        $rules_string = $this->generate_rules_content();
        $rules_array = explode( "\n", $rules_string );

        if ( ! function_exists( 'insert_with_markers' ) ) {
            require_once ABSPATH . 'wp-admin/includes/misc.php';
        }

        $result = insert_with_markers( $this->get_htaccess_path(), $this->marker, $rules_array );

        if ( ! $result ) {
            return new WP_Error( 'write_failed', 'Failed to write to .htaccess file.' );
        }

        // FIM & Firewall Sync: Update baseline to prevent false positive alert
        if ( isset( $this->plugin->file_verifier ) && ! empty( $this->plugin->options['enable_fim'] ) ) {
            $this->plugin->file_verifier->update_file_hash( $this->get_htaccess_path() );
        }

        return true;
    }

    public function remove_rules() {
        if ( ! function_exists( 'insert_with_markers' ) ) {
            require_once ABSPATH . 'wp-admin/includes/misc.php';
        }
        return insert_with_markers( $this->get_htaccess_path(), $this->marker, [] );
    }
}