<?php

if ( ! defined( 'ABSPATH' ) ) exit;

use RobThree\Auth\TwoFactorAuth;
use RobThree\Auth\Providers\Qr\GoogleChartsQrCodeProvider;
use RobThree\Auth\Providers\Rng\CSRNGProvider;
use RobThree\Auth\Algorithm;

class ADVAIPBL_2fa_Manager {

    const META_SECRET           = '_advaipbl_2fa_secret';
    const META_ENABLED_AT       = '_advaipbl_2fa_enabled_at';
    const META_BACKUP_CODES     = '_advaipbl_2fa_backup_codes';
    const META_TEMP_SECRET      = '_advaipbl_2fa_temp_secret';

    private $main_class;
    private $tfa;

    public function __construct( ADVAIPBL_Main $main_class ) {
        $this->main_class = $main_class;        
        $renderer = new \BaconQrCode\Renderer\ImageRenderer(
            new \BaconQrCode\Renderer\RendererStyle\RendererStyle(300),
            new \BaconQrCode\Renderer\Image\SvgImageBackEnd()
        );
        $writer = new \BaconQrCode\Writer($renderer);       
        $qrProvider = new \RobThree\Auth\Providers\Qr\BaconQrCodeProvider($writer);
        
        $rngProvider = new \RobThree\Auth\Providers\Rng\CSRNGProvider();
        $issuer = get_bloginfo( 'name' );

        $this->tfa = new \RobThree\Auth\TwoFactorAuth(
            $qrProvider,
            $issuer,
            6,
            30,
            \RobThree\Auth\Algorithm::Sha1,
            $rngProvider,
            null
        );
    }

        public function generate_new_secret_for_user( WP_User $user ): array {
        $secret = $this->tfa->createSecret();
        update_user_meta( $user->ID, self::META_TEMP_SECRET, $secret );
        $label = $user->user_login;
        $qr_url = $this->tfa->getQRCodeImageAsDataUri( $label, $secret );
        $backup_codes = $this->generate_backup_codes();
        return [ 'secret' => $secret, 'qr_url' => $qr_url, 'backup_codes' => $backup_codes ];
    }

    public function is_2fa_enabled_for_user( int $user_id ): bool { return (bool) get_user_meta( $user_id, self::META_ENABLED_AT, true ); }
    public function verify_and_activate( int $user_id, string $code, array $backup_codes ): bool {
        $temp_secret = get_user_meta( $user_id, self::META_TEMP_SECRET, true );

        if ( empty( $temp_secret ) ) {
            return false;
        }

        if ( $this->tfa->verifyCode( $temp_secret, $code, 1 ) ) {
            update_user_meta( $user_id, self::META_SECRET, $temp_secret );
            update_user_meta( $user_id, self::META_ENABLED_AT, time() );
            update_user_meta( $user_id, self::META_BACKUP_CODES, $this->hash_backup_codes( $backup_codes ) );
            delete_user_meta( $user_id, self::META_TEMP_SECRET );
            $user = get_user_by('id', $user_id);
            if ($user) {
                $this->main_class->notification_manager->send_2fa_notification_email('activated', $user);
            }

            $this->main_class->log_event( sprintf( '2FA enabled for user ID #%d.', $user_id ), 'info' );
            return true;
        }

        return false;
    }
    public function verify_code( int $user_id, string $code ): bool { if ( $this->is_valid_backup_code( $user_id, $code ) ) { return true; } $secret = get_user_meta( $user_id, self::META_SECRET, true ); if ( empty( $secret ) ) { return false; } return $this->tfa->verifyCode( $secret, $code, 1 ); }
    public function deactivate_for_user( int $user_id ) {

        delete_user_meta( $user_id, self::META_SECRET );
        delete_user_meta( $user_id, self::META_ENABLED_AT );
        delete_user_meta( $user_id, self::META_BACKUP_CODES );
        delete_user_meta( $user_id, self::META_TEMP_SECRET );
                
        $user = get_user_by('id', $user_id);
        if ($user) {
            $this->main_class->notification_manager->send_2fa_notification_email('deactivated', $user);
        }       
        
        $this->main_class->log_event( sprintf( '2FA disabled for user ID #%d.', $user_id ), 'info' );
    }
    public function admin_reset_for_user( int $user_id ) {
        delete_user_meta( $user_id, self::META_SECRET );
        delete_user_meta( $user_id, self::META_ENABLED_AT );
        delete_user_meta( $user_id, self::META_BACKUP_CODES );
        delete_user_meta( $user_id, self::META_TEMP_SECRET );
               
        $user = get_user_by('id', $user_id);
        if ($user) {
            $this->main_class->notification_manager->send_2fa_notification_email('reset', $user);
        }

        $admin_username = $this->main_class->get_current_admin_username();
        $this->main_class->log_event( sprintf( '2FA was reset for user ID #%1$d by admin %2$s.', $user_id, $admin_username ), 'warning' );
    }
    public function is_2fa_forced_for_user( WP_User $user ): bool { $forced_roles = $this->main_class->options['tfa_force_roles'] ?? []; if ( empty( $forced_roles ) ) { return false; } return ! empty( array_intersect( (array) $user->roles, $forced_roles ) ); }
    public function generate_backup_codes( int $count = 8, int $length = 10 ): array { $codes = []; for ( $i = 0; $i < $count; $i++ ) { $code = wp_generate_password( $length, false ); if ($length > 5) { $code = substr($code, 0, $length/2) . '-' . substr($code, $length/2); } $codes[] = $code; } return $codes; }
    public function hash_backup_codes( array $codes ): array { $hashed_codes = []; foreach ( $codes as $code ) { $hashed_codes[] = wp_hash_password( $code ); } return $hashed_codes; }
    public function is_valid_backup_code( int $user_id, string $code ): bool {
        $hashed_codes = get_user_meta( $user_id, self::META_BACKUP_CODES, true );
        if ( ! is_array( $hashed_codes ) || empty( $hashed_codes ) ) {
            return false;
        }
        foreach ( $hashed_codes as $key => $hash ) {
            if ( wp_check_password( $code, $hash ) ) {
                unset( $hashed_codes[ $key ] );
                update_user_meta( $user_id, self::META_BACKUP_CODES, $hashed_codes );
                
                $user = get_user_by('id', $user_id);
                if ($user) {
                    $this->main_class->send_2fa_notification_email(
                        'backup_used', 
                        $user,
                        ['remaining_codes' => count($hashed_codes)]
                    );
                }

                $this->main_class->log_event( sprintf( 'Backup code used by user ID #%d.', $user_id ), 'info' );
                return true;
            }
        }
        return false;
    }
}