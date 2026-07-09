<?php
/**
 * Captcha Manager for Advanced IP Blocker
 * Handles integration with Cloudflare Turnstile and hCaptcha.
 */

if (!defined('ABSPATH')) {
    exit;
}

class ADVAIPBL_Captcha_Manager {

    /**
     * @var ADVAIPBL_Main
     */
    private $plugin;

    public function __construct(ADVAIPBL_Main $plugin_instance) {
        $this->plugin = $plugin_instance;
    }

    /**
     * Verifica la respuesta de un Captcha si se ha enviado.
     */
    public function verify_submission() {
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        if (!isset($_POST['cf-turnstile-response']) && !isset($_POST['h-captcha-response'])) {
            return;
        }

        if ( !empty($this->plugin->request_is_asn_whitelisted) || $this->plugin->is_whitelisted($this->plugin->get_client_ip()) || !empty($this->plugin->is_advanced_rule_allowed) ) {
            return;
        }

        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $challenge_type = sanitize_key($_POST['_advaipbl_challenge_type'] ?? 'signature');
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $engine = isset($_POST['cf-turnstile-response']) ? 'turnstile' : 'hcaptcha';
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $token = sanitize_text_field(wp_unslash($_POST['cf-turnstile-response'] ?? $_POST['h-captcha-response']));
        $ip = $this->plugin->get_client_ip();

        $is_valid = false;
        
        if ($engine === 'turnstile') {
            $secret_key = $this->plugin->options['turnstile_secret_key'] ?? '';
            $response = wp_remote_post('https://challenges.cloudflare.com/turnstile/v0/siteverify', [
                'body' => [
                    'secret'   => $secret_key,
                    'response' => $token,
                    'remoteip' => $ip,
                ],
            ]);
            if (!is_wp_error($response)) {
                $body = json_decode(wp_remote_retrieve_body($response), true);
                if (!empty($body['success'])) {
                    $is_valid = true;
                }
            }
        } elseif ($engine === 'hcaptcha') {
            $secret_key = $this->plugin->options['hcaptcha_secret_key'] ?? '';
            $response = wp_remote_post('https://api.hcaptcha.com/siteverify', [
                'body' => [
                    'secret'   => $secret_key,
                    'response' => $token,
                    'remoteip' => $ip,
                ],
            ]);
            if (!is_wp_error($response)) {
                $body = json_decode(wp_remote_retrieve_body($response), true);
                if (!empty($body['success'])) {
                    $is_valid = true;
                }
            }
        }

        $global_duration_hours = (int)($this->plugin->options['global_challenge_cookie_duration'] ?? 4);
        $cookie_duration = ($global_duration_hours > 0) ? $global_duration_hours * HOUR_IN_SECONDS : 0;

        if ($challenge_type === 'geo_challenge') {
            $duration_hours = (int)($this->plugin->options['geo_challenge_cookie_duration'] ?? 24);
            $cookie_duration = ($duration_hours > 0) ? $duration_hours * HOUR_IN_SECONDS : 0;
        }

        if ($is_valid) {
            // Set grace pass transient to avoid instant loops due to caching
            set_transient('advaipbl_grace_pass_' . md5($ip), true, 15);
            // Set cookie and reload
            $this->plugin->js_challenge_manager->set_vip_pass_cookie($cookie_duration, $ip);
            
            // phpcs:ignore WordPress.Security.NonceVerification.Missing
            $redirect_to = !empty($_POST['_advaipbl_redirect_to']) ? esc_url_raw(wp_unslash($_POST['_advaipbl_redirect_to'])) : '';
            if (empty($redirect_to)) {
                $protocol   = is_ssl() ? 'https://' : 'http://';
                $host       = sanitize_text_field(wp_unslash($_SERVER['HTTP_HOST'] ?? ''));
                $uri        = esc_url_raw(wp_unslash($_SERVER['REQUEST_URI'] ?? '/'));
                $redirect_to = $protocol . $host . $uri;
            }

            wp_safe_redirect($redirect_to);
            exit;
        } else {
            $this->plugin->log_event("{$engine} verification failed.", 'warning', ['ip' => $ip, 'token' => substr($token, 0, 10) . '...']);
            wp_die(
                esc_html__('Verification failed. Please try again.', 'advanced-ip-blocker'),
                esc_html__('Verification Failed', 'advanced-ip-blocker'),
                ['response' => 403]
            );
        }
    }

    /**
     * Sirve el desafío Captcha (Turnstile o hCaptcha).
     */
    public function serve_challenge($challenge_type, $engine, $challenge_mode = 'managed') {
        if (!defined('DONOTCACHEPAGE')) define('DONOTCACHEPAGE', true);
        if (headers_sent()) { return; }
        
        header('Cache-Control: private, no-store, no-cache, must-revalidate, max-age=0, post-check=0, pre-check=0');
        header('Pragma: no-cache');
        header('Expires: Thu, 01 Jan 1970 00:00:01 GMT');
        header('X-LiteSpeed-Cache-Control: no-cache'); 
        header('Cloudflare-CDN-Cache-Control: no-store');
        header('CDN-Cache-Control: no-store'); 
        header('Surrogate-Control: no-store'); 
        header('X-Accel-Expires: 0');
        header('X-Cache-Enabled: False');

        header('X-Frame-Options: DENY');
        header('X-Content-Type-Options: nosniff');
        
        // El CSP debe permitir los scripts de turnstile/hcaptcha
        if ($engine === 'turnstile') {
            header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; style-src 'self' 'unsafe-inline';");
        } else {
            header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://hcaptcha.com https://*.hcaptcha.com; frame-src https://hcaptcha.com https://*.hcaptcha.com; style-src 'self' 'unsafe-inline' https://hcaptcha.com https://*.hcaptcha.com; connect-src 'self' https://hcaptcha.com https://*.hcaptcha.com;");
        }
        
        status_header(503);
        header('Content-Type: text/html; charset=utf-8');
        header('Retry-After: 10');

        $protocol   = is_ssl() ? 'https://' : 'http://';
        $host       = sanitize_text_field(wp_unslash($_SERVER['HTTP_HOST'] ?? ''));
        $uri        = esc_url_raw(wp_unslash($_SERVER['REQUEST_URI'] ?? '/'));
        $action_url = esc_url($protocol . $host . $uri);
        
        $site_title         = get_bloginfo('name', 'display');
        $site_host          = wp_parse_url(home_url(), PHP_URL_HOST);
        $page_title         = esc_html__('Verifying your connection...', 'advanced-ip-blocker');
        $main_heading       = esc_html__('Security Check Required', 'advanced-ip-blocker'); 
        $site_msg           = esc_html__('needs to review the security of your connection before proceeding.', 'advanced-ip-blocker');        
        
        $site_key = '';
        if ($engine === 'turnstile') {
            $site_key = $this->plugin->options['turnstile_site_key'] ?? '';
        } elseif ($engine === 'hcaptcha') {
            $site_key = $this->plugin->options['hcaptcha_site_key'] ?? '';
        }

        ?>
        <!DOCTYPE html>
        <html lang="<?php echo esc_attr(get_locale()); ?>">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title><?php echo esc_html($page_title); ?></title>
            <meta name="robots" content="noindex, nofollow">
            <style>
                body {
                    margin: 0; padding: 0; background-color: #f7f9fa; color: #1a1a1a;
                    font-family: system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
                    display: flex; align-items: center; justify-content: center; min-height: 100vh;
                }
                .container {
                    background: #fff; padding: 40px; border-radius: 12px; box-shadow: 0 10px 30px rgba(0,0,0,0.08);
                    max-width: 500px; width: 90%; text-align: center; border: 1px solid #e1e4e8;
                }
                h1 { margin-top: 0; font-size: 24px; color: #2c3e50; margin-bottom: 15px; }
                p { font-size: 15px; color: #5c6b7a; line-height: 1.6; margin-bottom: 25px; }
                .site-name { font-weight: 600; color: #2c3e50; }
                .footer-brand { margin-top: 30px; font-size: 12px; color: #95a5a6; display: flex; align-items: center; justify-content: center; }
                .footer-brand svg { width: 16px; height: 16px; margin-right: 6px; fill: currentColor; }
                .challenge-box { margin: 20px auto; min-height: 70px; display: flex; justify-content: center; align-items: center; }
            </style>
            <?php if ($engine === 'turnstile'): ?>
                <?php // phpcs:ignore WordPress.WP.EnqueuedResources.NonEnqueuedScript, PluginCheck.CodeAnalysis.Offloading.OffloadedContent ?>
                <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
            <?php elseif ($engine === 'hcaptcha'): ?>
                <?php // phpcs:ignore WordPress.WP.EnqueuedResources.NonEnqueuedScript, PluginCheck.CodeAnalysis.Offloading.OffloadedContent ?>
                <script src="https://hcaptcha.com/1/api.js" async defer></script>
            <?php endif; ?>
        </head>
        <body>
            <div class="container">
                <h1><?php echo esc_html($main_heading); ?></h1>
                <p>
                    <span class="site-name"><?php echo esc_html($site_host); ?></span> 
                    <?php echo esc_html($site_msg); ?>
                </p>

                <div class="challenge-box">
                    <form method="POST" action="<?php echo esc_url($action_url); ?>" id="advaipbl-challenge-form">
                        <input type="hidden" name="_advaipbl_challenge_type" value="<?php echo esc_attr($challenge_type); ?>">
                        <input type="hidden" name="_advaipbl_redirect_to" value="<?php echo esc_attr($action_url); ?>">
                        
                        <?php if ($engine === 'turnstile'): ?>
                            <div class="cf-turnstile" data-sitekey="<?php echo esc_attr($site_key); ?>" <?php if ($challenge_mode === 'automatic') echo 'data-action="login"'; ?>></div>
                        <?php elseif ($engine === 'hcaptcha'): ?>
                            <div class="h-captcha" data-sitekey="<?php echo esc_attr($site_key); ?>"></div>
                        <?php endif; ?>
                        
                        <noscript>
                            <button type="submit" style="margin-top: 15px; padding: 10px 20px; background: #2c3e50; color: #fff; border: none; border-radius: 5px; cursor: pointer;">
                                <?php esc_html_e('Submit', 'advanced-ip-blocker'); ?>
                            </button>
                        </noscript>
                    </form>
                </div>

                <div class="footer-brand">
                    <svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z"/></svg>
                    Protected by Advanced IP Blocker
                </div>
            </div>
            
            <script>
            // Auto submit if the captcha supports it natively or via callback.
            // Turnstile can auto submit by adding a callback.
            <?php if ($engine === 'turnstile'): ?>
                function turnstileCallback(token) {
                    document.getElementById('advaipbl-challenge-form').submit();
                }
                // We'll dynamically set the callback if we want auto-submit
                document.querySelector('.cf-turnstile').setAttribute('data-callback', 'turnstileCallback');
            <?php elseif ($engine === 'hcaptcha'): ?>
                function hcaptchaCallback(token) {
                    document.getElementById('advaipbl-challenge-form').submit();
                }
                document.querySelector('.h-captcha').setAttribute('data-callback', 'hcaptchaCallback');
            <?php endif; ?>
            </script>
        </body>
        </html>
        <?php
    }
}
