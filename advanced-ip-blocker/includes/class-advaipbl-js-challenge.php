<?php

if ( ! defined( 'ABSPATH' ) ) exit;

class ADVAIPBL_JS_Challenge {

    /**
     * @var ADVAIPBL_Main
     */
    private $plugin;

    public function __construct( ADVAIPBL_Main $plugin_instance ) {
        $this->plugin = $plugin_instance;
    }

    /**
     * Verifica la respuesta de un desafío JS si se ha enviado.
     * Esta función se ejecuta antes que las reglas de bloqueo para procesar
     * la respuesta de un desafío y establecer la cookie de verificación.
     */
    public function verify_submission() {
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        if (!isset($_POST['_advaipbl_js_token'])) {
            return;
        }

        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $challenge_type = sanitize_key($_POST['_advaipbl_challenge_type'] ?? 'signature');
        $cookie_duration = 4 * HOUR_IN_SECONDS; // Default

        if ($challenge_type === 'geo_challenge') {
            $duration_hours = (int)($this->plugin->options['geo_challenge_cookie_duration'] ?? 24);
            $cookie_duration = ($duration_hours > 0) ? $duration_hours * HOUR_IN_SECONDS : 0;
        } elseif ($challenge_type === 'endpoint') {
            $cookie_duration = 1 * HOUR_IN_SECONDS;
        }

        $this->verify_challenge('advaipbl_js_verified', $cookie_duration);
    }

    /**
     * Verifica el token del desafío y establece la cookie si es correcto.
     * 
     * @param string $cookie_name Nombre de la cookie a establecer.
     * @param int $cookie_duration Duración de la cookie en segundos.
     */
    public function verify_challenge($cookie_name, $cookie_duration) {
        // Sanitize input
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $token = sanitize_text_field(wp_unslash($_POST['_advaipbl_js_token'] ?? ''));
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $response = (int) sanitize_text_field(wp_unslash($_POST['_advaipbl_js_response'] ?? 0));

        $ip = $this->plugin->get_client_ip();

        // Sanitizar el modo reportado
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $mode_reported = sanitize_key($_POST['_advaipbl_challenge_mode'] ?? 'managed');

        // Verification check
        $is_valid       = false;
        $correct_answer = null;

        // Decode HMAC Token (Stateless Verification)
        if (!empty($token)) {
            $decoded = base64_decode(strtr($token, '-_', '+/'));
            if ($decoded !== false && strpos($decoded, '::') !== false) {
                list($payload, $signature) = explode('::', $decoded, 2);
                
                $salt = function_exists('wp_salt') ? wp_salt('auth') : (defined('AUTH_SALT') ? AUTH_SALT : 'fallback_salt_advaipbl');
                $expected_signature = hash_hmac('sha256', $payload, $salt);
                
                if (hash_equals($expected_signature, $signature)) {
                    $parts = explode('|', $payload);
                    if (count($parts) === 2) {
                        $parsed_answer = (int) $parts[0];
                        $expiration    = (int) $parts[1];
                        
                        if (time() <= $expiration) {
                            $correct_answer = $parsed_answer;
                        }
                    }
                }
            }
        }

        if ($correct_answer !== null && $response === $correct_answer) {
            // Si el cliente reporta que es un challenge 'managed', verificamos el checkbox
            if ($mode_reported === 'managed') {
                // phpcs:ignore WordPress.Security.NonceVerification.Missing
                if (isset($_POST['human_check'])) {
                    $is_valid = true;
                }
            } else {
                // Automático
                $is_valid = true;
            }
        }

        if ($is_valid) {
            
            set_transient('advaipbl_grace_pass_' . md5($ip), true, 15);
            
            $expiration = ($cookie_duration > 0) ? time() + $cookie_duration : 0;
            $request_uri = esc_url_raw(wp_unslash($_SERVER['REQUEST_URI'] ?? ''));

            if (defined('ADVAIPBL_EDGE_MODE') && ADVAIPBL_EDGE_MODE) {
                // En Edge Mode, limpiamos el buffer y usamos una redirección de PHP nativa.
                if (ob_get_level()) {
                    ob_end_clean();
                }

                $cookie_options = [
                    'expires' => $expiration,
                    'path' => '/',
                    'domain' => defined('COOKIE_DOMAIN') && COOKIE_DOMAIN ? COOKIE_DOMAIN : '',
                    'secure' => is_ssl(),
                    'httponly' => true,
                    'samesite' => 'Lax'
                ];
                setcookie($cookie_name, '1', $cookie_options);
                
                wp_safe_redirect($request_uri, 303);
                exit;

            } else {
                // En modo normal de WordPress, usamos las funciones de WordPress.
                setcookie($cookie_name, '1', $expiration, '/', defined('COOKIE_DOMAIN') ? COOKIE_DOMAIN : '', is_ssl(), true);
                wp_safe_redirect($request_uri);
                exit;
            }
        }
    
        if ( ! defined( 'DONOTCACHEPAGE' ) ) {
            // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound
            define( 'DONOTCACHEPAGE', true );
        }
        header( 'Cache-Control: no-store, no-cache, must-revalidate, max-age=0' );
        
        $this->plugin->log_event('JS challenge verification failed.', 'warning', ['ip' => $ip, 'token' => $token, 'response' => $response]);
        
        wp_die(
            esc_html__('Verification failed. Please ensure JavaScript and cookies are enabled in your browser.', 'advanced-ip-blocker'),
            esc_html__('Access Denied', 'advanced-ip-blocker'),
            ['response' => 403]
        );
    }

    /**
     * Muestra la página del desafío JavaScript, optimizada para seguridad, UX y responsividad.
     *
     * @param string $challenge_type Un identificador para el desafío (ej. 'signature', 'geo_challenge').
     * @param string $challenge_mode El modo del desafío ('managed' o 'automatic').
     */
    public function serve_challenge($challenge_type, $challenge_mode = 'managed') {
            // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound
        if (!defined('DONOTCACHEPAGE')) define('DONOTCACHEPAGE', true);
        if (headers_sent()) { return; }
        
        // 1. Headers estándar HTTP/1.1 y HTTP/1.0
        header('Cache-Control: private, no-store, no-cache, must-revalidate, max-age=0, post-check=0, pre-check=0');
        header('Pragma: no-cache');
        header('Expires: Thu, 01 Jan 1970 00:00:01 GMT');
        
        // 2. Headers específicos para proveedores de Caché/CDN conocidos
        // Cubre: LiteSpeed, Cloudflare, Fastly, Varnish
        header('X-LiteSpeed-Cache-Control: no-cache'); 
        header('Cloudflare-CDN-Cache-Control: no-store');
        header('CDN-Cache-Control: no-store'); 
        header('Surrogate-Control: no-store'); 
        
        // Cubre: NGINX FastCGI Cache (FlyingPress, WP Rocket NGINX mode, etc.)
        header('X-Accel-Expires: 0');
        
        // Cubre: SG Optimizer y otros sistemas basados en headers
        header('X-Cache-Enabled: False');

        // Nota: La constante DONOTCACHEPAGE (definida arriba) maneja:
        // WP Rocket, W3 Total Cache, WP Super Cache, WP Fastest Cache, Cache Enabler.

        // 3. Seguridad Standard
        header('X-Frame-Options: DENY');
        header('X-Content-Type-Options: nosniff');
        header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';");
        
        $num1   = wp_rand(1, 9);
        $num2   = wp_rand(1, 9);
        $answer = $num1 + $num2;
        // Stateless verification token (HMAC) to bypass Cache and Database limitations
        $expiration = time() + 120;
        $payload    = $answer . '|' . $expiration;
        $salt       = function_exists('wp_salt') ? wp_salt('auth') : (defined('AUTH_SALT') ? AUTH_SALT : 'fallback_salt_advaipbl');
        $signature  = hash_hmac('sha256', $payload, $salt);
        $token_raw  = $payload . '::' . $signature;
        // URL-safe Base64
        $token      = strtr(base64_encode($token_raw), '+/', '-_');
        
        status_header(503);
        header('Content-Type: text/html; charset=utf-8');
        header('Retry-After: 10');

        $protocol   = is_ssl() ? 'https://' : 'http://';
        $host       = sanitize_text_field(wp_unslash($_SERVER['HTTP_HOST'] ?? ''));
        $uri        = esc_url_raw(wp_unslash($_SERVER['REQUEST_URI'] ?? '/'));
        $action_url = esc_url($protocol . $host . $uri);
        $site_host          = wp_parse_url(home_url(), PHP_URL_HOST);
        $site_msg           = esc_html__('needs to review the security of your connection before proceeding.', 'advanced-ip-blocker');        
        $site_title         = get_bloginfo('name', 'display');
        $page_title         = esc_html__('Verifying your connection...', 'advanced-ip-blocker');
        $main_heading       = esc_html__('Security Check Required', 'advanced-ip-blocker'); 
        
        $timer_text         = esc_html__('Time remaining: ', 'advanced-ip-blocker');
        $noscript_text      = esc_html__('Please enable JavaScript to continue.', 'advanced-ip-blocker');
        $button_text        = esc_html__('Verify and Continue', 'advanced-ip-blocker');
        $checkbox_label     = esc_html__('I am not a robot.', 'advanced-ip-blocker');
        $expired_heading    = esc_html__('Session Expired', 'advanced-ip-blocker');
        $expired_message    = esc_html__('The security challenge has expired. Click the button below to get a new challenge.', 'advanced-ip-blocker');
        $reload_button_text = esc_html__('Start New Challenge', 'advanced-ip-blocker');
        
        if ($challenge_mode === 'automatic') {
            $main_text = esc_html__('Please wait while we verify your connection. This process is automatic and protects the website from automated attacks.', 'advanced-ip-blocker');
            $js_script = "<script>
                let isSubmitting = false;
                document.getElementById('js_response').value = {$num1} + {$num2};
                document.getElementById('challenge_form').addEventListener('submit', function(e) {
                    if (isSubmitting) { e.preventDefault(); return false; }
                    isSubmitting = true;
                });
                setTimeout(function(){ 
                    if (!isSubmitting) {
                        document.getElementById('challenge_form').submit();
                    }
                }, 2500);
            </script>";
            
            $form_content = '
                <div id="challenge_spinner"></div>
                <!-- Automatic Mode: No checkbox rendered -->
            ';
        } else {
            // Managed mode
            $main_text = esc_html__('To proceed, please prove you are human. This verification protects the website from automated attacks.', 'advanced-ip-blocker');
            $js_script = "<script>
                let isSubmitting = false;
                const TIMEOUT_SECONDS = 120;
                document.getElementById('js_response').value = {$num1} + {$num2};
                
                document.getElementById('challenge_form').addEventListener('submit', function(e) {
                    if (isSubmitting) { e.preventDefault(); return false; }
                    isSubmitting = true;
                    var btn = document.getElementById('submit_btn');
                    if (btn) btn.disabled = true;
                });
                
                let timeRemaining = TIMEOUT_SECONDS;
                function updateTimer() {
                    const timerElement = document.getElementById('challenge_timer');
                    if (timerElement) { timerElement.textContent = timeRemaining; }
                    if (timeRemaining <= 0) {
                        document.getElementById('challenge_interaction').style.display = 'none';
                        document.getElementById('challenge_expired').style.display = 'block';
                        document.getElementById('challenge_spinner').style.display = 'none';
                        return;
                    }
                    timeRemaining--;
                    setTimeout(updateTimer, 1000);
                }
                setTimeout(function(){ 
                    document.getElementById('challenge_spinner').style.display = 'none';
                    document.getElementById('challenge_interaction').style.display = 'flex';
                    updateTimer();
                }, 1500);
            </script>";
            
            $form_content = '
                <div id="challenge_spinner"></div>
                <div id="challenge_interaction" style="display:none;">
                    <label><input type="checkbox" name="human_check" required> ' . $checkbox_label . '</label>
                    <button type="submit" id="submit_btn">' . $button_text . '</button>
                    <div id="challenge_timer_container">' . $timer_text . '<span id="challenge_timer">120</span>s</div>
                </div>
            ';
        }

        $html = '<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
<meta http-equiv="Pragma" content="no-cache">
<meta http-equiv="Expires" content="0">
<title>' . $page_title . ' - ' . esc_attr($site_title) . '</title>
<style>
body{font-family:sans-serif;margin:0;padding:20px;background:#f1f1f1;color:#444;display:flex;justify-content:center;align-items:center;min-height:100vh;text-align:center;}
div.challenge-box{background:white;padding:40px;border-radius:8px;box-shadow:0 4px 15px rgba(0,0,0,0.1);max-width:500px;width:90%;}
h1{margin-top:0;margin-bottom:15px;color:#2271b1;font-size:1.8em;}
p{margin:10px auto;max-width:400px;}
p.site-info{color:#555;font-size:1.1em;margin-bottom:25px;}
p.site-info strong{color:#333;}
p.branding{margin-top:30px;font-size:13px;color:#666;border-top:1px solid #eee;padding-top:20px;}
p.branding a{color:#0073aa;text-decoration:none;}
p.branding a:hover{text-decoration:underline;}
#challenge_spinner{border:4px solid #f3f3f3;border-top:4px solid #3498db;border-radius:50%;width:30px;height:30px;animation:spin 1s linear infinite;margin:20px auto;}
@keyframes spin{0%{transform:rotate(0deg)}100%{transform:rotate(360deg)}}
#challenge_interaction{display:flex;flex-direction:column;align-items:center;margin-top:20px;}
#challenge_interaction label{font-size:1.1em;cursor:pointer;display:flex;align-items:center;user-select:none;}
#challenge_interaction input[type="checkbox"]{width:20px;height:20px;margin-right:10px;cursor:pointer;transform:scale(1.1);}
#challenge_interaction button, #challenge_expired button{margin-top:20px;padding:12px 35px;background:#2271b1;color:white;border:none;border-radius:4px;cursor:pointer;font-size:1em;transition:background 0.2s ease;}
#challenge_interaction button:hover, #challenge_expired button:hover{background:#1e6093;}
#challenge_timer_container{margin-top:15px;font-size:0.9em;font-weight:bold;color:#b20f03;}
#challenge_expired{display:none;flex-direction:column;align-items:center;margin-top:20px;}
#challenge_expired h2{color:#b20f03;font-size:1.5em;margin-bottom:10px;}
@media (max-width: 600px) { div.challenge-box{padding:25px;} h1{font-size:1.5em;} }
</style>
</head>
<body>
    <div class="challenge-box">
        <h1>' . $main_heading . '</h1>
        <p class="site-info"><strong>' . esc_html($site_host) . '</strong> ' . $site_msg . '</p>
        <p>' . $main_text . '</p>
        
        <form id="challenge_form" method="POST" action="' . $action_url . '">
            <input type="hidden" name="_advaipbl_js_token" value="' . esc_attr($token) . '">
            <input type="hidden" name="_advaipbl_js_response" id="js_response">
            <input type="hidden" name="_advaipbl_challenge_type" value="' . esc_attr($challenge_type) . '">    
            <input type="hidden" name="_advaipbl_challenge_mode" value="' . esc_attr($challenge_mode) . '"> 
            
            ' . $form_content . '
        </form>

        <div id="challenge_expired">
            <h2>' . $expired_heading . '</h2>
            <p>' . $expired_message . '</p>
            <button onclick="window.location.reload(true);">' . $reload_button_text . '</button>
        </div>
        
        <noscript><p style="color:red;font-weight:bold;">' . $noscript_text . '</p></noscript>
        
        <p class="branding">Performance &amp; security by <a rel="noopener noreferrer" href="https://advaipbl.com/" target="_blank">Advanced IP Blocker</a></p>
    </div>' . $js_script . '</body>
</html>';
        // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
        echo $html; 
        exit;
    }
}