<?php

if ( ! defined( 'ABSPATH' ) ) exit;

class ADVAIPBL_Bot_Verifier {

    private $plugin;
    private static $verified_cache = []; // Caché estático por petición

    public function __construct(ADVAIPBL_Main $plugin_instance) {
        $this->plugin = $plugin_instance;
    }

    /**
     * Función principal que comprueba si una IP es un bot conocido y verificado.
     */
    public function is_verified_bot($ip, $user_agent) {
        if (empty($ip) || empty($user_agent)) {
            return false;
        }

        // Usar caché estático para evitar múltiples consultas de DNS en la misma petición.
        if (isset(self::$verified_cache[$ip])) {
            return self::$verified_cache[$ip];
        }

        $known_bots = [
            // --- Motores de Búsqueda Principales (Alta Confianza) ---
            'googlebot'         => ['.googlebot.com', '.google.com'],
            'google.com/bot'    => '.google.com',
            'adsbot-google'     => ['.googlebot.com', '.google.com'],
            'bingbot'           => '.search.msn.com',
            'adidxbot'          => '.search.msn.com',
            // Yandex usa .ru, .com y .net
            'yandexbot'         => ['.yandex.com', '.yandex.ru', '.yandex.net'],
            'duckduckbot'       => '.duckduckgo.com',
            // Applebot: Aceptamos infraestructura oficial y iCloud
            'applebot'          => ['.applebot.apple.com', '.apple.com', '.icloud.com'],
            'baiduspider'       => ['.baidu.com', '.baidu.jp'],
            
            // --- Bots de Redes Sociales ---
            // Facebook usa tfbnw.net para infraestructura
            'facebookexternalhit' => ['.facebook.com', '.tfbnw.net'],
            'facebot'             => ['.facebook.com', '.tfbnw.net'],
            'twitterbot'          => '.twitter.com',
            'linkedinbot'         => '.linkedin.com',
            'pinterestbot'        => '.pinterest.com',

            // --- IA Generativa y Comerciales Modernos ---
            'chatgpt-user'        => '.outbound-customer.openai.com',
            'oai/openai'          => '.outbound-customer.openai.com',
            'gptbot'              => '.outbound-customer.openai.com',
            'searchbot'           => '.outbound-customer.openai.com',
            'amazonbot'           => ['.amazonbot.amazon.com', '.crawl.amazonbot.amazon.com'],

            // --- Otros Bots de Confianza ---
            'yahoo! slurp'        => '.yahoo.com',
            'yahoofaqbot'         => '.yahoo.com',
            'petalbot'            => ['.aspiegel.com', '.petalsearch.com'],

            // --- Servicios de Monitoreo (Verificados por IP) ---
            'uptimerobot'         => [], // Uptime Robot (Sin rDNS)
            'pingdom'             => [], // Pingdom (Sin rDNS)
        ];

        $is_known_bot = false;
        $expected_domains = '';

        foreach ($known_bots as $ua_keyword => $domains) {
            if (stripos($user_agent, $ua_keyword) !== false) {
                $is_known_bot = true;
                $expected_domains = $domains;
                break;
            }
        }

        // Si el User-Agent no coincide con ningún bot conocido, no hay nada que verificar.
        if (!$is_known_bot) {
            return false;
        }

        $is_ai_bot = false;
        $is_google_bot = false;
        $is_monitoring_bot = false;
        
        if (in_array($ua_keyword, ['chatgpt-user', 'oai/openai', 'gptbot', 'searchbot', 'applebot'])) {
            $is_ai_bot = true;
        } elseif (in_array($ua_keyword, ['googlebot', 'google.com/bot', 'adsbot-google'])) {
            $is_google_bot = true;
        } elseif (in_array($ua_keyword, ['uptimerobot', 'pingdom'])) {
            $is_monitoring_bot = true;
        }

        // Si es un bot de IA y la opción está activa, o si es de Google, verificamos por CIDR en lugar de DNS
        // (Activado por defecto si no está definido para usuarios existentes)
        $ai_bot_enabled = isset($this->plugin->options['enable_ai_bot_verification']) ? $this->plugin->options['enable_ai_bot_verification'] : '1';
        $monitoring_bot_enabled = isset($this->plugin->options['enable_monitoring_bot_verification']) ? $this->plugin->options['enable_monitoring_bot_verification'] : '1';
        
        if (($is_ai_bot && $ai_bot_enabled === '1') || $is_google_bot || ($is_monitoring_bot && $monitoring_bot_enabled === '1')) {
            if (!get_transient('advaipbl_bot_ips_cached')) {
                $this->fetch_and_cache_bot_lists();
            }
            $is_verified = $this->verify_bot_ip($ip, $ua_keyword);
            
            // Fallback a DNS si la lista CIDR está vacía por algún error de API, o no está en la lista JSON (raro)
            if (!$is_verified && !$is_monitoring_bot) {
                $is_verified = $this->verify_dns($ip, $expected_domains);
            }
        } else {
            // Ahora realizamos la verificación de DNS clásica (omitido para bots de monitoreo que no tienen rDNS)
            if ($is_monitoring_bot) {
                $is_verified = false;
            } else {
                $is_verified = $this->verify_dns($ip, $expected_domains);
            }
        }

        self::$verified_cache[$ip] = $is_verified;

        return $is_verified;
    }

    /**
     * Realiza una verificación de DNS inversa (rDNS) y directa (forward DNS).
     */
    private function verify_dns($ip, $expected_domains) {
        $hostname = gethostbyaddr($ip);
        if ($hostname === $ip || $hostname === false) {
            return false;
        }
        
        // Normalización
        $hostname = rtrim($hostname, '.');

        if (!is_array($expected_domains)) {
            $expected_domains = [$expected_domains];
        }

        $domain_match = false;
        foreach ($expected_domains as $domain) {
            if (substr($hostname, -strlen($domain)) === $domain) {
                $domain_match = true;
                break;
            }
        }

        if (!$domain_match) {
            return false;
        }
        
        // Paso 3: Obtener la IP del hostname (Forward DNS - A Record).
        // Obligatorio para asegurar que el PTR no ha sido falsificado por un atacante en su servidor (DNS Spoofing).
        $resolved_ips = gethostbynamel($hostname);
        
        if ($resolved_ips === false || empty($resolved_ips)) {
            return false;
        }

        return in_array($ip, $resolved_ips, true);
    }
	
	/**
     * Comprueba si un User-Agent coincide con un bot conocido, para identificar impostores.
     */
    public function is_known_bot_impersonator($ip, $user_agent) {
        // Lista sincronizada para evitar falsos positivos en móviles (Sin redes sociales)
        $known_bots = [
            'googlebot'     => '.googlebot.com',
            'google.com/bot'=> '.google.com',
            'adsbot-google' => '.google.com',
            'bingbot'       => '.search.msn.com',
            'yandexbot'     => '.yandex.com',
            'duckduckbot'   => '.duckduckgo.com',
            'Applebot'      => '.applebot.apple.com',
            'baiduspider'   => '.baidu.com',
            'yahoofaqbot'   => '.yahoo.com',
            'chatgpt-user'  => '.outbound-customer.openai.com',
            'oai/openai'    => '.outbound-customer.openai.com',
            'gptbot'        => '.outbound-customer.openai.com',
            'searchbot'     => '.outbound-customer.openai.com',
            'amazonbot'     => '.amazonbot.amazon.com',
            'uptimerobot'   => '',
            'pingdom'       => '',
        ];

        foreach ($known_bots as $ua_keyword => $domain) {
            if (stripos($user_agent, $ua_keyword) !== false) {
                return true;
            }
        }
        return false;
    }

    /**
     * Descarga y cachea las listas oficiales de IPs de bots (Google y bots de IA).
     */
    public function fetch_and_cache_bot_lists() {
        $endpoints = [
            'gptbot' => 'https://openai.com/gptbot.json',
            'searchbot' => 'https://openai.com/searchbot.json',
            'chatgpt-user' => 'https://openai.com/chatgpt-user.json',
            'applebot' => 'https://search.developer.apple.com/applebot.json',
            'google' => [
                'https://developers.google.com/static/crawling/ipranges/common-crawlers.json',
                'https://developers.google.com/static/crawling/ipranges/special-crawlers.json',
                'https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers.json',
                'https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers-google.json',
                'https://developers.google.com/static/crawling/ipranges/user-triggered-agents.json'
            ]
        ];

        $txt_endpoints = [
            'uptimerobot' => [
                'https://uptimerobot.com/inc/files/ips/IPv4.txt',
                'https://uptimerobot.com/inc/files/ips/IPv6.txt'
            ],
            'pingdom' => [
                'https://my.pingdom.com/probes/ipv4',
                'https://my.pingdom.com/probes/ipv6'
            ]
        ];

        $all_cidrs = [];
        
        // Cargar listas JSON
        foreach ($endpoints as $bot => $urls) {
            if (!is_array($urls)) {
                $urls = [$urls];
            }
            
            foreach ($urls as $url) {
                $response = wp_remote_get($url, ['timeout' => 5]);
                if (!is_wp_error($response)) {
                    $body = wp_remote_retrieve_body($response);
                    $data = json_decode($body, true);
                    if (is_array($data) && !empty($data['prefixes'])) {
                        foreach ($data['prefixes'] as $prefix) {
                            if (!empty($prefix['ipv4Prefix'])) {
                                $all_cidrs[$bot][] = $prefix['ipv4Prefix'];
                            }
                            if (!empty($prefix['ipv6Prefix'])) {
                                $all_cidrs[$bot][] = $prefix['ipv6Prefix'];
                            }
                        }
                    }
                }
            }
        }

        // Cargar listas TXT (Uptime Robot, Pingdom, etc.)
        foreach ($txt_endpoints as $bot => $urls) {
            foreach ($urls as $url) {
                $response = wp_remote_get($url, ['timeout' => 5]);
                if (!is_wp_error($response)) {
                    $body = wp_remote_retrieve_body($response);
                    $lines = explode("\n", $body);
                    foreach ($lines as $line) {
                        $ip = trim($line);
                        // Limpiar comentarios si existen
                        if (strpos($ip, '#') !== false) {
                            $ip = trim(substr($ip, 0, strpos($ip, '#')));
                        }
                        if (!empty($ip)) {
                            $all_cidrs[$bot][] = $ip;
                        }
                    }
                }
            }
        }

        if (!empty($all_cidrs)) {
            update_option('advaipbl_bot_ips', $all_cidrs, false);
            set_transient('advaipbl_bot_ips_cached', true, DAY_IN_SECONDS);
            $this->plugin->log_event(__('Official bot IP lists successfully downloaded and cached (Google, AI Bots, Monitoring Bots).', 'advanced-ip-blocker'), 'info');
        } else {
            // CRITICAL FIX: If all HTTP requests fail, set a shorter transient to prevent
            // a timeout loop on every page load (which could cause a DoS).
            set_transient('advaipbl_bot_ips_cached', true, HOUR_IN_SECONDS);
            $this->plugin->log_event(__('Failed to download official bot IP lists. This could be due to a firewall blocking outgoing HTTP requests or an API outage. Retrying in 1 hour.', 'advanced-ip-blocker'), 'error');
        }
    }

    /**
     * Verifica si la IP pertenece a la lista CIDR cacheada del bot.
     */
    private function verify_bot_ip($ip, $ua_keyword) {
        $bot_ips = get_option('advaipbl_bot_ips', []);
        
        $bot_key = '';
        if ($ua_keyword === 'gptbot' || $ua_keyword === 'oai/openai') {
            $bot_key = 'gptbot';
        } elseif ($ua_keyword === 'searchbot') {
            $bot_key = 'searchbot';
        } elseif ($ua_keyword === 'chatgpt-user') {
            $bot_key = 'chatgpt-user';
        } elseif ($ua_keyword === 'applebot') {
            $bot_key = 'applebot';
        } elseif (in_array($ua_keyword, ['googlebot', 'google.com/bot', 'adsbot-google'])) {
            $bot_key = 'google';
        } elseif ($ua_keyword === 'uptimerobot') {
            $bot_key = 'uptimerobot';
        } elseif ($ua_keyword === 'pingdom') {
            $bot_key = 'pingdom';
        }

        if (empty($bot_key) || empty($bot_ips[$bot_key])) {
            return false;
        }

        foreach ($bot_ips[$bot_key] as $cidr) {
            if ($this->plugin->is_ip_in_range($ip, $cidr)) {
                return true;
            }
        }

        return false;
    }
}