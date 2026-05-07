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
            'adsbot-google'     => '.googlebot.com',
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
            'amazonbot'           => ['.amazonbot.amazon.com', '.crawl.amazonbot.amazon.com'],

            // --- Otros Bots de Confianza ---
            'yahoo! slurp'        => '.yahoo.com',
            'yahoofaqbot'         => '.yahoo.com',
            'petalbot'            => ['.aspiegel.com', '.petalsearch.com'],
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
        if (in_array($ua_keyword, ['chatgpt-user', 'oai/openai', 'gptbot', 'applebot'])) {
            $is_ai_bot = true;
        }

        // Si es un bot de IA y la opción está activa, verificamos por CIDR en lugar de DNS
        if ($is_ai_bot && !empty($this->plugin->options['enable_ai_bot_verification']) && $this->plugin->options['enable_ai_bot_verification'] === '1') {
            if (!get_transient('advaipbl_ai_bot_ips_cached')) {
                $this->fetch_and_cache_ai_lists();
            }
            $is_verified = $this->verify_ai_ip($ip, $ua_keyword);
            
            // Fallback a DNS si la lista CIDR está vacía por algún error de API
            if (!$is_verified && empty(get_option('advaipbl_ai_bot_ips', []))) {
                $is_verified = $this->verify_dns($ip, $expected_domains);
            }
        } else {
            // Ahora realizamos la verificación de DNS clásica
            $is_verified = $this->verify_dns($ip, $expected_domains);
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
            'bingbot'       => '.search.msn.com',
            'yandexbot'     => '.yandex.com',
            'duckduckbot'   => '.duckduckgo.com',
            'Applebot'      => '.applebot.apple.com',
            'baiduspider'   => '.baidu.com',
            'yahoofaqbot'   => '.yahoo.com',
            'chatgpt-user'  => '.outbound-customer.openai.com',
            'oai/openai'    => '.outbound-customer.openai.com',
            'gptbot'        => '.outbound-customer.openai.com',
            'amazonbot'     => '.amazonbot.amazon.com',
        ];

        foreach ($known_bots as $ua_keyword => $domain) {
            if (stripos($user_agent, $ua_keyword) !== false) {
                return true;
            }
        }
        return false;
    }

    /**
     * Descarga y cachea las listas oficiales de IPs de bots de IA.
     */
    public function fetch_and_cache_ai_lists() {
        $endpoints = [
            'gptbot' => 'https://openai.com/gptbot.json',
            'searchbot' => 'https://openai.com/searchbot.json',
            'chatgpt-user' => 'https://openai.com/chatgpt-user.json',
            'applebot' => 'https://search.developer.apple.com/applebot.json'
        ];

        $all_cidrs = [];
        foreach ($endpoints as $bot => $url) {
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

        if (!empty($all_cidrs)) {
            update_option('advaipbl_ai_bot_ips', $all_cidrs, false);
            set_transient('advaipbl_ai_bot_ips_cached', true, DAY_IN_SECONDS);
        }
    }

    /**
     * Verifica si la IP pertenece a la lista CIDR del bot de IA.
     */
    private function verify_ai_ip($ip, $ua_keyword) {
        $ai_ips = get_option('advaipbl_ai_bot_ips', []);
        
        $bot_key = '';
        if ($ua_keyword === 'gptbot' || $ua_keyword === 'oai/openai') {
            $bot_key = 'gptbot';
        } elseif ($ua_keyword === 'chatgpt-user') {
            $bot_key = 'chatgpt-user';
        } elseif ($ua_keyword === 'applebot') {
            $bot_key = 'applebot';
        }

        if (empty($bot_key) || empty($ai_ips[$bot_key])) {
            return false;
        }

        foreach ($ai_ips[$bot_key] as $cidr) {
            if ($this->plugin->is_ip_in_range($ip, $cidr)) {
                return true;
            }
        }

        return false;
    }
}