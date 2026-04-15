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

        // Ahora realizamos la verificación de DNS
        $is_verified = $this->verify_dns($ip, $expected_domains);

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
}