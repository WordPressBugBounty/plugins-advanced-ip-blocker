<?php

if (! defined('ABSPATH')) {
    exit;
}

class ADVAIPBL_Bot_Verifier
{
    private $plugin;

    private static $verified_cache = [];

    public function __construct(ADVAIPBL_Main $plugin_instance)
    {
        $this->plugin = $plugin_instance;
    }

    /**
     * Main function that checks if an IP is a known and verified bot.
     */
    public function is_verified_bot($ip, $user_agent)
    {
        if (empty($ip) || empty($user_agent)) {
            return false;
        }

        if (isset(self::$verified_cache[$ip])) {
            return self::$verified_cache[$ip];
        }

        $known_bots = [
            'googlebot'         => ['.googlebot.com', '.google.com'],
            'google.com/bot'    => '.google.com',
            'adsbot-google'     => ['.googlebot.com', '.google.com'],
            'bingbot'           => '.search.msn.com',
            'adidxbot'          => '.search.msn.com',

            'yandexbot'         => ['.yandex.com', '.yandex.ru', '.yandex.net'],
            'duckduckbot'       => '.duckduckgo.com',

            'applebot'          => ['.applebot.apple.com', '.apple.com', '.icloud.com'],
            'baiduspider'       => ['.baidu.com', '.baidu.jp'],
            'seznambot'         => '.seznam.cz',

            'ahrefsbot'         => ['.ahrefs.com', '.ahrefs.net'],
            'semrushbot'        => '.semrush.com',
            'splitsignalbot'    => '.semrush.com',
            'siteauditbot'      => '.semrush.com',
            'contentanalyzerbot' => '.semrush.com',
            'mj12bot'           => '.mj12bot.com',
            'iboubot'           => '.ibou.io',

            'facebookexternalhit' => ['.facebook.com', '.tfbnw.net'],
            'facebot'             => ['.facebook.com', '.tfbnw.net'],
            'twitterbot'          => '.twitter.com',
            'linkedinbot'         => '.linkedin.com',
            'pinterestbot'        => '.pinterest.com',

            'chatgpt-user'        => '.outbound-customer.openai.com',
            'oai/openai'          => '.outbound-customer.openai.com',
            'gptbot'              => '.outbound-customer.openai.com',
            'oai-searchbot'       => '.outbound-customer.openai.com',
            'amazonbot'           => ['.amazonbot.amazon.com', '.crawl.amazonbot.amazon.com'],
            'amzn-searchbot'      => ['.amazonbot.amazon.com', '.crawl.amazonbot.amazon.com'],

            'yahoo! slurp'        => ['.yahoo.com', '.crawl.yahoo.net'],
            'yahoofaqbot'         => ['.yahoo.com', '.crawl.yahoo.net'],
            'petalbot'            => ['.aspiegel.com', '.petalsearch.com'],

            'uptimerobot'         => '.uptimerobot.com',
            'pingdom'             => '.pingdom.com',
            'pingbot'             => '.pingdom.com',
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

        if (!$is_known_bot) {
            return false;
        }

        $is_ai_bot = false;
        $is_google_bot = false;
        $is_monitoring_bot = false;
        $is_seo_cidr_bot = false;

        if (in_array($ua_keyword, ['chatgpt-user', 'oai/openai', 'gptbot', 'oai-searchbot', 'applebot', 'amazonbot', 'amzn-searchbot'])) {
            $is_ai_bot = true;
        } elseif (in_array($ua_keyword, ['googlebot', 'google.com/bot', 'adsbot-google'])) {
            $is_google_bot = true;
        } elseif (in_array($ua_keyword, ['uptimerobot', 'pingdom', 'pingbot'])) {
            $is_monitoring_bot = true;
        } elseif (in_array($ua_keyword, ['ahrefsbot', 'bingbot', 'adidxbot', 'duckduckbot', 'seznambot', 'iboubot'])) {
            $is_seo_cidr_bot = true;
        }

        $ai_bot_enabled = isset($this->plugin->options['enable_ai_bot_verification']) ? $this->plugin->options['enable_ai_bot_verification'] : '1';
        $monitoring_bot_enabled = isset($this->plugin->options['enable_monitoring_bot_verification']) ? $this->plugin->options['enable_monitoring_bot_verification'] : '1';

        if (($is_ai_bot && $ai_bot_enabled === '1') || $is_google_bot || ($is_monitoring_bot && $monitoring_bot_enabled === '1') || $is_seo_cidr_bot) {
            if (!get_transient('advaipbl_bot_ips_cached')) {
                $this->fetch_and_cache_bot_lists();
            }
            $is_verified = $this->verify_bot_ip($ip, $ua_keyword);

            if (!$is_verified) {
                $is_verified = $this->verify_dns($ip, $expected_domains);
            }
        } else {
            $is_verified = $this->verify_dns($ip, $expected_domains);
        }

        self::$verified_cache[$ip] = $is_verified;

        return $is_verified;
    }

    /**
     * Performs a reverse DNS (rDNS) and forward DNS verification.
     */
    private function verify_dns($ip, $expected_domains)
    {
        $hostname = gethostbyaddr($ip);
        if ($hostname === $ip || $hostname === false) {
            return false;
        }

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

        $resolved_ips = gethostbynamel($hostname);

        if ($resolved_ips === false || empty($resolved_ips)) {
            return false;
        }

        return in_array($ip, $resolved_ips, true);
    }

    /**
     * Checks if a User-Agent matches a known bot, to identify imposters.
     */
    public function is_known_bot_impersonator($ip, $user_agent)
    {
        $known_bots = [
            'googlebot'     => '.googlebot.com',
            'google.com/bot' => '.google.com',
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
            'oai-searchbot' => '.outbound-customer.openai.com',
            'amazonbot'     => '.amazonbot.amazon.com',
            'ahrefsbot'     => '.ahrefs.com',
            'semrushbot'    => '.semrush.com',
            'splitsignalbot' => '.semrush.com',
            'siteauditbot'  => '.semrush.com',
            'contentanalyzerbot' => '.semrush.com',
            'mj12bot'       => '.majestic12.co.uk',
            'iboubot'       => '.ibou.io',
            'seznambot'     => '.seznam.cz',
            'uptimerobot'   => '.uptimerobot.com',
            'pingdom'       => '.pingdom.com',
            'pingbot'       => '.pingdom.com',
        ];

        foreach ($known_bots as $ua_keyword => $domain) {
            if (stripos($user_agent, $ua_keyword) !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * Downloads and caches official bot IP lists (Google and AI bots).
     */
    public function fetch_and_cache_bot_lists()
    {
        $endpoints = [
            'ahrefsbot' => 'https://api.ahrefs.com/v3/public/crawler-ips',
            'amazonbot' => [
                'https://developer.amazon.com/amazonbot/searchbot-ip-addresses/',
                'https://developer.amazon.com/amazonbot/ip-addresses/'
            ],
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
            ],
            'bingbot' => 'https://www.bing.com/toolbox/bingbot.json',
            'duckduckbot' => 'https://duckduckgo.com/duckduckbot.json',
            'seznambot' => 'https://search.seznam.cz/ipranges/seznambot.json',
            'iboubot' => 'https://ibou.io/iboubot-ip-ranges.json'
        ];

        $txt_endpoints = [
            'uptimerobot' => [
                'https://cdn.uptimerobot.com/api/IPv4andIPv6.txt'
            ],
            'pingdom' => [
                'https://my.pingdom.com/probes/ipv4',
                'https://my.pingdom.com/probes/ipv6'
            ]
        ];

        $all_cidrs = [];

        foreach ($endpoints as $bot => $urls) {
            if (!is_array($urls)) {
                $urls = [$urls];
            }

            foreach ($urls as $url) {
                $response = wp_remote_get($url, ['timeout' => 5]);
                if (!is_wp_error($response)) {
                    $body = wp_remote_retrieve_body($response);

                    if ($bot === 'amazonbot') {
                        if (preg_match('/<code[^>]*>\s*(\{[\s\S]*?"prefixes"[\s\S]*?\})\s*<\/code>/i', $body, $matches)) {
                            $amz_data = json_decode($matches[1], true);
                            if (is_array($amz_data) && !empty($amz_data['prefixes'])) {
                                foreach ($amz_data['prefixes'] as $prefix) {
                                    if (!empty($prefix['ip_prefix'])) {
                                        $all_cidrs[$bot][] = $prefix['ip_prefix'];
                                    } elseif (!empty($prefix['ipv4Prefix'])) {
                                        $all_cidrs[$bot][] = $prefix['ipv4Prefix'];
                                    }

                                    if (!empty($prefix['ipv6_prefix'])) {
                                        $all_cidrs[$bot][] = $prefix['ipv6_prefix'];
                                    } elseif (!empty($prefix['ipv6Prefix'])) {
                                        $all_cidrs[$bot][] = $prefix['ipv6Prefix'];
                                    }
                                }
                            }
                        }
                    } else {
                        $data = json_decode($body, true);

                        if ($bot === 'ahrefsbot') {
                            if (is_array($data) && !empty($data['ips'])) {
                                foreach ($data['ips'] as $item) {
                                    if (!empty($item['ip_address'])) {
                                        $all_cidrs[$bot][] = $item['ip_address'];
                                    }
                                }
                            }
                        } else {
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
            }
        }

        foreach ($txt_endpoints as $bot => $urls) {
            foreach ($urls as $url) {
                $response = wp_remote_get($url, ['timeout' => 5]);
                if (!is_wp_error($response)) {
                    $body = wp_remote_retrieve_body($response);
                    $lines = explode("\n", $body);
                    foreach ($lines as $line) {
                        $ip = trim($line);

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

            set_transient('advaipbl_bot_ips_cached', true, HOUR_IN_SECONDS);
            $this->plugin->log_event(__('Failed to download official bot IP lists. This could be due to a firewall blocking outgoing HTTP requests or an API outage. Retrying in 1 hour.', 'advanced-ip-blocker'), 'error');
        }
    }

    /**
     * Verifies if the IP belongs to the bot's cached CIDR list.
     */
    private function verify_bot_ip($ip, $ua_keyword)
    {
        $bot_ips = get_option('advaipbl_bot_ips', []);

        $bot_key = '';
        if ($ua_keyword === 'gptbot' || $ua_keyword === 'oai/openai') {
            $bot_key = 'gptbot';
        } elseif ($ua_keyword === 'oai-searchbot') {
            $bot_key = 'searchbot';
        } elseif ($ua_keyword === 'chatgpt-user') {
            $bot_key = 'chatgpt-user';
        } elseif ($ua_keyword === 'applebot') {
            $bot_key = 'applebot';
        } elseif (in_array($ua_keyword, ['googlebot', 'google.com/bot', 'adsbot-google'])) {
            $bot_key = 'google';
        } elseif ($ua_keyword === 'uptimerobot') {
            $bot_key = 'uptimerobot';
        } elseif (in_array($ua_keyword, ['pingdom', 'pingbot'])) {
            $bot_key = 'pingdom';
        } elseif ($ua_keyword === 'ahrefsbot') {
            $bot_key = 'ahrefsbot';
        } elseif (in_array($ua_keyword, ['bingbot', 'adidxbot'])) {
            $bot_key = 'bingbot';
        } elseif ($ua_keyword === 'duckduckbot') {
            $bot_key = 'duckduckbot';
        } elseif (in_array($ua_keyword, ['amazonbot', 'amzn-searchbot'])) {
            $bot_key = 'amazonbot';
        } elseif ($ua_keyword === 'seznambot') {
            $bot_key = 'seznambot';
        } elseif ($ua_keyword === 'iboubot') {
            $bot_key = 'iboubot';
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
