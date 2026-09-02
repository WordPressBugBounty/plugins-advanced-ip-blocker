<?php

if (!defined('ABSPATH')) {
    exit;
}

class ADVAIPBL_Waf_Manager
{
    /**
    * Scans the current request against the user's custom WAF rules,
    * respecting the excluded URLs list.
    *
    * @return string|false The matching rule, or false if no match.
    */
    public function run_waf_scan()
    {
        if (is_user_logged_in() && current_user_can('unfiltered_html')) {
            return false;
        }
        $main_class = ADVAIPBL_Main::get_instance();
        $request_uri = $main_class->get_current_request_uri();

        $options = get_option(ADVAIPBL_Main::OPTION_SETTINGS, []);
        $raw_excluded_urls = $options['waf_excluded_urls'] ?? '';

        if (!empty(trim($raw_excluded_urls))) {
            $excluded_urls = array_filter(array_map('trim', explode("\n", $raw_excluded_urls)));

            if (!empty($excluded_urls)) {
                foreach ($excluded_urls as $excluded_url_fragment) {
                    if (empty($excluded_url_fragment) || strpos($excluded_url_fragment, '#') === 0) {
                        continue;
                    }

                    if (stripos($request_uri, $excluded_url_fragment) !== false) {
                        return false;
                    }
                }
            }
        }

        if (strpos($request_uri, 'xmlrpc.php') !== false) {
            return false;
        }

        $raw_rules = get_option(ADVAIPBL_Main::OPTION_WAF_RULES, '');

        $rules = array_filter(array_map('trim', explode("\n", $raw_rules)));

        if (!empty($options['enable_intelligent_waf']) && '1' === $options['enable_intelligent_waf']) {
            $zeroday_rules = get_option('advaipbl_zeroday_waf_rules', []);
            if (is_array($zeroday_rules) && !empty($zeroday_rules)) {
                $filtered_zeroday = [];
                foreach ($zeroday_rules as $rule) {
                    $rule = trim((string) $rule);
                    if (!empty($rule) && strpos($rule, '#') !== 0) {
                        $filtered_zeroday[] = $rule;
                    }
                }
                $rules = array_merge($rules, $filtered_zeroday);
            }
        }

        if (empty($rules)) {
            return false;
        }

        $headers = [];
        foreach ($_SERVER as $key => $value) {
            if (strpos($key, 'HTTP_') === 0) {
                $headers[$key] = $value;
            }
        }

        $request_data_to_scan = [
            // phpcs:disable WordPress.Security.NonceVerification.Recommended, WordPress.Security.NonceVerification.Missing
            'GET'         => $_GET,
            'POST'        => $_POST,
            'COOKIE'      => $_COOKIE,
            'FILES'       => $_FILES,
            // phpcs:enable WordPress.Security.NonceVerification.Recommended, WordPress.Security.NonceVerification.Missing
            'HEADERS'     => $headers,
            'REQUEST_URI' => $request_uri,
            'USER_AGENT'  => $main_class->get_user_agent(),
            'RAW_BODY'    => @file_get_contents('php://input'),
        ];

        foreach ($rules as $rule) {
            if (empty($rule) || strpos($rule, '#') === 0) {
                continue;
            }
            $pattern = '#' . $rule . '#i';
            if ($this->scan_data_recursively($request_data_to_scan, $pattern)) {
                return $rule;
            }
        }

        return false;
    }

    /**
     * Recursively scans data for a match.
     * @param mixed  $data    Data or array to scan.
     * @param string $pattern Regular expression.
     * @return bool True if there is a match.
     */
    private function scan_data_recursively($data, $pattern)
    {
        if (is_array($data)) {
            foreach ($data as $key => $value) {
                if (is_string($key) && @preg_match($pattern, $key)) {
                    return true;
                }
                if ($this->scan_data_recursively($value, $pattern)) {
                    return true;
                }
            }
        } elseif (is_string($data)) {
            if (@preg_match($pattern, $data)) {
                return true;
            }
        }

        return false;
    }
}
