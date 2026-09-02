<?php

if (! defined('ABSPATH')) {
    exit;
}

class ADVAIPBL_Rules_Engine
{
    public const OPTION_RULES = 'advaipbl_advanced_rules';

    /**
     * Main plugin class instance.
     * @var ADVAIPBL_Main
     */
    private $plugin;

    /**
     * Constructor.
     * @param ADVAIPBL_Main $plugin_instance The main class instance.
     */
    public function __construct(ADVAIPBL_Main $plugin_instance)
    {
        $this->plugin = $plugin_instance;
    }

    /**
     * Temporary context for evaluation (e.g. username on login).
     * @var array
     */
    private $context = [];

    /**
     * Sets the context for rule evaluation.
     * @param array $context Array of context data (e.g. ['username' => 'admin']).
     */
    public function set_context(array $context)
    {
        $this->context = $context;
    }

    /**
     * Gets all stored advanced rules.
     * @return array
     */
    public function get_rules()
    {
        $rules = get_option(self::OPTION_RULES, []);
        if (is_array($rules)) {
            foreach ($rules as &$rule) {
                if (!isset($rule['is_active'])) {
                    $rule['is_active'] = true;
                }
            }
        }

        return is_array($rules) ? $rules : [];
    }

    /**
 * Sanitizes and validates a rule data array.
 *
 * @param array $rule_data The raw rule data.
 * @return array|false The sanitized rule, or false if invalid.
 */
    private function sanitize_rule(array $rule_data)
    {
        $sanitized_rule = [];

        if (isset($rule_data['id']) && !empty($rule_data['id'])) {
            $sanitized_rule['id'] = sanitize_key($rule_data['id']);
        } else {
            $sanitized_rule['id'] = 'ar_' . bin2hex(random_bytes(8));
        }
        $sanitized_rule['name'] = isset($rule_data['name']) ? sanitize_text_field($rule_data['name']) : 'Untitled Rule';
        $sanitized_rule['is_active'] = isset($rule_data['is_active']) ? filter_var($rule_data['is_active'], FILTER_VALIDATE_BOOLEAN) : true;

        $allowed_actions = ['block', 'challenge', 'challenge_automatic', 'challenge_turnstile', 'challenge_hcaptcha', 'score', 'allow'];
        $sanitized_rule['action'] = isset($rule_data['action']) && in_array($rule_data['action'], $allowed_actions, true) ? $rule_data['action'] : 'block';

        $sanitized_rule['action_params'] = [];
        if (isset($rule_data['action_params']) && is_array($rule_data['action_params'])) {
            if (isset($rule_data['action_params']['duration'])) {
                $sanitized_rule['action_params']['duration'] = absint($rule_data['action_params']['duration']);
            }
            if (isset($rule_data['action_params']['points'])) {
                $sanitized_rule['action_params']['points'] = absint($rule_data['action_params']['points']);
            }
        }

        if (!isset($rule_data['conditions']) || !is_array($rule_data['conditions']) || empty($rule_data['conditions'])) {
            return false;
        }

        $sanitized_rule['conditions'] = [];
        $allowed_types = ['ip', 'ip_range', 'country', 'asn', 'hostname', 'uri', 'user_agent', 'username', 'request_method', 'referer', 'cookie', 'header', 'payload', 'query_string'];
        $allowed_operators = ['is', 'is_not', 'contains', 'does_not_contain', 'starts_with', 'ends_with', 'matches_regex', 'is_empty', 'is_not_empty'];

        foreach ($rule_data['conditions'] as $condition) {
            if (
                !isset($condition['type']) || !in_array($condition['type'], $allowed_types, true) ||
                !isset($condition['operator']) || !in_array($condition['operator'], $allowed_operators, true)
            ) {
                continue;
            }

            if (!in_array($condition['operator'], ['is_empty', 'is_not_empty'], true)) {
                if (!isset($condition['value']) || $condition['value'] === '') {
                    continue;
                }
            }

            $sanitized_condition = [
                'type'     => $condition['type'],
                'operator' => $condition['operator'],
                'target'   => isset($condition['target']) ? sanitize_text_field($condition['target']) : '',
                'value'    => isset($condition['value']) ? sanitize_text_field($condition['value']) : '' // Sanitización genérica y segura para todos los valores.
            ];

            $sanitized_rule['conditions'][] = $sanitized_condition;
        }

        if (empty($sanitized_rule['conditions'])) {
            return false;
        }

        return $sanitized_rule;
    }

    /**
     * Saves a complete array of rules.
     * @param array $rules The array of rules to save.
     * @return bool True if successfully updated.
     */
    private function save_rules(array $rules)
    {
        return update_option(self::OPTION_RULES, $rules);
    }

    /**
     * Adds a new rule to the set.
     * @param array $rule_data The new rule data.
     * @return array|false The complete rule with its new ID, or false if failed.
     */
    public function add_rule(array $rule_data)
    {
        $rules = $this->get_rules();

        $sanitized_rule = $this->sanitize_rule($rule_data);
        if ($sanitized_rule === false) {
            return false;
        }

        $rules[] = $sanitized_rule;

        if ($this->save_rules($rules)) {
            return $sanitized_rule;
        }

        return false;
    }

    /**
     * Updates an existing rule.
     * @param string $rule_id The rule ID to update.
     * @param array $rule_data The new data for the rule.
     * @return bool True if found and updated.
     */
    public function update_rule($rule_id, array $rule_data)
    {
        $rules = $this->get_rules();
        $rule_found = false;

        $sanitized_rule = $this->sanitize_rule($rule_data);
        if ($sanitized_rule === false) {
            return false;
        }

        foreach ($rules as $index => $rule) {
            if (isset($rule['id']) && $rule['id'] === $rule_id) {
                $sanitized_rule['id'] = $rule_id;

                if (strpos($rule_id, 'ar_zd_') === 0) {
                    $original_rule = $rule;
                    $original_rule['is_active'] = $sanitized_rule['is_active'];
                    $sanitized_rule = $original_rule;
                }

                if ($rules[$index] === $sanitized_rule) {
                    return true;
                }

                $rules[$index] = $sanitized_rule;
                $rule_found = true;
                break;
            }
        }

        if ($rule_found) {
            $this->save_rules($rules);

            return true;
        }

        return false;
    }

    /**
     * Deletes a rule by its ID.
     * @param string $rule_id The rule ID to delete.
     * @return bool True if found and deleted.
     */
    public function delete_rule($rule_id)
    {
        $rules = $this->get_rules();
        $rules_updated = [];
        $rule_found = false;

        foreach ($rules as $rule) {
            if (isset($rule['id']) && $rule['id'] === $rule_id) {
                if (strpos($rule_id, 'ar_zd_') === 0) {
                    return false;
                }
                $rule_found = true;
            } else {
                $rules_updated[] = $rule;
            }
        }

        if ($rule_found) {
            return $this->save_rules($rules_updated);
        }

        return false;
    }

    /**
     * Evaluates the current request against the advanced rule set.
     * Stops at the first matching rule and executes its action.
     *
     * @return bool True if a rule matched and an action was taken that ends the request (block or challenge), false otherwise.
     */
    public function evaluate()
    {
        $rules = $this->get_rules();

        if (empty($rules)) {
            return false;
        }

        if (is_user_logged_in() && current_user_can('unfiltered_html')) {
            return false;
        }

        $ip = $this->plugin->get_client_ip();

        if ($this->plugin->is_whitelisted($ip) || !empty($this->plugin->request_is_asn_whitelisted)) {
            return false;
        }

        if (get_transient('advaipbl_grace_pass_' . md5($ip))) {
            return false;
        }

        if ($this->plugin->js_challenge_manager->is_vip_pass_valid()) {
            return false;
        }

        foreach ($rules as $rule) {
            if (isset($rule['is_active']) && $rule['is_active'] === false) {
                continue;
            }

            if (!isset($rule['conditions']) || empty($rule['conditions']) || !isset($rule['action'])) {
                continue;
            }

            $all_conditions_met = true;
            foreach ($rule['conditions'] as $condition) {
                if (!$this->check_condition($condition, $ip)) {
                    $all_conditions_met = false;
                    break;
                }
            }

            if ($all_conditions_met) {
                return $this->execute_action($rule, $ip);
            }
        }

        return false;
    }

    /**
     * Checks if an individual condition is met.
     *
     * @param array $condition The condition object.
     * @param string $ip The visitor's IP.
     * @return bool True if the condition is met.
     */
    private function check_condition($condition, $ip)
    {
        $type     = $condition['type'] ?? null;
        $operator = $condition['operator'] ?? 'is';
        $value    = $condition['value'] ?? '';

        if ($type === null) {
            return false;
        }

        if ($value === '' && !in_array($operator, ['is_empty', 'is_not_empty'], true)) {
            return false;
        }

        $subject = '';

        switch ($type) {
            case 'username':

                if (empty($this->context['username'])) {
                    return false;
                }
                $subject = $this->context['username'];
                break;
            case 'ip':
            case 'ip_range':
                $subject = $ip;
                break;
            case 'country':
                $location = $this->plugin->geolocation_manager->fetch_location($ip);
                $subject = $location['country_code'] ?? '';
                break;
            case 'asn':
                $location = $this->plugin->geolocation_manager->fetch_location($ip);
                $subject = $this->plugin->asn_manager->extract_asn_from_data($location);
                break;
            case 'hostname':
                $hostname = @gethostbyaddr($ip);
                $subject = ($hostname && $hostname !== $ip) ? $hostname : '';
                break;
            case 'uri':
                $subject = $this->plugin->get_current_request_uri();
                break;
            case 'user_agent':
                $subject = $this->plugin->get_user_agent();
                break;
            case 'request_method':
                // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
                $subject = $_SERVER['REQUEST_METHOD'] ?? '';
                break;
            case 'referer':
                // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
                $subject = $_SERVER['HTTP_REFERER'] ?? '';
                break;
            case 'cookie':
                $target = $condition['target'] ?? '';
                // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
                $subject = (!empty($target) && isset($_COOKIE[$target])) ? $_COOKIE[$target] : '';
                break;
            case 'header':
                $target = $condition['target'] ?? '';
                if (empty($target)) {
                    $subject = '';
                } else {
                    $header_key = 'HTTP_' . strtoupper(str_replace('-', '_', $target));
                    // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
                    $subject = isset($_SERVER[$header_key]) ? $_SERVER[$header_key] : '';
                }
                break;
            case 'payload':
                $raw_body = @file_get_contents('php://input');
                // phpcs:disable WordPress.Security.NonceVerification.Missing
                $post_data = !empty($_POST) ? urldecode(http_build_query($_POST)) : '';
                // Incluir metadatos de archivos subidos para vulnerabilidades de File Upload / RCE (ej. CVE-2026-18431)
                $files_data = !empty($_FILES) ? urldecode(http_build_query($_FILES)) : '';
                // phpcs:enable WordPress.Security.NonceVerification.Missing
                $subject = $raw_body . "\n" . $post_data . "\n" . $files_data;
                break;
            case 'query_string':
                // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
                $subject = isset($_SERVER['QUERY_STRING']) ? $_SERVER['QUERY_STRING'] : '';
                break;
            default:
                return false;
        }

        $result = false;

        switch ($operator) {
            case 'is_empty':
                $result = empty($subject);
                break;
            case 'is_not_empty':
                $result = !empty($subject);
                break;
            case 'is':
                if ($type === 'ip_range') {
                    $result = $this->plugin->is_ip_in_range($subject, $value);
                } else {
                    $result = strcasecmp($subject, $value) === 0;
                }
                break;
            case 'is_not':
                if ($type === 'ip_range') {
                    $result = !$this->plugin->is_ip_in_range($subject, $value);
                } else {
                    $result = strcasecmp($subject, $value) !== 0;
                }
                break;
            case 'contains':
                $result = stripos($subject, $value) !== false;
                break;
            case 'does_not_contain':
                $result = stripos($subject, $value) === false;
                break;
            case 'starts_with':

                $result = stripos($subject, $value) === 0;
                break;
            case 'ends_with':
                $length = strlen($value);
                if ($length == 0) {
                    $result = true;
                } else {
                    $result = substr_compare($subject, $value, -$length, $length, true) === 0;
                }
                break;
            case 'matches_regex':

                $safe_value = str_replace('@', '\@', $value);
                $result = @preg_match('@' . $safe_value . '@i', $subject) === 1;
                break;
        }

        return $result;
    }

    /**
     * Executes the action defined in a rule.
     *
     * @param array $rule The matched rule.
     * @param string $ip The visitor's IP.
     * @return bool True if the action ends the request.
     */
    private function execute_action($rule, $ip)
    {
        $action = $rule['action'];
        $params = $rule['action_params'] ?? [];
        $rule_name = $rule['name'] ?? 'Untitled Rule';

        if (isset($this->plugin->rules_metrics) && !empty($rule['id'])) {
            $this->plugin->rules_metrics->increment($rule['id'], 'hits');
        }

        $log_data = [
            'rule_id'   => $rule['id'],
            'rule_name' => $rule_name,
            'uri'       => $this->plugin->get_current_request_uri()
        ];

        switch ($action) {
            case 'allow':
                $this->plugin->log_specific_error(
                    'advanced_rule_allow',
                    $ip,
                    $log_data,
                    'info'
                );

                $this->plugin->is_advanced_rule_allowed = true;

                return true;
            case 'block':

                $duration_minutes = isset($params['duration']) ? (int) $params['duration'] : 0;
                $duration_seconds = ($duration_minutes > 0) ? $duration_minutes * 60 : 0;

                /* translators: %s is a placeholder */
                $reason = sprintf(__('Blocked by Advanced Rule: %s', 'advanced-ip-blocker'), $rule_name);

                $this->plugin->block_ip_instantly($ip, 'advanced_rule', $reason, $log_data, 'frontend_block', $duration_seconds);

                return true;

            case 'challenge':
            case 'challenge_automatic':
            case 'challenge_turnstile':
            case 'challenge_hcaptcha':

                if (isset($this->plugin->js_challenge_manager) && $this->plugin->js_challenge_manager->is_vip_pass_valid()) {
                    return false;
                }

                // phpcs:ignore WordPress.Security.NonceVerification.Missing
                if (isset($_POST['_advaipbl_js_token']) || isset($_POST['_advaipbl_challenge_type'])) {
                    return false;
                }

                $mode = str_replace('challenge_', '', $action);
                if ($mode === 'challenge') {
                    $mode = 'managed';
                }
                if ($mode === 'managed') {
                    $mode = 'js_managed';
                }
                if ($mode === 'automatic') {
                    $mode = 'js_automatic';
                }

                $log_data['mode'] = $mode;

                $this->plugin->log_specific_error(
                    'advanced_rule_challenge',
                    $ip,
                    $log_data,
                    'warning' // Nivel 'warning' porque no es un bloqueo, es un desafío
                );
                $this->plugin->js_challenge_manager->serve_challenge('advanced_rule_challenge', $mode);

                return true;

            case 'score':
                $points = isset($params['points']) ? (int)$params['points'] : 10;
                $log_data['points_added'] = $points;

                $this->plugin->log_specific_error(
                    'advanced_rule',
                    $ip,
                    $log_data,
                    'info'
                );

                $this->plugin->threat_score_manager->increment_score($ip, $points, 'advanced_rule', ['rule_name' => $rule_name]);

                return false;

            default:
                return false;
        }
    }
}
