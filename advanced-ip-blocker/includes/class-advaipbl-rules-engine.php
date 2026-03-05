<?php

if ( ! defined( 'ABSPATH' ) ) exit;

class ADVAIPBL_Rules_Engine {

    const OPTION_RULES = 'advaipbl_advanced_rules';

    /**
     * Instancia de la clase principal del plugin.
     * @var ADVAIPBL_Main
     */
    private $plugin;

    /**
     * Constructor.
     * @param ADVAIPBL_Main $plugin_instance La instancia de la clase principal.
     */
    public function __construct(ADVAIPBL_Main $plugin_instance) {
        $this->plugin = $plugin_instance;
    }

    /**
     * Contexto temporal para evaluación (ej. username en login).
     * @var array
     */
    private $context = [];

    /**
     * Establece el contexto para la evaluación de reglas.
     * @param array $context Array de datos de contexto (ej. ['username' => 'admin']).
     */
    public function set_context(array $context) {
        $this->context = $context;
    }

    /**
     * Obtiene todas las reglas avanzadas almacenadas.
     * @return array
     */
    public function get_rules() {
        return get_option(self::OPTION_RULES, []);
    }

    /**
 * Sanitiza y valida un array de datos de una regla.
 *
 * @param array $rule_data Los datos de la regla sin procesar.
 * @return array|false La regla saneada, o false si es inválida.
 */
private function sanitize_rule(array $rule_data) {
    $sanitized_rule = [];

    if (isset($rule_data['id']) && !empty($rule_data['id'])) {
    // Si estamos actualizando una regla, saneamos el ID existente.
    $sanitized_rule['id'] = sanitize_key($rule_data['id']);
    } else {
    $sanitized_rule['id'] = 'ar_' . bin2hex(random_bytes(8));
    }
    $sanitized_rule['name'] = isset($rule_data['name']) ? sanitize_text_field($rule_data['name']) : 'Untitled Rule';

    $allowed_actions = ['block', 'challenge', 'score', 'allow'];
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
        return false; // Una regla sin condiciones no es válida.
    }

    $sanitized_rule['conditions'] = [];
    $allowed_types = ['ip', 'ip_range', 'country', 'asn', 'uri', 'user_agent', 'username'];
    $allowed_operators = ['is', 'is_not', 'contains', 'does_not_contain', 'starts_with', 'ends_with', 'matches_regex'];

    foreach ($rule_data['conditions'] as $condition) {
        if (
            !isset($condition['type']) || !in_array($condition['type'], $allowed_types, true) ||
            !isset($condition['operator']) || !in_array($condition['operator'], $allowed_operators, true) ||
            !isset($condition['value']) || $condition['value'] === ''
        ) {
            continue; // Saltar condición mal formada o vacía.
        }
        
        $sanitized_condition = [
            'type'     => $condition['type'],
            'operator' => $condition['operator'],
            'value'    => sanitize_text_field($condition['value']) // Sanitización genérica y segura para todos los valores.
        ];
        
        $sanitized_rule['conditions'][] = $sanitized_condition;
    }
    

    if (empty($sanitized_rule['conditions'])) {
        return false;
    }

    return $sanitized_rule;
}

    /**
     * Guarda un array completo de reglas.
     * @param array $rules El array de reglas a guardar.
     * @return bool True si se actualizó correctamente.
     */
    private function save_rules(array $rules) {
        return update_option(self::OPTION_RULES, $rules);
    }

    /**
     * Añade una nueva regla al conjunto.
     * @param array $rule_data Los datos de la nueva regla.
     * @return array|false La regla completa con su nuevo ID, o false si falla.
     */
    public function add_rule(array $rule_data) {
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
     * Actualiza una regla existente.
     * @param string $rule_id El ID de la regla a actualizar.
     * @param array $rule_data Los nuevos datos para la regla.
     * @return bool True si se encontró y actualizó.
     */
    public function update_rule($rule_id, array $rule_data) {
    $rules = $this->get_rules();
    $rule_found = false;

    $sanitized_rule = $this->sanitize_rule($rule_data);
    if ($sanitized_rule === false) {
        return false;
    }

    foreach ($rules as $index => $rule) {
        if (isset($rule['id']) && $rule['id'] === $rule_id) {
            // Aseguramos que el ID no se sobrescriba con uno nuevo del sanitizador.
            $sanitized_rule['id'] = $rule_id;
            $rules[$index] = $sanitized_rule;
            $rule_found = true;
            break;
        }
    }

    if ($rule_found) {
        return $this->save_rules($rules);
    }

    return false;
}

    /**
     * Elimina una regla por su ID.
     * @param string $rule_id El ID de la regla a eliminar.
     * @return bool True si se encontró y eliminó.
     */
    public function delete_rule($rule_id) {
        $rules = $this->get_rules();
        $rules_updated = [];
        $rule_found = false;

        foreach ($rules as $rule) {
            if (isset($rule['id']) && $rule['id'] === $rule_id) {
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
 * Evalúa la petición actual contra el conjunto de reglas avanzadas.
 * Se detiene en la primera regla que coincida y ejecuta su acción.
 * 
 * @return bool True si una regla coincidió y se tomó una acción que finaliza la petición (block o challenge), false en caso contrario.
 */
public function evaluate() {
    $rules = $this->get_rules();

    if (empty($rules)) {
        return false;
    }
	// Si el usuario acaba de pasar un desafío, le damos un pase de gracia de 15s
   // para evitar un bucle en la redirección. No evaluamos ninguna regla en esta petición.
    if (get_transient('advaipbl_grace_pass_' . md5($this->plugin->get_client_ip()))) {
        return false;
    }
	
	if (isset($_COOKIE['advaipbl_js_verified']) && $_COOKIE['advaipbl_js_verified'] === '1') {
        return false;
    }

    $ip = $this->plugin->get_client_ip();

    foreach ($rules as $rule) {
        if (!isset($rule['conditions']) || empty($rule['conditions']) || !isset($rule['action'])) {
            continue; // Regla mal formada, la saltamos
        }

        $all_conditions_met = true;
        foreach ($rule['conditions'] as $condition) {
            if (!$this->check_condition($condition, $ip)) {
                $all_conditions_met = false;
                break; // Si una condición falla, la regla entera falla
            }
        }

        if ($all_conditions_met) {
            // ¡Coincidencia! Ejecutamos la acción y terminamos.
            return $this->execute_action($rule, $ip);
        }
    }

    return false; // Ninguna regla coincidió
}

/**
 * Comprueba si una condición individual se cumple.
 *
 * @param array $condition El objeto de condición.
 * @param string $ip La IP del visitante.
 * @return bool True si la condición se cumple.
 */
private function check_condition($condition, $ip) {
    $type     = $condition['type'] ?? null;
    $operator = $condition['operator'] ?? 'is';
    $value    = $condition['value'] ?? null;

    if ($type === null || $value === null) {
        return false;
    }

    $subject = ''; // El valor de la petición actual que vamos a comprobar

    // Obtenemos el "sujeto" de la comprobación según el tipo
    switch ($type) {
        case 'username':
            // Si no estamos en contexto de login (context['username'] vacío), la regla no aplica.
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
        case 'uri':
            $subject = $this->plugin->get_current_request_uri();
            break;
        case 'user_agent':
            $subject = $this->plugin->get_user_agent();
            break;
        default:
            return false;
    }
    
    $result = false;
    // Realizamos la comparación usando el operador
    switch ($operator) {
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
            // stripos devuelve 0 (que es falsey en PHP) si la cadena empieza, así que la comparación debe ser estricta.
            $result = stripos($subject, $value) === 0;
            break;
        case 'ends_with':
            $length = strlen($value);
            if ($length == 0) {
                $result = true;
            } else {
                // Usamos substr_compare para una comparación case-insensitive del final de la cadena.
                $result = substr_compare($subject, $value, -$length, $length, true) === 0;
            }
            break;
        case 'matches_regex':
            // Añadimos supresión de errores por si la regex es inválida
            $result = @preg_match('/' . $value . '/i', $subject) === 1;
            break;
    }
    return $result;
}

/**
 * Ejecuta la acción definida en una regla.
 *
 * @param array $rule La regla completa que ha coincidido.
 * @param string $ip La IP del visitante.
 * @return bool True si la acción termina la petición.
 */
private function execute_action($rule, $ip) {
    $action = $rule['action'];
    $params = $rule['action_params'] ?? [];
    $rule_name = $rule['name'] ?? 'Untitled Rule';

    // Preparamos los datos de log comunes para todas las acciones
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
            'info' // Es un evento informativo, no una amenaza
            );
            
            // Set global allow flag to bypass subsequent checks (e.g. AbuseIPDB)
            $this->plugin->is_advanced_rule_allowed = true;

            // Devolvemos true para indicar a run_all_block_checks que debe detenerse.
            return true;
        case 'block':
            // La duración viene en minutos desde la UI. 0 para permanente.
            $duration_minutes = isset($params['duration']) ? (int) $params['duration'] : 0;
            $duration_seconds = ($duration_minutes > 0) ? $duration_minutes * 60 : 0;
            
            /* translators: %s: The name of the custom rule. */
            $reason = sprintf(__('Blocked by Advanced Rule: %s', 'advanced-ip-blocker'), $rule_name);
            
            // Llamamos a block_ip_instantly
            $this->plugin->block_ip_instantly($ip, 'advanced_rule', $reason, $log_data, 'frontend_block', $duration_seconds);
            return true; // block_ip_instantly ya hace exit()

        case 'challenge':
            $this->plugin->log_specific_error(
                'advanced_rule', // Usamos el tipo base y el nivel lo diferencia
                $ip,
                $log_data,
                'warning' // Nivel 'warning' porque no es un bloqueo, es un desafío
            );
            $this->plugin->js_challenge_manager->serve_challenge('advanced_rule');
            return true; // serve_js_challenge ya hace exit()

        case 'score':
            $points = isset($params['points']) ? (int)$params['points'] : 10;
            $log_data['points_added'] = $points;
            
            $this->plugin->log_specific_error(
                'advanced_rule', // Usamos el tipo base y el nivel lo diferencia
                $ip,
                $log_data,
                'info' // Nivel 'info' ya que solo es una suma de puntos.
            );
            
            $this->plugin->threat_score_manager->increment_score($ip, $points, 'advanced_rule', ['rule_name' => $rule_name]);
            return false;

        default:
            return false;
    }
  }

}