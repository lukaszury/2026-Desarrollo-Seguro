package com.cinebuscador.config;

import org.springframework.stereotype.Component;

/**
 * Antes, este componente tomaba el texto de búsqueda ingresado por el usuario
 * y lo evaluaba directamente como una expresión SpEL con un
 * StandardEvaluationContext (que además exponía System y Runtime como
 * variables), permitiendo Server-Side Template Injection: cualquier
 * expresión SpEL enviada por el usuario ("7 * 7", o expresiones que invocan
 * métodos de Java) era ejecutada por el servidor.
 *
 * La búsqueda de funciones no necesita evaluar expresiones: solo necesita el
 * texto tal cual lo escribió el usuario para hacer un "contains". Por lo
 * tanto la mitigación es no interpretar el input como código en absoluto:
 * se elimina el uso de SpelExpressionParser/StandardEvaluationContext sobre
 * datos no confiables y se devuelve el texto recibido, normalizado.
 *
 * Si en algún momento se necesitara evaluar expresiones dinámicas reales,
 * se debería usar SimpleEvaluationContext (sin acceso a tipos, reflexión ni
 * constructores) en lugar de StandardEvaluationContext, y nunca pasarle una
 * expresión construida a partir de input del usuario sin una whitelist
 * estricta de expresiones permitidas.
 */
@Component
public class SpelEvaluator {

    public String evaluate(String expression) {
        if (expression == null || expression.isBlank()) {
            return "";
        }
        return expression.trim();
    }
}
