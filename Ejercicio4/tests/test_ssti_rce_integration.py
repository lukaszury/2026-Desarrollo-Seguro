"""
Pruebas de integración de regresión de seguridad — Ejercicio4 (SpEL
Injection: Server Side Template Injection / Remote Code Execution).

Cubre el ítem 4 de la Fe de Erratas de la consigna de Práctica 4 ("Pruebas
de Integración que validen la mitigación del Server Side Template Injection
(SSTI) en el ejercicio 4"), que coincide con la consigna de Práctico 2 y con
el código real de este repositorio:
test_ssti_no_evalua_expresion_aritmetica() — el input del usuario se evalúa
como código/expresión SpEL en vez de tratarse como texto (se prueba con una
expresión aritmética inocua, 7*7).

Este archivo incluye además un segundo test,
test_rce_no_permite_invocar_clases_java_arbitrarias(), que NO es un ítem
pedido por la consigna actual (la Fe de Erratas eliminó el ítem de RCE como
punto separado). Se deja como prueba extra porque, en este código, el mismo
mecanismo de SSTI (SpEL injection con StandardEvaluationContext) permite
además invocar clases y métodos Java arbitrarios vía T(...) — la vía real
hacia Remote Code Execution (por ejemplo, Runtime.exec(...)) —, lo cual es
útil para explicar el impacto completo en la defensa oral.

Vulnerabilidad original (ver Práctico 2), en SpelEvaluator.evaluate()
(rama main):
    ExpressionParser parser = new SpelExpressionParser();
    StandardEvaluationContext standardContext = new StandardEvaluationContext();
    standardContext.setVariable("system", System.class);
    standardContext.setVariable("runtime", Runtime.class);
    var expr = parser.parseExpression(expression);
    Object result = expr.getValue(standardContext);

El texto de búsqueda (`buscar`) se evalúa directamente como expresión SpEL
con un StandardEvaluationContext, que permite reflexión completa y el
operador T(...) para invocar cualquier clase Java.

Mitigación (rama practico-2): se elimina por completo el parseo/evaluación
SpEL; el texto ingresado se usa tal cual, sin interpretarlo como código:
    return expression.trim();

Estas pruebas deben FALLAR contra la rama `main` y PASAR contra la rama
`practico-2`, ambas corriendo en el ambiente dockerizado del Ejercicio4
(docker compose up, puerto 8080).

Ejecutar con: pytest (parado en la carpeta Ejercicio4/, con el contenedor
del ejercicio corriendo)
"""
import re

import requests


def test_ssti_no_evalua_expresion_aritmetica(base_url):
    """Prueba de SSTI: una expresión aritmética SpEL no debe evaluarse.

    main: el mensaje de resultado contiene "49" (7*7 evaluado como código).
    practico-2: el mensaje contiene literalmente "7*7" (tratado como texto).
    """
    resp = requests.get(f"{base_url}/", params={"buscar": "7*7"}, timeout=10)
    assert resp.status_code == 200

    assert "Resultados buscando por: 49" not in resp.text, (
        "La respuesta contiene 'Resultados buscando por: 49': el texto de "
        "búsqueda '7*7' fue evaluado como una expresión SpEL (aritmética) "
        "en vez de tratarse como un string literal. Esto confirma SSTI."
    )
    assert "Resultados buscando por: 7*7" in resp.text, (
        "No se encontró el mensaje 'Resultados buscando por: 7*7' con el "
        "texto literal sin evaluar. El mensaje de resultado debería "
        "mostrar el término de búsqueda tal cual fue ingresado, sin "
        "interpretarlo como código."
    )


def test_rce_no_permite_invocar_clases_java_arbitrarias(base_url):
    """Prueba de RCE: una expresión SpEL que usa T(...) para invocar una
    API real de Java (lectura, no destructiva) no debe ejecutarse.

    Se usa `T(java.lang.Math).PI` como payload: si el StandardEvaluationContext
    sigue habilitado, SpEL lo evalúa y expone el valor real de Math.PI
    (3.14159...) en la respuesta. Se elige deliberadamente una operación de
    solo lectura (no `Runtime.exec`) para que la prueba sea segura de correr
    en un pipeline automatizado, pero que de todas formas demuestre acceso
    real a código Java arbitrario vía reflexión -- la misma vía que,
    sin mitigar, permite invocar Runtime.getRuntime().exec(...) y ejecutar
    comandos del sistema operativo.
    """
    payload = "T(java.lang.Math).PI"
    resp = requests.get(f"{base_url}/", params={"buscar": payload}, timeout=10)
    assert resp.status_code == 200

    pi_evaluado = re.search(r"Resultados buscando por:\s*3\.14159", resp.text)
    assert pi_evaluado is None, (
        "La respuesta contiene el valor evaluado de Math.PI "
        f"({pi_evaluado.group(0) if pi_evaluado else ''!r}): la expresión "
        f"SpEL {payload!r} fue evaluada, lo que confirma acceso a clases "
        "Java arbitrarias vía reflexión (T(...)). Esta misma vía permite "
        "invocar Runtime.getRuntime().exec(...) y ejecutar comandos del "
        "sistema operativo (RCE)."
    )
    assert f"Resultados buscando por: {payload}" in resp.text, (
        f"No se encontró el mensaje con el payload {payload!r} tal cual, "
        "sin evaluar. El texto de búsqueda debería tratarse siempre como "
        "string literal, nunca como código a ejecutar."
    )
