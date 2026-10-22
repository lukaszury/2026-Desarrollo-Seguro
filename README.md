# 2026-Desarrollo-Seguro

**Autor:** Lucas Cordero
**Ramas:** `main` (código vulnerable, sin modificar) / `practico-2` (mitigaciones del Práctico 2 + pruebas de regresión del Práctico 4)

Este README documenta cómo correr las pruebas automatizadas de seguridad pedidas en **Práctica 4**. El informe de hallazgos y PoCs del Práctico 2 está en [`Practico2.md`](Practico2.md) (rama `practico-2`).

## Resumen de qué se implementó

Según la Fe de Erratas de la consigna de Práctica 4: ítem 3 = File Upload en el Ejercicio3, ítem 4 = SSTI en el Ejercicio4 (coincide con la consigna de Práctico 2 y con el código real de este repositorio).

| # | Ejercicio | Vulnerabilidad | Tipo de prueba | Tecnología | Ubicación |
|---|---|---|---|---|---|
| 1 | Ejercicio1 | SQL Injection | Unitaria | Pytest | `Ejercicio1/tests/test_sqli.py` |
| 2 | Ejercicio2 | Cross-Site Scripting (XSS) | Unitaria | Pytest | `Ejercicio2/tests/test_xss.py` |
| 3 | Ejercicio3 | File Upload inseguro | Integración | Pytest + requests | `Ejercicio3/tests/test_file_upload_integration.py` |
| 4 | Ejercicio4 | SSTI (SpEL Injection) | Integración | Pytest + requests | `Ejercicio4/tests/test_ssti_rce_integration.py` |
| 5 | Ejercicio5 | Almacenamiento inseguro | Unitaria | JUnit 5 + Spring Boot Test | `Ejercicio5/src/test/java/com/cinebuscador/AlmacenamientoInseguroTest.java` |

`Ejercicio4/tests/test_ssti_rce_integration.py` incluye además un segundo test (`test_rce_no_permite_invocar_clases_java_arbitrarias`) que **no es un ítem pedido por la consigna actual**: queda como prueba extra que demuestra que el mismo SpEL Injection que causa el SSTI (ítem 4) también permite invocar clases Java arbitrarias vía `T(...)` — la vía real hacia Remote Code Execution (por ejemplo, `Runtime.exec(...)`) — útil para la defensa oral aunque no sea una entrega obligatoria.

Todas las pruebas están pensadas para correr igual en ambas ramas: **deben fallar en `main`** (código vulnerable) **y pasar en `practico-2`** (código mitigado).

---

## 1. Ejercicio1 — SQL Injection (Pytest, unitaria)

No necesita Docker ni el servidor levantado: la prueba carga `app.py` directamente y usa una base SQLite temporal propia.

```bash
cd Ejercicio1
pip install -r requirements.txt -r tests/requirements.txt
pytest tests/ -v
```

## 2. Ejercicio2 — Cross-Site Scripting (Pytest, unitaria)

Tampoco necesita Docker: usa el test client de Flask contra una base SQLite temporal.

```bash
cd Ejercicio2
pip install -r requirements.txt -r tests/requirements.txt
pytest tests/ -v
```

## 3. Ejercicio3 — File Upload inseguro (Pytest + requests, integración)

Necesita el ambiente dockerizado levantado (hace requests HTTP reales a `http://localhost:8080`):

```bash
cd Ejercicio3
docker compose up -d --build
pip install -r tests/requirements.txt
pytest tests/ -v
docker compose down
```

## 4. Ejercicio4 — SSTI vía SpEL Injection (Pytest + requests, integración)

También necesita el ambiente dockerizado levantado:

```bash
cd Ejercicio4
docker compose up -d --build
pip install -r tests/requirements.txt
pytest tests/ -v
docker compose down
```

## 5. Ejercicio5 — Almacenamiento inseguro (JUnit 5, unitaria)

No necesita Docker: usa un contexto de Spring Boot con base de datos H2 embebida en memoria.

```bash
cd Ejercicio5
mvn test
```

---

## Correr todo de una (en una máquina con Docker, Python y Maven disponibles)

```bash
# Unitarias (no requieren Docker)
(cd Ejercicio1 && pip install -r requirements.txt -r tests/requirements.txt && pytest tests/ -v)
(cd Ejercicio2 && pip install -r requirements.txt -r tests/requirements.txt && pytest tests/ -v)
(cd Ejercicio5 && mvn test)

# Integración (requieren Docker)
(cd Ejercicio3 && docker compose up -d --build && pip install -r tests/requirements.txt && pytest tests/ -v; docker compose down)
(cd Ejercicio4 && docker compose up -d --build && pip install -r tests/requirements.txt && pytest tests/ -v; docker compose down)
```

Repetir todo el bloque anterior parado en la rama `main` y en la rama `practico-2` para verificar el comportamiento esperado: falla en `main`, pasa en `practico-2`.
