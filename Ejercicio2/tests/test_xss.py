"""
Pruebas de regresión de seguridad — Ejercicio2 (Cross-Site Scripting / XSS).

Vulnerabilidad original (ver Práctico 2): en `templates/edit.html`, la
descripción de la película guardada por el usuario se renderiza con el
filtro `| safe` de Jinja2, que desactiva el auto-escapado:

    {{ pelicula['descripcion'] | safe }}

Esto permite XSS almacenado: cualquier HTML/JS guardado vía
`POST /edit/<id>` se ejecuta tal cual al volver a abrir esa página.

Mitigación (rama practico-2): se saca el filtro `| safe`, quedando el
auto-escapado por defecto de Jinja2 activo:

    {{ pelicula['descripcion'] }}

Estas pruebas deben FALLAR en la rama `main` (vulnerable) y PASAR en la
rama `practico-2` (mitigada).

Ejecutar con: pytest (parado en la carpeta Ejercicio2/)
"""
import pytest

PAYLOADS = [
    pytest.param("<script>alert(1)</script>", id="script_tag"),
    pytest.param('<img src=x onerror=alert(document.cookie)>', id="img_onerror"),
]


@pytest.mark.parametrize("payload", PAYLOADS)
def test_descripcion_editada_no_se_renderiza_sin_escapar(client, payload):
    """Guarda un payload de XSS en la descripción vía POST /edit/1 y
    verifica que, al releer la página de edición, el HTML/JS inyectado NO
    aparezca sin escapar en la respuesta.
    """
    post_resp = client.post(
        "/edit/1",
        data={
            "nombre": "Dune: Parte Dos",
            "genero": "Ciencia Ficcion",
            "director": "Denis Villeneuve",
            "descripcion": payload,
        },
        follow_redirects=True,
    )
    assert post_resp.status_code == 200

    get_resp = client.get("/edit/1")
    body = get_resp.get_data(as_text=True)

    assert payload not in body, (
        f"El payload {payload!r} aparece tal cual (sin escapar) en la "
        "respuesta HTML de /edit/1. Esto significa que la descripción se "
        "está renderizando con el filtro '| safe' de Jinja2 (o equivalente), "
        "permitiendo que el HTML/JS inyectado se ejecute en el navegador."
    )

    # Con auto-escapado activo, Jinja2 debe haber convertido los caracteres
    # especiales a sus entidades HTML (por ejemplo '<' -> '&lt;').
    assert "&lt;" in body or "&amp;lt;" in body, (
        "No se encontró la versión escapada del payload en la respuesta; "
        "se esperaba encontrar '&lt;' en el HTML devuelto por /edit/1."
    )
