import base64

import pytest
import requests

BASE_URL = "http://localhost:8080"

# PNG válido de 1x1 píxel transparente (67 bytes), usado como "imagen real"
# en los tests que necesitan pasar la validación de contenido.
PNG_1X1_BASE64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk"
    "+A8AAQUBAScY42YAAAAASUVORK5CYII="
)


@pytest.fixture(scope="session")
def base_url():
    try:
        requests.get(BASE_URL + "/", timeout=5)
    except requests.exceptions.ConnectionError as exc:
        pytest.skip(
            "No se pudo conectar a "
            f"{BASE_URL}. Levantá el ambiente dockerizado del Ejercicio3 "
            "primero (docker compose up -d --build) antes de correr estas "
            f"pruebas de integración. Detalle: {exc}"
        )
    return BASE_URL


@pytest.fixture
def imagen_real_png():
    """Bytes de un PNG válido de 1x1, para subir como archivo legítimo."""
    return base64.b64decode(PNG_1X1_BASE64)
