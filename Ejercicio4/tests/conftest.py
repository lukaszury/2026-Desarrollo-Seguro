import pytest
import requests

BASE_URL = "http://localhost:8080"


@pytest.fixture(scope="session")
def base_url():
    try:
        requests.get(BASE_URL + "/", timeout=5)
    except requests.exceptions.ConnectionError as exc:
        pytest.skip(
            "No se pudo conectar a "
            f"{BASE_URL}. Levantá el ambiente dockerizado del Ejercicio4 "
            "primero (docker compose up -d --build) antes de correr estas "
            f"pruebas de integración. Detalle: {exc}"
        )
    return BASE_URL
