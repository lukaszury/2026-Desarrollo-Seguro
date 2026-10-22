"""
Fixtures compartidas para las pruebas de regresión de seguridad del Ejercicio2.

Cargan app.py/config.py del ejercicio de forma aislada y arman una base de
datos SQLite temporal con una película de prueba, para no depender del
cine2.db real del proyecto. Exponen un Flask test client real para poder
hacer requests HTTP de punta a punta (GET/POST) contra las rutas /, /edit/<id>.
"""
import importlib.util
import sqlite3
import sys
from pathlib import Path

import pytest

EJERCICIO_DIR = Path(__file__).resolve().parent.parent


def _load_module(name, filename):
    spec = importlib.util.spec_from_file_location(name, EJERCICIO_DIR / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _init_schema(db_path):
    conn = sqlite3.connect(db_path)
    conn.executescript(
        """
        CREATE TABLE peliculas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre TEXT NOT NULL,
            genero TEXT NOT NULL,
            director TEXT NOT NULL,
            descripcion TEXT
        );

        CREATE TABLE funciones (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pelicula_id INTEGER NOT NULL,
            fecha_hora TEXT NOT NULL,
            asientos_totales INTEGER NOT NULL DEFAULT 100,
            asientos_ocupados INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY(pelicula_id) REFERENCES peliculas(id)
        );
        """
    )
    conn.execute(
        "INSERT INTO peliculas (nombre, genero, director, descripcion) VALUES (?, ?, ?, ?)",
        ("Dune: Parte Dos", "Ciencia Ficcion", "Denis Villeneuve", "Descripcion original"),
    )
    conn.commit()
    conn.close()


@pytest.fixture
def client(tmp_path):
    """Flask test client del Ejercicio2, con una base de datos temporal y
    una única película (id=1) ya cargada."""
    config_module = _load_module("ejercicio2_config", "config.py")
    sys.modules["config"] = config_module

    app_module = _load_module("ejercicio2_app", "app.py")

    db_path = tmp_path / "cine2_test.db"
    _init_schema(str(db_path))
    app_module.app.config["DATABASE"] = str(db_path)
    app_module.app.config["TESTING"] = True

    with app_module.app.test_client() as test_client:
        yield test_client

    del sys.modules["ejercicio2_config"]
    del sys.modules["ejercicio2_app"]
    del sys.modules["config"]
