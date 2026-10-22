"""
Fixtures compartidas para las pruebas de regresión de seguridad del Ejercicio1.

Cargan app.py/config.py del ejercicio de forma aislada (sin depender de que
el proyecto esté "instalado") y arman una base de datos SQLite temporal con
datos de prueba conocidos, para no depender del cine.db real del proyecto.
"""
import importlib.util
import sqlite3
import sys
from pathlib import Path

import pytest

EJERCICIO_DIR = Path(__file__).resolve().parent.parent


def _load_module(name, filename):
    """Carga un módulo .py por ruta de archivo, de forma aislada."""
    spec = importlib.util.spec_from_file_location(name, EJERCICIO_DIR / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _init_schema(db_path):
    """Crea el esquema y carga datos de prueba fijos y conocidos.

    Incluye deliberadamente una película cuyo nombre contiene un apóstrofe
    (comilla simple), ya que es el caso que rompe una consulta SQL construida
    por concatenación de strings.
    """
    conn = sqlite3.connect(db_path)
    conn.executescript(
        """
        CREATE TABLE peliculas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre TEXT NOT NULL,
            genero TEXT NOT NULL,
            director TEXT NOT NULL
        );

        CREATE TABLE funciones (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pelicula_id INTEGER NOT NULL,
            fecha_hora TEXT NOT NULL,
            asientos_totales INTEGER NOT NULL DEFAULT 100,
            asientos_ocupados INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (pelicula_id) REFERENCES peliculas(id)
        );
        """
    )
    conn.executemany(
        "INSERT INTO peliculas (nombre, genero, director) VALUES (?, ?, ?)",
        [
            ("Dune: Parte Dos", "Ciencia Ficcion", "Denis Villeneuve"),
            ("Oppenheimer", "Drama", "Christopher Nolan"),
            ("D'Artagnan's Adventure", "Aventura", "Anonimo"),
        ],
    )
    conn.executemany(
        "INSERT INTO funciones (pelicula_id, fecha_hora, asientos_totales, asientos_ocupados) "
        "VALUES (?, ?, ?, ?)",
        [
            (1, "2026-07-13 14:30:00", 120, 85),
            (2, "2026-07-13 16:00:00", 100, 92),
            (3, "2026-07-13 18:00:00", 90, 30),
        ],
    )
    conn.commit()
    conn.close()


@pytest.fixture
def buscar_funciones(tmp_path):
    """Devuelve la función buscar_funciones() del Ejercicio1 lista para usar,
    apuntando a una base de datos SQLite temporal con 3 películas conocidas.
    """
    # Se cargan config.py y app.py bajo nombres únicos para no chocar con los
    # módulos homónimos de otros ejercicios si se corriera todo en una sola
    # sesión de pytest.
    config_module = _load_module("ejercicio1_config", "config.py")
    sys.modules["config"] = config_module  # app.py hace "from config import Config"

    app_module = _load_module("ejercicio1_app", "app.py")

    db_path = tmp_path / "cine_test.db"
    _init_schema(str(db_path))
    app_module.app.config["DATABASE"] = str(db_path)

    with app_module.app.app_context():
        yield app_module.buscar_funciones

    del sys.modules["ejercicio1_config"]
    del sys.modules["ejercicio1_app"]
    del sys.modules["config"]
