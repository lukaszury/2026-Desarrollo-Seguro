"""
Pruebas de regresión de seguridad — Ejercicio1 (SQL Injection).

Vulnerabilidad original (ver Práctico 2): `buscar_funciones()` arma la
consulta SQL concatenando directamente el parámetro `buscar` recibido por la
URL dentro de un `LIKE '%...%'`:

    sql = f"... WHERE peliculas.nombre LIKE '%{query}%' ..."
    return db.execute(sql).fetchall()

Mitigación (rama practico-2): el valor se pasa como parámetro ligado (`?`)
en vez de interpolarse en el string:

    sql = f"... WHERE peliculas.nombre LIKE ? ..."
    return db.execute(sql, (f'%{query}%',)).fetchall()

Estas pruebas deben FALLAR en la rama `main` (vulnerable) y PASAR en la
rama `practico-2` (mitigada).

Ejecutar con: pytest (parado en la carpeta Ejercicio1/)
"""


def test_sqli_boolean_bypass_no_devuelve_todas_las_peliculas(buscar_funciones):
    """Payload clásico de bypass booleano con comentario SQL.

    Si el input se concatena sin sanitizar, el payload cierra la comilla del
    LIKE, agrega una condición `OR '1'='1'` siempre verdadera, y comenta
    (`--`) el resto de la consulta (incluido el `%'` de cierre y el ORDER
    BY), devolviendo TODAS las funciones sin importar el texto buscado.

    Con la consulta parametrizada, todo el payload se trata como un único
    valor literal de búsqueda, que no matchea ninguna película real, y la
    búsqueda debe devolver 0 resultados.
    """
    payload = "pelicula_inexistente' OR '1'='1' -- "

    resultados = buscar_funciones(payload)

    assert len(resultados) == 0, (
        "La búsqueda con el payload de SQL Injection devolvió "
        f"{len(resultados)} resultado(s) en vez de 0: la consulta está "
        "evaluando la condición inyectada 'OR 1=1' en lugar de tratar el "
        "payload completo como texto literal de búsqueda."
    )


def test_busqueda_con_comilla_simple_no_rompe_la_consulta(buscar_funciones):
    """Un apóstrofe en el término de búsqueda no debe causar un error SQL.

    Con concatenación de strings, una comilla simple sin escapar rompe la
    sintaxis de la sentencia SQL (sqlite3.OperationalError: "near ...:
    syntax error"). Con parámetros ligados, el driver se encarga de
    escaparla correctamente y la búsqueda funciona con normalidad.
    """
    resultados = buscar_funciones("D'Artagnan")

    nombres = [fila["pelicula"] for fila in resultados]
    assert nombres == ["D'Artagnan's Adventure"], (
        "La búsqueda de un término con comilla simple no devolvió el "
        f"resultado esperado (se obtuvo: {nombres!r}). Si esto lanzó una "
        "excepción en lugar de llegar a este assert, es porque la comilla "
        "rompió la sentencia SQL armada por concatenación de strings."
    )
