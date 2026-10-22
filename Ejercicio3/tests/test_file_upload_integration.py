"""
Pruebas de integración de regresión de seguridad — Ejercicio3 (File Upload
inseguro).

Cubre el ítem 3 de la Fe de Erratas de la consigna de Práctica 4 ("Pruebas
de Integración que validen la mitigación del File Upload en el ejercicio
3"), que coincide con la consigna de Práctico 2 y con el código real de
este repositorio.

Vulnerabilidad original (ver Práctico 2), en PeliculaController.uploadFile()
(rama main):
  - No valida el contenido real del archivo: cualquier archivo, sea o no una
    imagen, se acepta si el formulario lo envía.
  - No valida la extensión ni el Content-Type.
  - Guarda el archivo usando el nombre original tal cual llega del cliente
    (`uploadPath.resolve(filename)`), lo que permite path traversal si el
    nombre contiene segmentos "..".

Mitigación (rama practico-2):
  - Valida que el contenido decodifique como imagen real (ImageIO.read).
  - Valida extensión (whitelist jpg/jpeg/png/webp) y Content-Type declarado.
  - Nunca usa el nombre original para guardar: genera un nombre con UUID.

Estas pruebas deben FALLAR contra la rama `main` y PASAR contra la rama
`practico-2`, ambas corriendo en el ambiente dockerizado del Ejercicio3
(docker compose up, puerto 8080).

Ejecutar con: pytest (parado en la carpeta Ejercicio3/, con el contenedor
del ejercicio corriendo)
"""
import requests

PELICULA_ID = 1  # "Inception" en el data.sql de este ejercicio


def test_rechaza_archivo_que_no_es_una_imagen_real(base_url):
    """Un archivo de texto plano disfrazado de .jpg no debe aceptarse.

    main: no valida el contenido real (magic bytes) -> lo acepta (sigue el
    flujo normal, redirect 302 a "/").
    practico-2: ImageIO no puede decodificarlo como imagen -> 400 Bad Request.
    """
    archivo_falso = b"Esto no es una imagen, es texto plano disfrazado de .jpg"

    resp = requests.post(
        f"{base_url}/upload/{PELICULA_ID}",
        files={"afiche": ("afiche_falso.jpg", archivo_falso, "image/jpeg")},
        allow_redirects=False,
        timeout=10,
    )

    assert resp.status_code == 400, (
        "Se esperaba 400 Bad Request al subir un archivo que no es una "
        f"imagen real disfrazado de .jpg, pero se obtuvo {resp.status_code}. "
        "El servidor está aceptando el archivo sin validar su contenido "
        "real (magic bytes)."
    )


def test_rechaza_extension_no_permitida(base_url, imagen_real_png):
    """Un archivo con extensión fuera de la whitelist no debe aceptarse,
    aunque su Content-Type declarado sea de imagen.

    main: no valida extensión -> lo acepta.
    practico-2: extensión ".php" no está en la whitelist (jpg/jpeg/png/webp)
    -> 400 Bad Request.
    """
    resp = requests.post(
        f"{base_url}/upload/{PELICULA_ID}",
        files={"afiche": ("shell.php", imagen_real_png, "image/jpeg")},
        allow_redirects=False,
        timeout=10,
    )

    assert resp.status_code == 400, (
        "Se esperaba 400 Bad Request al subir un archivo con extensión "
        f".php, pero se obtuvo {resp.status_code}. El servidor está "
        "aceptando extensiones fuera de la whitelist permitida."
    )


def test_no_usa_el_nombre_original_del_archivo_para_guardarlo(base_url, imagen_real_png):
    """El nombre con el que se guarda/sirve el archivo no debe depender del
    nombre original enviado por el cliente (evita path traversal tipo
    "../archivo.png" y filtra cualquier rastro de ese nombre en la UI).

    main: guarda y expone el archivo con el nombre original tal cual
    (`pelicula.setAfichePath(filename)`), así que el nombre elegido por el
    atacante queda visible en el HTML de la página de resultados.
    practico-2: siempre genera un nombre nuevo con UUID, por lo que el
    nombre original nunca aparece en la respuesta.
    """
    nombre_malicioso = "marca_de_ataque_evil"
    filename_enviado = f"../{nombre_malicioso}.png"

    upload_resp = requests.post(
        f"{base_url}/upload/{PELICULA_ID}",
        files={"afiche": (filename_enviado, imagen_real_png, "image/png")},
        allow_redirects=False,
        timeout=10,
    )
    assert upload_resp.status_code in (200, 302, 303), (
        "La subida con una imagen válida (pero con nombre de archivo con "
        f"path traversal) debería aceptarse igual; status recibido: "
        f"{upload_resp.status_code}"
    )

    listado_resp = requests.get(f"{base_url}/", params={"buscar": "Inception"}, timeout=10)
    assert nombre_malicioso not in listado_resp.text, (
        f"El nombre de archivo original ('{filename_enviado}') aparece tal "
        "cual en la página de resultados. Esto significa que el servidor "
        "está usando el nombre provisto por el cliente para guardar/servir "
        "el archivo, en lugar de generar un nombre propio (por ejemplo, un "
        "UUID), lo que habilita path traversal."
    )
