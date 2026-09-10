1. Ejercicio 1 - Inyección SQL (SQLi).

 - Donde: app.py, funcion buscar_funciones
 - Como se explota: le estamos pasando directo el input del usuario como un comando sql
    esto provoca que se pueda utilizar setencias como "' OR 1=1 --" y esto devolveria todas las peliculas
 - Como solucionarlo: utilizar consultas parametrizadas en lugar de mandar directamente
    lo que envia el usuario, utilizando ? en lugar de la query directamente


2. Ejercicio 2 - Cross Site Scripting (XSS).

    - Donde: edit.html, en la descripcion de la pelicula
    - Como se explota: en la descripcion se usa un "safe", 
    "{{ pelicula['descripcion'] | safe }}", lo que esto significa es "no escapes este contenido, tratálo como HTML", lo que causa que al ingresar, por ejemplo, "<script>alert('XSS')</script>" en la descripcion, la proxima vez que alguien le de al boton de edit de esa pelicula, se va a ejecutar el script y se va a mostrar un alert
    - Como solucionarlo: para solucionarlo bastaria con eliminar el safe y que quede {{ pelicula['descripcion'] }}


3. Ejercicio 3 - File Upload.

    - Donde: PeliculaController.java, en la función uploadFile().

    - Como se explota: la aplicación permite subir archivos sin verificar que realmente sean imágenes. Para comprobarlo se creó un archivo de texto con contenido cualquiera y se cambió su extensión a ".jpg". El archivo fue aceptado por la aplicación como si fuera un afiche válido.

    - Como solucionarlo: validar en el servidor que el archivo sea realmente una imagen, verificando su contenido y tipo MIME, además de controlar las extensiones permitidas y el tamaño máximo del archivo.


4. Ejercicio 4 - Server Side Template Injection.

    - Donde: SpelEvaluator.java, en la función evaluate(), al procesar el parámetro buscar recibido por el usuario.

    - Como se explota: el valor ingresado por el usuario se pasa directamente a SpelExpressionParser y se evalúa como una expresión SpEL. Por ejemplo, al ingresar "7 * 7" en el buscador, la aplicación devuelve "49", demostrando que el servidor está interpretando el input como una expresión en lugar de tratarlo como texto.

    - Como solucionarlo: no evaluar directamente datos proporcionados por el usuario como expresiones SpEL. Si se necesita utilizar expresiones, se debería restringir estrictamente qué expresiones pueden ejecutarse y utilizar un contexto de evaluación con los permisos mínimos necesarios.


5. Ejercicio 5 - Almacenamiento inseguro.

   - Donde: AuthController.java y EncryptionService.java, al registrar y almacenar las contraseñas.

   - Como se explota: las contraseñas se almacenan utilizando un cifrado reversible AES. Además, la clave utilizada para cifrarlas está escrita directamente en el código fuente. Esto permite que una persona que tenga acceso al código obtenga la clave y pueda descifrar las contraseñas almacenadas.

   - Como solucionarlo: no se deberían almacenar las contraseñas mediante cifrado reversible. Se debe utilizar un algoritmo de hashing como BCrypt, que permite verificar la contraseña sin necesidad de recuperar su valor original. También se elimina la clave estática y el uso de EncryptionService.
