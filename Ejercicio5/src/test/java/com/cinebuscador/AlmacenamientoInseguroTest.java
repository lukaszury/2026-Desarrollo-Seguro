package com.cinebuscador;

import com.cinebuscador.model.User;
import com.cinebuscador.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Pruebas de regresion de seguridad - Ejercicio5 (Almacenamiento inseguro de contrasenas).
 *
 * Vulnerabilidad original (ver Practico 2): AuthController guardaba la contrasena
 * cifrada (no hasheada) con EncryptionService, que usaba AES-256 en modo ECB con
 * una clave estatica embebida en el codigo fuente:
 *
 *   private static final String SECRET_KEY = "MySup3rS3cr3tK3y!2024CineBuscadorAES";
 *   private static final String CIPHER_ALGO = "AES/ECB/PKCS5Padding";
 *
 * Esto es inseguro por dos motivos, que son justamente los que validan estas pruebas:
 *   1. Es reversible: cualquiera que tenga el codigo fuente (o la clave) puede
 *      descifrar cualquier contrasena almacenada.
 *   2. ECB es determinista y no usa IV/salt: dos usuarios con la misma contrasena
 *      quedan con exactamente el mismo valor almacenado en la base de datos.
 *
 * Mitigacion (rama practico-2): se elimina EncryptionService por completo y se
 * reemplaza por BCryptPasswordEncoder (hash con salt aleatorio, no reversible).
 *
 * Estas pruebas deben FALLAR en la rama main (vulnerable) y PASAR en la rama
 * practico-2 (mitigada). No referencian la clase EncryptionService directamente
 * (fue eliminada en practico-2); el intento de descifrado AES se reimplementa
 * aqui mismo, a partir de la clave que figuraba hardcodeada en el codigo fuente
 * original, para que el test compile y corra igual en ambas ramas.
 *
 * Ejecutar con: mvn test (parado en la carpeta Ejercicio5/)
 */
@SpringBootTest
@AutoConfigureMockMvc
class AlmacenamientoInseguroTest {

    // Clave estatica que figuraba hardcodeada en EncryptionService.java (rama main).
    // Se reproduce aqui unicamente para probar que, tras la mitigacion, YA NO
    // permite recuperar la contrasena original.
    private static final String CLAVE_HISTORICA_HARDCODEADA = "MySup3rS3cr3tK3y!2024CineBuscadorAES";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Test
    void mismaContrasenaEnDosUsuarios_noDebeQuedarAlmacenadaIgual() throws Exception {
        String passwordPlano = "CineBuscador2026!";

        registrar("usuarioA_" + System.nanoTime(), passwordPlano);
        registrar("usuarioB_" + System.nanoTime(), passwordPlano);

        User usuarioA = buscarUltimoRegistrado("usuarioA");
        User usuarioB = buscarUltimoRegistrado("usuarioB");

        assertNotEquals(
            usuarioA.getPassword(),
            usuarioB.getPassword(),
            "Dos usuarios distintos que se registraron con la MISMA contrasena "
          + "quedaron con el MISMO valor almacenado en la base de datos. Esto "
          + "indica que el almacenamiento es determinista (por ejemplo, cifrado "
          + "AES en modo ECB sin IV/salt) en lugar de usar un hash con salt "
          + "aleatorio por usuario (por ejemplo BCrypt)."
        );
    }

    @Test
    void contrasenaAlmacenada_noDebeSerReversibleConLaClaveHistoricaHardcodeada() throws Exception {
        String passwordPlano = "OtraClaveDePrueba#2026";
        String username = "usuarioC_" + System.nanoTime();

        registrar(username, passwordPlano);
        User usuario = userRepository.findByUsername(username).orElseThrow();
        String valorAlmacenado = usuario.getPassword();

        String valorDescifrado = intentarDescifrarAesEcb(valorAlmacenado, CLAVE_HISTORICA_HARDCODEADA);

        assertNotEquals(
            passwordPlano,
            valorDescifrado,
            "Se pudo recuperar la contrasena en texto plano descifrando el valor "
          + "almacenado con AES/ECB y la clave estatica que figuraba hardcodeada "
          + "en el codigo fuente. El almacenamiento de contrasenas debe ser "
          + "irreversible (hash), no cifrado reversible con una clave fija."
        );

        // Ademas, el valor almacenado no debe ser ni siquiera un Base64 valido de
        // 32 bytes (bloque AES), como lo era con EncryptionService: un hash
        // BCrypt tiene el formato "$2a$10$..." y no decodifica a un multiplo de
        // 16 bytes como exige un cifrado por bloques.
        assertTrue(
            noPareceCiphertextAesValido(valorAlmacenado),
            "El valor almacenado tiene la forma de un ciphertext AES/ECB valido "
          + "(Base64 cuyo largo decodificado es multiplo del tamano de bloque), "
          + "en vez de tener el formato de un hash (por ejemplo BCrypt)."
        );
    }

    private void registrar(String username, String password) throws Exception {
        mockMvc.perform(post("/register")
                .param("username", username)
                .param("password", password)
                .param("confirmPwd", password))
            .andExpect(status().isOk());
    }

    private User buscarUltimoRegistrado(String prefijoUsername) {
        return userRepository.findAll().stream()
            .filter(u -> u.getUsername().startsWith(prefijoUsername))
            .reduce((primero, segundo) -> segundo) // el mas reciente insertado
            .orElseThrow();
    }

    /**
     * Reimplementacion standalone (no importa EncryptionService, que fue borrado
     * en practico-2) del descifrado AES/ECB con padding-a-32-bytes que usaba el
     * codigo vulnerable original. Si el valor almacenado no es un ciphertext AES
     * valido para esta clave (porque ahora es un hash BCrypt), se captura la
     * excepcion y se devuelve un string que nunca podria coincidir con una
     * contrasena real.
     */
    private static String intentarDescifrarAesEcb(String valorAlmacenadoBase64, String claveTexto) {
        try {
            byte[] keyBytes = claveTexto.getBytes(StandardCharsets.UTF_8);
            byte[] key32 = new byte[32];
            System.arraycopy(keyBytes, 0, key32, 0, Math.min(keyBytes.length, 32));
            SecretKeySpec secretKey = new SecretKeySpec(key32, "AES");

            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] decoded = Base64.getDecoder().decode(valorAlmacenadoBase64);
            byte[] decrypted = cipher.doFinal(decoded);
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception noEsUnCiphertextAesValido) {
            return "<<no-reversible-con-esa-clave>>";
        }
    }

    private static boolean noPareceCiphertextAesValido(String valorAlmacenadoBase64) {
        try {
            byte[] decoded = Base64.getDecoder().decode(valorAlmacenadoBase64);
            return decoded.length == 0 || decoded.length % 16 != 0;
        } catch (IllegalArgumentException noEsBase64) {
            return true;
        }
    }
}
