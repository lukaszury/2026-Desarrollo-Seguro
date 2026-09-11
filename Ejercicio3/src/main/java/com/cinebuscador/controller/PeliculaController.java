package com.cinebuscador.controller;

import com.cinebuscador.model.Pelicula;
import com.cinebuscador.repository.PeliculaRepository;
import jakarta.persistence.EntityNotFoundException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.MediaType;
import org.springframework.http.MediaTypeFactory;
import org.springframework.core.io.UrlResource;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

@Controller
public class PeliculaController {

    // Extensiones y tipos MIME aceptados para el afiche (whitelist)
    private static final Set<String> EXTENSIONES_PERMITIDAS = Set.of("jpg", "jpeg", "png", "webp");
    private static final Set<String> MIME_PERMITIDOS = Set.of("image/jpeg", "image/png", "image/webp");
    private static final long TAMANIO_MAXIMO_BYTES = 5L * 1024 * 1024; // 5 MB

    private final PeliculaRepository peliculaRepo;

    @Value("${app.upload-dir}")
    private String uploadDir;

    public PeliculaController(PeliculaRepository peliculaRepo) {
        this.peliculaRepo = peliculaRepo;
    }

    @GetMapping("/")
    public String index(@RequestParam(required = false) String buscar,
                        @RequestParam(required = false, defaultValue = "nombre") String ordenarPor,
                        @RequestParam(required = false, defaultValue = "ASC") String sentido,
                        Model model) {

        if (buscar != null && !buscar.isBlank()) {
            List<Object[]> resultadosRaw;
            if ("DESC".equalsIgnoreCase(sentido)) {
                resultadosRaw = peliculaRepo.searchWithFuncionesDesc(buscar, ordenarPor);
            } else {
                resultadosRaw = peliculaRepo.searchWithFunciones(buscar, ordenarPor);
            }

            // Wrap Object[] in Maps for cleaner Thymeleaf access
            List<Map<String, Object>> resultados = new java.util.ArrayList<>();
            for (Object[] row : resultadosRaw) {
                Map<String, Object> map = new HashMap<>();
                map.put("id",        row[0]);
                map.put("nombre",    row[1]);
                map.put("fechaHora", row[2]);
                map.put("disponibles", row[3]);
                map.put("descripcion", row[4]);
                map.put("afichePath", row[5]);
                resultados.add(map);
            }
            model.addAttribute("resultados", resultados);
        }

        model.addAttribute("query", buscar != null ? buscar : "");
        model.addAttribute("sort_by", ordenarPor);
        model.addAttribute("sort_dir", sentido);
        return "index";
    }

    @GetMapping("/upload/{id}")
    public String uploadForm(@PathVariable Integer id, Model model) {
        Pelicula pelicula = peliculaRepo.findById(id)
            .orElseThrow(() -> new EntityNotFoundException("Pelicula no encontrada"));
        model.addAttribute("pelicula", pelicula);
        return "upload";
    }

    @PostMapping("/upload/{id}")
    public String uploadFile(@PathVariable Integer id,
                             @RequestParam("afiche") MultipartFile archivo) throws IOException {
        Pelicula pelicula = peliculaRepo.findById(id)
            .orElseThrow(() -> new EntityNotFoundException("Pelicula no encontrada"));

        if (archivo.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "El archivo esta vacio");
        }

        // 1) Tamaño máximo
        if (archivo.getSize() > TAMANIO_MAXIMO_BYTES) {
            throw new ResponseStatusException(HttpStatus.PAYLOAD_TOO_LARGE,
                "El archivo supera el tamaño máximo permitido (5 MB)");
        }

        // 2) Extensión permitida (a partir del nombre original, solo para obtener la extensión)
        String originalFilename = archivo.getOriginalFilename();
        String extension = extraerExtension(originalFilename);
        if (extension == null || !EXTENSIONES_PERMITIDAS.contains(extension.toLowerCase())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                "Extensión de archivo no permitida. Solo se aceptan: " + EXTENSIONES_PERMITIDAS);
        }

        // 3) Tipo MIME declarado por el cliente (fácil de falsificar, pero se suma como capa extra)
        String contentType = archivo.getContentType();
        if (contentType == null || !MIME_PERMITIDOS.contains(contentType.toLowerCase())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                "Tipo de archivo no permitido");
        }

        // 4) Validación real de contenido: el archivo debe poder decodificarse como imagen.
        //    Esto es lo que detecta un .txt renombrado a .jpg, ya que ImageIO lee los
        //    "magic bytes" del archivo y no confía en la extensión ni en el Content-Type.
        BufferedImage imagen;
        try (InputStream in = archivo.getInputStream()) {
            imagen = ImageIO.read(in);
        }
        if (imagen == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                "El archivo no es una imagen válida");
        }

        Path uploadPath = Paths.get(uploadDir);
        if (!Files.exists(uploadPath)) {
            Files.createDirectories(uploadPath);
        }

        // 5) Nunca usar el nombre original para guardar el archivo: evita path traversal
        //    (p. ej. "../../etc/passwd.jpg") y colisiones/sobrescritura entre usuarios.
        String nombreSeguro = UUID.randomUUID() + "." + extension.toLowerCase();
        Files.copy(archivo.getInputStream(), uploadPath.resolve(nombreSeguro));

        pelicula.setAfichePath(nombreSeguro);
        peliculaRepo.save(pelicula);

        return "redirect:/";
    }

    private String extraerExtension(String filename) {
        if (filename == null) {
            return null;
        }
        // Nos quedamos solo con el nombre de archivo, descartando cualquier ruta
        String soloNombre = Paths.get(filename).getFileName().toString();
        int idx = soloNombre.lastIndexOf('.');
        if (idx < 0 || idx == soloNombre.length() - 1) {
            return null;
        }
        return soloNombre.substring(idx + 1);
    }

    @GetMapping("/uploads/{filename:.+}")
    @ResponseBody
    public ResponseEntity<Resource> serveFile(@PathVariable String filename) throws IOException {
        Path filePath = Paths.get(uploadDir).resolve(filename).normalize();
        Resource resource = new UrlResource(filePath.toUri());
        MediaType mediaType = MediaTypeFactory.getMediaType(resource)
        .orElse(MediaType.APPLICATION_OCTET_STREAM);

        if (!resource.exists()) {
            return ResponseEntity.notFound().build();
        }

        return ResponseEntity.ok()
            .contentType(mediaType)
            .header(HttpHeaders.CONTENT_DISPOSITION, "inline; filename=\"" + resource.getFilename() + "\"")
            .body(resource);
    }

}