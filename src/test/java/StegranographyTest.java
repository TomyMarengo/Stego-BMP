import ar.edu.itba.cripto.Steganography;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class StegranographyTest {
    private final Path inputFile = Paths.get("src", "main", "resources", "messages", "hello.txt");
    private final Path coverFile = Paths.get("src", "main", "resources", "covers", "all_gray.bmp");

    @ParameterizedTest
    @MethodSource("provideParameters")
    public void testEmbedAndExtract(String steg, boolean encrypt, String algorithm, String mode) throws IOException {
        Path stegoFile;
        Path extractedFile;

        if (encrypt) {
            stegoFile = Paths.get("src", "main", "resources", "outputs", "all_gray-" + steg + "-" + algorithm + "-" + mode + ".bmp");
            extractedFile = Paths.get("src", "main", "resources", "extracted", "extracted-hello-" + steg + "-" + algorithm + "-" + mode);
        } else {
            stegoFile = Paths.get("src", "main", "resources", "outputs", "all_gray-" + steg + ".bmp");
            extractedFile = Paths.get("src", "main", "resources", "extracted", "extracted-hello-" + steg);
        }

        // Embed the file
        String[] embedParams;
        if (encrypt) {
            embedParams = new String[]{"-embed", "-in", inputFile.toString(), "-p", coverFile.toString(), "-out", stegoFile.toString(), "-steg", steg, "-a", algorithm, "-m", mode, "-pass", "hola"};
        } else {
            embedParams = new String[]{"-embed", "-in", inputFile.toString(), "-p", coverFile.toString(), "-out", stegoFile.toString(), "-steg", steg};
        }
        Steganography.main(embedParams);

        // Extract the file
        String[] extractParams;
        if (encrypt) {
            extractParams = new String[]{"-extract", "-p", stegoFile.toString(), "-out", extractedFile.toString(), "-steg", steg, "-a", algorithm, "-m", mode, "-pass", "hola"};
        } else {
            extractParams = new String[]{"-extract", "-p", stegoFile.toString(), "-out", extractedFile.toString(), "-steg", steg};
        }
        Steganography.main(extractParams);

        // Read the original and extracted files
        byte[] originalContent = Files.readAllBytes(inputFile);
        byte[] extractedContent = Files.readAllBytes(Path.of(extractedFile + ".txt"));

        // Compare the contents
        assertArrayEquals(originalContent, extractedContent, "The extracted content does not match the original content.");
    }

    private static Stream<Object[]> provideParameters() {
        return Stream.of(
                new Object[]{"LSB1", false, null, null},
                new Object[]{"LSB1", true, "aes128", "ecb"},
                new Object[]{"LSB1", true, "aes192", "cfb"},
                new Object[]{"LSB1", true, "aes256", "ofb"},
                new Object[]{"LSB1", true, "des", "cbc"},
                new Object[]{"LSB4", false, null, null},
                new Object[]{"LSB4", true, "aes128", "ecb"},
                new Object[]{"LSB4", true, "aes192", "cfb"},
                new Object[]{"LSB4", true, "aes256", "ofb"},
                new Object[]{"LSB4", true, "des", "cbc"},
                new Object[]{"LSBI", false, null, null},
                new Object[]{"LSBI", true, "aes128", "ecb"},
                new Object[]{"LSBI", true, "aes192", "cfb"},
                new Object[]{"LSBI", true, "aes256", "ofb"},
                new Object[]{"LSBI", true, "des", "cbc"}
        );
    }
}
