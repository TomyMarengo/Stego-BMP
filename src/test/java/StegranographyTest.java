import ar.edu.itba.cripto.Steganography;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class StegranographyTest {
    private final String bmpName = "tricolor";
    private final String messageName = "hello";
    private final Path inputFile = Paths.get("src", "main", "resources", "messages", messageName + ".txt");
    private final Path coverFile = Paths.get("src", "main", "resources", "covers", bmpName + ".bmp");

    @ParameterizedTest
    @MethodSource("provideParameters")
    public void testEmbedAndExtract(String steg, boolean encrypt, String algorithm, String mode) throws IOException {
        Path stegoFile;
        Path extractedFile;

        if (encrypt) {
            stegoFile = Paths.get("src", "main", "resources", "outputs", bmpName + "-" + steg + "-" + algorithm + "-" + mode + ".bmp");
            extractedFile = Paths.get("src", "main", "resources", "extracted", "extracted-" + messageName + "-" + steg + "-" + algorithm + "-" + mode);
        } else {
            stegoFile = Paths.get("src", "main", "resources", "outputs", bmpName + "-" + steg + ".bmp");
            extractedFile = Paths.get("src", "main", "resources", "extracted", "extracted-" + messageName + "-" + steg);
        }

        // Embed the file
        String[] embedParams;
        if (encrypt) {
            embedParams = new String[]{"-embed", "-in", inputFile.toString(), "-p", coverFile.toString(), "-out", stegoFile.toString(), "-steg", steg, "-a", algorithm, "-m", mode, "-pass", "password"};
        } else {
            embedParams = new String[]{"-embed", "-in", inputFile.toString(), "-p", coverFile.toString(), "-out", stegoFile.toString(), "-steg", steg};
        }
        Steganography.main(embedParams);

        // Extract the file
        String[] extractParams;
        if (encrypt) {
            extractParams = new String[]{"-extract", "-p", stegoFile.toString(), "-out", extractedFile.toString(), "-steg", steg, "-a", algorithm, "-m", mode, "-pass", "password"};
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


    @ParameterizedTest
    @MethodSource("provideParameters")
    public void testLoImposible(String steg, boolean encrypt, String algorithm, String mode) throws IOException {
        String name = "lima";
        Path stegoFile = Paths.get("src", "main", "resources", "outputs", name + ".bmp");
        Path extractedFile;

        if (encrypt) {
            extractedFile = Paths.get("src", "main", "resources", "extracted", "extracted-" + name + "-" + steg + "-" + algorithm + "-" + mode);
        } else {
            extractedFile = Paths.get("src", "main", "resources", "extracted", "extracted-" + name + "-" + steg);
        }

        // Extract the file
        String[] extractParams;
        if (encrypt) {
            extractParams = new String[]{"-extract", "-p", stegoFile.toString(), "-out", extractedFile.toString(), "-steg", steg, "-a", algorithm, "-m", mode, "-pass", "sorpresa"};
        } else {
            extractParams = new String[]{"-extract", "-p", stegoFile.toString(), "-out", extractedFile.toString(), "-steg", steg};
        }
        Steganography.main(extractParams);
    }

    private static Stream<Object[]> provideParameters() {
        return Stream.of(
                new Object[]{"LSB1", false, null, null},
                new Object[]{"LSB1", true, "AES128", "ECB"},
                new Object[]{"LSB1", true, "AES128", "CBC"},
                new Object[]{"LSB1", true, "AES128", "CFB"},
                new Object[]{"LSB1", true, "AES128", "CFB8"},
                new Object[]{"LSB1", true, "AES128", "OFB"},
                new Object[]{"LSB1", true, "AES128", "OFB8"},
                new Object[]{"LSB1", true, "AES192", "ECB"},
                new Object[]{"LSB1", true, "AES192", "CBC"},
                new Object[]{"LSB1", true, "AES192", "CFB"},
                new Object[]{"LSB1", true, "AES192", "CFB8"},
                new Object[]{"LSB1", true, "AES192", "OFB"},
                new Object[]{"LSB1", true, "AES192", "OFB8"},
                new Object[]{"LSB1", true, "AES256", "ECB"},
                new Object[]{"LSB1", true, "AES256", "CBC"},
                new Object[]{"LSB1", true, "AES256", "CFB"},
                new Object[]{"LSB1", true, "AES256", "CFB8"},
                new Object[]{"LSB1", true, "AES256", "OFB"},
                new Object[]{"LSB1", true, "AES256", "OFB8"},
                new Object[]{"LSB1", true, "DES", "ECB"},
                new Object[]{"LSB1", true, "DES", "CBC"},
                new Object[]{"LSB1", true, "DES", "CFB"},
                new Object[]{"LSB1", true, "DES", "CFB8"},
                new Object[]{"LSB1", true, "DES", "OFB"},
                new Object[]{"LSB1", true, "DES", "OFB8"},

                new Object[]{"LSB4", false, null, null},
                new Object[]{"LSB4", true, "AES128", "ECB"},
                new Object[]{"LSB4", true, "AES128", "CBC"},
                new Object[]{"LSB4", true, "AES128", "CFB"},
                new Object[]{"LSB4", true, "AES128", "CFB8"},
                new Object[]{"LSB4", true, "AES128", "OFB"},
                new Object[]{"LSB4", true, "AES128", "OFB8"},
                new Object[]{"LSB4", true, "AES192", "ECB"},
                new Object[]{"LSB4", true, "AES192", "CBC"},
                new Object[]{"LSB4", true, "AES192", "CFB"},
                new Object[]{"LSB4", true, "AES192", "CFB8"},
                new Object[]{"LSB4", true, "AES192", "OFB"},
                new Object[]{"LSB4", true, "AES192", "OFB8"},
                new Object[]{"LSB4", true, "AES256", "ECB"},
                new Object[]{"LSB4", true, "AES256", "CBC"},
                new Object[]{"LSB4", true, "AES256", "CFB"},
                new Object[]{"LSB4", true, "AES256", "CFB8"},
                new Object[]{"LSB4", true, "AES256", "OFB"},
                new Object[]{"LSB4", true, "AES256", "OFB8"},
                new Object[]{"LSB4", true, "DES", "ECB"},
                new Object[]{"LSB4", true, "DES", "CBC"},
                new Object[]{"LSB4", true, "DES", "CFB"},
                new Object[]{"LSB4", true, "DES", "CFB8"},
                new Object[]{"LSB4", true, "DES", "OFB"},
                new Object[]{"LSB4", true, "DES", "OFB8"},

                new Object[]{"LSBI", false, null, null},
                new Object[]{"LSBI", true, "AES128", "ECB"},
                new Object[]{"LSBI", true, "AES128", "CBC"},
                new Object[]{"LSBI", true, "AES128", "CFB"},
                new Object[]{"LSBI", true, "AES128", "CFB8"},
                new Object[]{"LSBI", true, "AES128", "OFB"},
                new Object[]{"LSBI", true, "AES128", "OFB8"},
                new Object[]{"LSBI", true, "AES192", "ECB"},
                new Object[]{"LSBI", true, "AES192", "CBC"},
                new Object[]{"LSBI", true, "AES192", "CFB"},
                new Object[]{"LSBI", true, "AES192", "CFB8"},
                new Object[]{"LSBI", true, "AES192", "OFB"},
                new Object[]{"LSBI", true, "AES192", "OFB8"},
                new Object[]{"LSBI", true, "AES256", "ECB"},
                new Object[]{"LSBI", true, "AES256", "CBC"},
                new Object[]{"LSBI", true, "AES256", "CFB"},
                new Object[]{"LSBI", true, "AES256", "CFB8"},
                new Object[]{"LSBI", true, "AES256", "OFB"},
                new Object[]{"LSBI", true, "AES256", "OFB8"},
                new Object[]{"LSBI", true, "DES", "ECB"},
                new Object[]{"LSBI", true, "DES", "CBC"},
                new Object[]{"LSBI", true, "DES", "CFB"},
                new Object[]{"LSBI", true, "DES", "CFB8"},
                new Object[]{"LSBI", true, "DES", "OFB"},
                new Object[]{"LSBI", true, "DES", "OFB8"}
        );
    }
}
