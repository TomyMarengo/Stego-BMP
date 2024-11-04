import ar.edu.itba.cripto.Steganography;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class SteganographyTest {
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
            stegoFile = Paths.get("src", "main", "resources", "embedded", bmpName + "-" + steg + "-" + algorithm + "-" + mode + ".bmp");
            extractedFile = Paths.get("src", "main", "resources", "extracted", "extracted-" + messageName + "-" + steg + "-" + algorithm + "-" + mode);
        } else {
            stegoFile = Paths.get("src", "main", "resources", "embedded", bmpName + "-" + steg + ".bmp");
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
        Path stegoFile = Paths.get("src", "main", "resources", "embedded", name + ".bmp");
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
        String[] stegMethods = {"LSB1", "LSB2", "LSB4", "LSBI"};
        boolean[] encryptOptions = {false, true};
        String[] encryptionAlgorithms = {"AES128", "AES192", "AES256", "DES"};
        String[] encryptionModes = {"ECB", "CBC", "CFB", "CFB8", "OFB", "OFB8"};

        List<Object[]> parameters = new ArrayList<>();

        for (String stegMethod : stegMethods) {
            for (boolean encrypt : encryptOptions) {
                if (!encrypt) {
                    parameters.add(new Object[]{stegMethod, encrypt, null, null});
                } else {
                    for (String algorithm : encryptionAlgorithms) {
                        for (String mode : encryptionModes) {
                            parameters.add(new Object[]{stegMethod, encrypt, algorithm, mode});
                        }
                    }
                }
            }
        }
        return parameters.stream();
    }
}
