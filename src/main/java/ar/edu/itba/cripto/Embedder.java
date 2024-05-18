package ar.edu.itba.cripto;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class Embedder {
    private final String inFilePath;
    private final String outFilePath;
    private final String pBitmapFilePath;
    private final String stegMethod;
    private final String algorithm;
    private final String mode;
    private final String password;
    private static final int HEADER_SIZE = 54; // BMP header is typically 54 bytes

    public Embedder(String inFile, String outFile, String pBitmapFile, String stegMethod, String algorithm, String mode, String password) {
        this.inFilePath = inFile;
        this.outFilePath = outFile;
        this.pBitmapFilePath = pBitmapFile;
        this.stegMethod = stegMethod;
        this.algorithm = algorithm;
        this.mode = mode;
        this.password = password;
    }

    public void embed() throws IOException {
        // Read the BMP file
        byte[] bmpBytes = Files.readAllBytes(new File(pBitmapFilePath).toPath());

        // Read the file to be hidden
        File inFile = new File(inFilePath);
        byte[] fileBytes = Files.readAllBytes(inFile.toPath());

        System.out.println(Arrays.toString(fileBytes));
        System.out.println(bmpBytes.length);

        // Get the file size and extension
        int fileSize = fileBytes.length;
        String fileExtension = getFileExtension(inFile);
        byte[] extensionBytes = (fileExtension + "\0").getBytes();

        // Create the byte array to be embedded
        byte[] dataToHide = new byte[4 + fileSize + extensionBytes.length];

        // Embed the file size (4 bytes)
        dataToHide[0] = (byte) (fileSize >> 24);
        dataToHide[1] = (byte) (fileSize >> 16);
        dataToHide[2] = (byte) (fileSize >> 8);
        dataToHide[3] = (byte) (fileSize);

        System.out.println(Arrays.toString(dataToHide));
        // Embed the file data
        System.arraycopy(fileBytes, 0, dataToHide, 4, fileBytes.length);

        System.out.println(Arrays.toString(dataToHide));
        // Embed the file extension
        System.arraycopy(extensionBytes, 0, dataToHide, 4 + fileBytes.length, extensionBytes.length);
        System.out.println(Arrays.toString(dataToHide));

        byte[] stegoImage = switch (stegMethod) {
            case "LSB1" -> embedLSB1(bmpBytes, dataToHide);
            case "LSB4" -> embedLSB4(bmpBytes, dataToHide);
            case "LSBI" -> embedLSBI(bmpBytes, dataToHide);
            default -> throw new IllegalArgumentException("Invalid steganography method: " + stegMethod);
        };

        // Write the new BMP file
        Files.write(new File(outFilePath).toPath(), stegoImage);
    }

    private String getFileExtension(File file) {
        String name = file.getName();
        int lastDot = name.lastIndexOf('.');
        return lastDot == -1 ? "" : name.substring(lastDot);
    }

    private byte[] embedLSB1(byte[] image, byte[] data) {
        int offset = HEADER_SIZE;
        for (byte b : data) {
            for (int bit = 7; bit >= 0; bit--) {
                int bitValue = (b >> bit) & 1;
                image[offset] = (byte) ((image[offset] & 0xFE) | bitValue);
                offset++;
            }
        }
        return image;
    }

    private byte[] embedLSB4(byte[] image, byte[] data) {
        int offset = HEADER_SIZE;
        for (byte b : data) {
            for (int nibble = 1; nibble >= 0; nibble--) {
                int nibbleValue = (b >> (nibble * 4)) & 0x0F;
                image[offset] = (byte) ((image[offset] & 0xF0) | nibbleValue);
                offset++;
            }
        }
        return image;
    }

    private byte[] embedLSBI(byte[] image, byte[] data) {
        int offset = HEADER_SIZE;
        // Pattern counters
        Map<Integer, Integer> changeCount = new HashMap<>();
        Map<Integer, Integer> noChangeCount = new HashMap<>();
        int[] patterns = {0b00, 0b01, 0b10, 0b11};

        // Initialize counters
        for (int pattern : patterns) {
            changeCount.put(pattern, 0);
            noChangeCount.put(pattern, 0);
        }

        // First pass: Steganography and change counting
        for (byte b : data) {
            for (int bit = 7; bit >= 0; bit--) {
                int bitValue = (b >> bit) & 1;
                int currentByte = image[offset] & 0xFF;

                // Get the pattern of the 2 least significant bits
                int patternBits = (currentByte >> 1) & 0x03;

                // Compare the least significant bit before and after the change
                int lsbBefore = currentByte & 1;
                image[offset] = (byte) ((currentByte & 0xFE) | bitValue);
                int lsbAfter = image[offset] & 1;

                // Update the counters
                if (lsbBefore != lsbAfter) {
                    changeCount.put(patternBits, changeCount.get(patternBits) + 1);
                } else {
                    noChangeCount.put(patternBits, noChangeCount.get(patternBits) + 1);
                }

                offset++;
            }
        }

        // Second pass: Invert least significant bits where necessary
        offset = HEADER_SIZE;
        for (byte b : data) {
            for (int bit = 7; bit >= 0; bit--) {
                int currentByte = image[offset] & 0xFF;

                // Get the pattern of the 2 least significant bits
                int patternBits = (currentByte >> 1) & 0x03;

                // Invert the least significant bit if there are more changes than no changes
                if (changeCount.get(patternBits) > noChangeCount.get(patternBits)) {
                    image[offset] ^= 1; // Invert the least significant bit
                }

                offset++;
            }
        }

        // Update the last 4 bytes to indicate which patterns changed and which did not
        for (int pattern : patterns) {
            int changed = changeCount.get(pattern);
            int notChanged = noChangeCount.get(pattern);

            image[offset] = (byte) (changed > notChanged ? (image[offset] | 0x01) : (image[offset] & 0xFE));
            System.out.println(image[offset]);
            offset++;
        }

        return image;
    }
}
