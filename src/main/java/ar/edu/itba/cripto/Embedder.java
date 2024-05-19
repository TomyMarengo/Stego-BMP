package ar.edu.itba.cripto;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.Map;

public class Embedder extends Operator {
    private final String inFilePath;

    public Embedder(String inFile, String outFile, String pBitmapFile, String stegMethod, String algorithm, String mode, String password) {
        super(outFile, pBitmapFile, stegMethod, algorithm, mode, password);
        this.inFilePath = inFile;
    }

    public void embed() throws Exception {
        // Read the BMP file
        byte[] bmpBytes = Files.readAllBytes(new File(pBitmapFilePath).toPath());

        // Read the file to be hidden
        File inFile = new File(inFilePath);
        byte[] fileBytes = Files.readAllBytes(inFile.toPath());

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

        // Embed the file data
        System.arraycopy(fileBytes, 0, dataToHide, 4, fileBytes.length);
        // Embed the file extension
        System.arraycopy(extensionBytes, 0, dataToHide, 4 + fileBytes.length, extensionBytes.length);

        // Encrypt the data to hide
        if (password != null && !password.isEmpty()) {
            System.out.println("Encrypting...");
            dataToHide = SteganographyUtil.encrypt(dataToHide, algorithm, mode, password);

            // add cypher text length to the beginning of the data
            byte[] dataToHideWithLength = new byte[dataToHide.length + 4];
            dataToHideWithLength[0] = (byte) (dataToHide.length >> 24);
            dataToHideWithLength[1] = (byte) (dataToHide.length >> 16);
            dataToHideWithLength[2] = (byte) (dataToHide.length >> 8);
            dataToHideWithLength[3] = (byte) (dataToHide.length);
            System.arraycopy(dataToHide, 0, dataToHideWithLength, 4, dataToHide.length);
            dataToHide = dataToHideWithLength;
        }

        String dataAsString = new String(dataToHide, StandardCharsets.UTF_8);
        System.out.println("Data to hide: " + dataAsString);

        System.out.println("Embedding...");
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
        int offset = SteganographyUtil.HEADER_SIZE;
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
        int offset = SteganographyUtil.HEADER_SIZE;;
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
        int offset = SteganographyUtil.HEADER_SIZE + 4;
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

                if ((offset + 1) % 3 != 0) { // Skip the LSB of the red channel
                    int currentByte = image[offset] & 0xFF;
                    int patternBits = (currentByte >> 1) & 0x03;
                    int lsbBefore = currentByte & 1;

                    image[offset] = (byte) ((currentByte & 0xFE) | bitValue);
                    int lsbAfter = image[offset] & 1;

                    if (lsbBefore != lsbAfter) {
                        changeCount.put(patternBits, changeCount.get(patternBits) + 1);
                    } else {
                        noChangeCount.put(patternBits, noChangeCount.get(patternBits) + 1);
                    }
                } else {
                    bit++;
                }

                offset++;
            }
        }

        // Second pass: Invert least significant bits where necessary
        offset = SteganographyUtil.HEADER_SIZE + 4;
        for (byte b : data) {
            for (int bit = 7; bit >= 0; bit--) {
                if ((offset + 1) % 3 != 0) { // Skip the LSB of the red channel
                    int currentByte = image[offset] & 0xFF;

                    // Get the pattern of the 2 least significant bits
                    int patternBits = (currentByte >> 1) & 0x03;

                    // Invert the least significant bit if there are more changes than no changes
                    if (changeCount.get(patternBits) > noChangeCount.get(patternBits)) {
                        image[offset] ^= 1; // Invert the least significant bit
                    }
                }
                else {
                    bit++;
                }

                offset++;
            }
        }

        // Update the first 4 bytes to indicate which patterns changed and which did not
        offset = SteganographyUtil.HEADER_SIZE;
        for (int pattern : patterns) {
            int changed = changeCount.get(pattern);
            int notChanged = noChangeCount.get(pattern);
            image[offset] = (byte) (changed > notChanged ? (image[offset] | 0x01) : (image[offset] & 0xFE));
            System.out.println("Pattern " + Integer.toBinaryString(pattern) + ": " + changed + " changes, " + notChanged + " no changes");
            offset++;
        }

        return image;
    }
}
