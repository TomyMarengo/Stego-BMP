package ar.edu.itba.cripto;

import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Extractor extends Operator {
    private static final int DATA_LENGTH_SIZE = 4;
    private static final int PATTERN_SIZE = 4;

    public Extractor(String outFile, String pBitmapFile, String stegMethod, Algorithm algorithm, Mode mode, String password) {
        super(outFile, pBitmapFile, stegMethod, algorithm, mode, password);
    }

    public void extract() throws Exception {
        // Read the BMP file
        byte[] bmpBytes = Files.readAllBytes(new File(pBitmapFilePath).toPath());
        byte[] data;

        // Decrypt the data if necessary
        if (password != null && !password.isEmpty()) {
            System.out.println("(EXTRACT) Extracting cypher data...");

            byte[] cipherData = switch (stegMethod) { // cypherLength || cipherData = (length || data || extension)
                case "lsb1" -> extractLSB1(bmpBytes, true);
                case "lsb4" -> extractLSB4(bmpBytes, true);
                case "lsbi" -> extractLSBI(bmpBytes, true);
                default -> throw new IllegalArgumentException("Invalid steganography method: " + stegMethod);
            };

            byte[] dataToDecrypt = Arrays.copyOfRange(cipherData, 4, cipherData.length);
            System.out.println("(EXTRACT) Decrypting...");
            data = SteganographyUtil.decrypt(dataToDecrypt, algorithm, mode, password); // length || data || extension
        } else {
            System.out.println("(EXTRACT) Extracting plain data...");

            data = switch (stegMethod) { // length || data || extension
                case "lsb1" -> extractLSB1(bmpBytes, false);
                case "lsb4" -> extractLSB4(bmpBytes, false);
                case "lsbi" -> extractLSBI(bmpBytes, false);
                default -> throw new IllegalArgumentException("Invalid steganography method: " + stegMethod);
            };
        }

        // Extract the data text length
        int dataLength = ((data[0] & 0xFF) << 24)
                | ((data[1] & 0xFF) << 16)
                | ((data[2] & 0xFF) << 8)
                | (data[3] & 0xFF);

        // Extract the file extension and file data
        int extensionStart = 4 + dataLength;
        int extensionEnd = extensionStart;
        while (data[extensionEnd] != 0) {
            extensionEnd++;
        }
        String fileExtension = new String(Arrays.copyOfRange(data, extensionStart, extensionEnd));
        byte[] fileData = Arrays.copyOfRange(data, 4, 4 + dataLength);

        // Write the extracted file
        File outFile = new File(outFilePath + fileExtension);
        System.out.println("(EXTRACT) Writing extracted file: " + outFile.getName());
        Files.write(outFile.toPath(), fileData);
    }

    private byte[] extractLSB1(byte[] image, boolean encrypted) {
        int offset = SteganographyUtil.HEADER_SIZE;

        // Extract the data length
        int dataLength = 0;
        for (int i = 0; i < DATA_LENGTH_SIZE * 8; i++) { // Data length
            dataLength = (dataLength << 1) | (image[offset] & 1);
            offset++;
        }

        // Calculate the total length of the data
        int bytesLength = DATA_LENGTH_SIZE + dataLength;

        // Extract [cypherLength || cypherData] or [length || data]
        byte[] extractedData = new byte[bytesLength];
        offset = SteganographyUtil.HEADER_SIZE;
        for (int i = 0; i < bytesLength; i++) {
            extractedData[i] = 0;
            for (int bit = 7; bit >= 0; bit--) {
                extractedData[i] |= (byte) ((image[offset] & 1) << bit);
                offset++;
            }
        }

        // Extract the extension if is not encrypted
        if (!encrypted) {
            List<Byte> extensionBytes = new ArrayList<>();
            boolean zeroNotFound = true;
            byte currentByte;

            while (zeroNotFound) {
                currentByte = 0;
                for (int bit = 7; bit >= 0; bit--) {
                    currentByte |= (byte) ((image[offset] & 1) << bit);
                    offset++;
                }
                extensionBytes.add(currentByte);
                if (currentByte == 0) {
                    zeroNotFound = false;
                }
            }

            // Convert the extension bytes to a character string
            byte[] extensionArray = new byte[extensionBytes.size()];
            for (int i = 0; i < extensionArray.length; i++) {
                extensionArray[i] = extensionBytes.get(i);
            }
            /* returnData array with length || data || extension */
            byte[] returnData = new byte[bytesLength + extensionArray.length];
            System.arraycopy(extractedData, 0, returnData, 0, bytesLength);
            System.arraycopy(extensionArray, 0, returnData, bytesLength, extensionArray.length);

            return returnData;
        }

        return extractedData;
    }

    private byte[] extractLSB4(byte[] image, boolean encrypted) {
        int offset = SteganographyUtil.HEADER_SIZE;

        // Extract the data length
        int dataLength = 0;
        for (int i = 0; i < DATA_LENGTH_SIZE * 2; i++) { // Data length (4 bits per iteration)
            int nibble = (image[offset] & 0x0F); // Get the last 4 bits
            dataLength = (dataLength << 4) | nibble; // Shift left by 4 bits and add the nibble
            offset++;
        }

        // Calculate the total length of the data
        int bytesLength = DATA_LENGTH_SIZE + dataLength;

        // Extract [cypherLength || cypherData] or [length || data]
        byte[] extractedData = new byte[bytesLength];
        offset = SteganographyUtil.HEADER_SIZE;
        for (int i = 0; i < bytesLength; i++) {
            extractedData[i] = 0;
            for (int nibble = 1; nibble >= 0; nibble--) {
                extractedData[i] |= (byte) ((image[offset] & 0x0F) << (nibble * 4));
                offset++;
            }
        }

        // Extract the extension if is not encrypted
        if (!encrypted) {
            List<Byte> extensionBytes = new ArrayList<>();
            boolean zeroNotFound = true;
            byte currentByte;

            while (zeroNotFound) {
                currentByte = 0;
                for (int nibble = 1; nibble >= 0; nibble--) {
                    currentByte |= (byte) ((image[offset] & 0x0F) << (nibble * 4));
                    offset++;
                }
                extensionBytes.add(currentByte);
                if (currentByte == 0) {
                    zeroNotFound = false;
                }
            }

            // Convert the extension bytes to a character string
            byte[] extensionArray = new byte[extensionBytes.size()];
            for (int i = 0; i < extensionArray.length; i++) {
                extensionArray[i] = extensionBytes.get(i);
            }
            /* returnData array with length || data || extension */
            byte[] returnData = new byte[bytesLength + extensionArray.length];
            System.arraycopy(extractedData, 0, returnData, 0, bytesLength);
            System.arraycopy(extensionArray, 0, returnData, bytesLength, extensionArray.length);

            return returnData;
        }

        return extractedData;
    }

    private byte[] extractLSBI(byte[] image, boolean encrypted) {
        // Recover the patterns stored in the last 4 bytes of the BGR pixels
        int offset = SteganographyUtil.HEADER_SIZE;
        int[] patterns = new int[4];
        for (int i = 0; i < PATTERN_SIZE; i++) {
            patterns[i] = image[offset] & 1;
            offset++;
        }

        // Extract the data length
        int dataLength = 0;
        for (int i = 0; i < DATA_LENGTH_SIZE * 8; i++) { // 32 bits = 4 bytes
            if ((offset + 1) % 3 != 0) { // Skip the LSB of the red channel
                int currentByte = image[offset] & 0xFF;
                int patternBits = (currentByte >> 1) & 0x03;
                int lsb = currentByte & 1;

                if (patterns[patternBits] == 1) {
                    lsb ^= 1; // Invert the LSB if the pattern has a 1
                }

                dataLength = (dataLength << 1) | lsb;
            } else {
                i--;
            }
            offset++;
        }


        // Calculate the total length of the data
        int bytesLength = DATA_LENGTH_SIZE + dataLength;

        // Extract [cypherLength || cypherData] or [length || data]
        byte[] extractedData = new byte[bytesLength];
        offset = SteganographyUtil.HEADER_SIZE + PATTERN_SIZE;
        for (int i = 0; i < bytesLength; i++) {
            extractedData[i] = 0;
            for (int bit = 7; bit >= 0; bit--) {
                if ((offset + 1) % 3 != 0) { // Skip the LSB of the red channel
                    int currentByte = image[offset] & 0xFF;
                    int patternBits = (currentByte >> 1) & 0x03;
                    int lsb = currentByte & 1;

                    if (patterns[patternBits] == 1) {
                        lsb ^= 1; // Invert the LSB if the pattern has a 1
                    }
                    extractedData[i] |= (byte) (lsb << bit);
                } else {
                    bit++;
                }
                offset++;
            }
        }

        // Extract the extension if is not encrypted
        if (!encrypted) {
            List<Byte> extensionBytes = new ArrayList<>();
            boolean zeroNotFound = true;
            byte currentByte = 0;
            int bitIndex = 7;

            while (zeroNotFound) {
                if ((offset + 1) % 3 != 0) { // Skip the LSB of the red channel
                    int pixelByte = image[offset] & 0xFF;
                    int patternBits = (pixelByte >> 1) & 0x03;
                    int lsb = pixelByte & 1;

                    if (patterns[patternBits] == 1) {
                        lsb ^= 1; // Invert the LSB if the pattern has a 1
                    }

                    currentByte |= (byte) (lsb << bitIndex);
                    bitIndex--;

                    if (bitIndex < 0) {
                        extensionBytes.add(currentByte);
                        if (currentByte == 0) {
                            zeroNotFound = false;
                        }
                        currentByte = 0;
                        bitIndex = 7;
                    }
                }
                offset++;
            }

            // Convert the extension bytes to a character string
            byte[] extensionArray = new byte[extensionBytes.size()];
            for (int i = 0; i < extensionArray.length; i++) {
                extensionArray[i] = extensionBytes.get(i);
            }
            /* returnData array with length || data || extension */
            byte[] returnData = new byte[bytesLength + extensionArray.length];
            System.arraycopy(extractedData, 0, returnData, 0, bytesLength);
            System.arraycopy(extensionArray, 0, returnData, bytesLength, extensionArray.length);

            return returnData;
        }

        return extractedData;
    }
}
