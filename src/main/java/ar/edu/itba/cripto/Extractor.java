package ar.edu.itba.cripto;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Extractor extends Operator {
    private static final int DATA_LENGTH_SIZE = 4;
    private static final int IV_LENGTH_SIZE = 4;

    public Extractor(String outFile, String pBitmapFile, String stegMethod, String algorithm, String mode, String password) {
        super(outFile, pBitmapFile, stegMethod, algorithm, mode, password);
    }

    public void extract() throws Exception {
        // Read the BMP file
        byte[] bmpBytes = Files.readAllBytes(new File(pBitmapFilePath).toPath());
        byte[] data;

        // Decrypt the data if necessary
        if (password != null && !password.isEmpty()) {
            System.out.println("Extracting cypher text...");

            byte[] cipherData = switch (stegMethod) { // cypherLength || ivLength || IV || cypherData = (length || data || extension)
                case "LSB1" -> extractLSB1(bmpBytes, true);
                case "LSB4" -> extractLSB4(bmpBytes, true);
                case "LSBI" -> extractLSBI(bmpBytes, true);
                default -> throw new IllegalArgumentException("Invalid steganography method: " + stegMethod);
            };

            //Extract iv, cypherData has ivLength in second first 4 bytes, then IV in the following ivLength bytes
            int ivLength = ((cipherData[4] & 0xFF) << 24)
                    | ((cipherData[5] & 0xFF) << 16)
                    | ((cipherData[6] & 0xFF) << 8)
                    | (cipherData[7] & 0xFF);

            System.out.println("IV length: " + ivLength);
            byte[] iv = Arrays.copyOfRange(cipherData, 8, 8 + ivLength);
            System.out.println("IV: " + Arrays.toString(iv));
            byte[] dataToDecrypt = Arrays.copyOfRange(cipherData, 8 + ivLength, cipherData.length); // cypherData finish before LBSI patterns
            System.out.println("Data to decrypt: " + Arrays.toString(dataToDecrypt));
            data = SteganographyUtil.decrypt(dataToDecrypt, algorithm, mode, password, iv); // length || data || extension
        } else {
            data = switch (stegMethod) { // length || data || extension
                case "LSB1" -> extractLSB1(bmpBytes, false);
                case "LSB4" -> extractLSB4(bmpBytes, false);
                case "LSBI" -> extractLSBI(bmpBytes, false);
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

        // Extract the IV length
        int ivLength = 0;
        if (encrypted) {
            for (int i = 0; i < IV_LENGTH_SIZE * 8; i++) { // Next 4 bytes are the IV length
                ivLength = (ivLength << 1) | (image[offset] & 1);
                offset++;
            }
        }

        // Calculate the total length of the data
        int length = DATA_LENGTH_SIZE + dataLength;
        if (encrypted) {
            length += IV_LENGTH_SIZE + ivLength;
        }

        // Extract [cypherLength || ivLength || IV || cypherData = (length || data || extension)] or [length || data]
        byte[] extractedData = new byte[length];
        offset = SteganographyUtil.HEADER_SIZE;
        System.out.println("Length: " + length);
        for (int i = 0; i < length; i++) {
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
            byte[] returnData = new byte[length + extensionArray.length];
            System.arraycopy(extractedData, 0, returnData, 0, length);
            System.arraycopy(extensionArray, 0, returnData, length, extensionArray.length);

            return returnData;
        }

        return extractedData;
    }

    private byte[] extractLSB4(byte[] image, boolean encrypted) {
        int offset = SteganographyUtil.HEADER_SIZE;

        // Extract the data length
        int dataLength = 0;
        for (int i = 0; i < DATA_LENGTH_SIZE * 8 / 4; i++) { // Data length
            dataLength = (dataLength << 1) | (image[offset] & 0x0F);
            offset++;
        }

        // Extract the IV length
        int ivLength = 0;
        if (encrypted) {
            for (int i = 0; i < IV_LENGTH_SIZE * 8 / 4; i++) { // Next 2 bytes are the IV length
                ivLength = (ivLength << 1) | (image[offset] & 0x0F);
                offset++;
            }
        }

        // Calculate the total length of the data
        int length = DATA_LENGTH_SIZE * 8 / 4 + dataLength / 2;
        if (encrypted) {
            length += + IV_LENGTH_SIZE * 8 / 4 + ivLength / 2;
        }

        // Extract the data
        byte[] extractedData = new byte[length];
        offset = 0;
        for (int i = 0; offset < length; i++) {
            extractedData[i] = 0;
            for (int nibble = 1; nibble >= 0; nibble--) {
                extractedData[i] |= (byte) ((image[offset] & 0x0F) << (nibble * 4));
                offset++;
            }
        }
        return extractedData;
    }

    private byte[] extractLSBI(byte[] image, boolean encrypted) {
        // Recover the patterns stored in the last 4 bytes of the BGR pixels
        int offset = SteganographyUtil.HEADER_SIZE;
        int[] patterns = new int[4];
        for (int i = 0; i < 4; i++) {
            patterns[i] = image[offset] & 1;
            offset++;
        }

        // Extract the data length
        int dataLength = 0;
        for (int i = 0; i < 32; i++) { // 32 bits = 4 bytes
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

        // Extract the data
        byte[] extractedData = new byte[dataLength];
        for (int i = 0; i < dataLength; i++) {
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

        // Extract the file extension, checking inverted LSB patterns
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
        byte[] returnData = new byte[4 + dataLength + extensionArray.length];
        returnData[0] = (byte) (dataLength >> 24);
        returnData[1] = (byte) (dataLength >> 16);
        returnData[2] = (byte) (dataLength >> 8);
        returnData[3] = (byte) dataLength;
        System.arraycopy(extractedData, 0, returnData, 4, dataLength);
        System.arraycopy(extensionArray, 0, returnData, 4 + dataLength, extensionArray.length);
        return returnData;
    }
}
