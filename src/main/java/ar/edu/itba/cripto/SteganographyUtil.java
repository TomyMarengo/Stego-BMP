package ar.edu.itba.cripto;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

public class SteganographyUtil {
    public static final String AES_ALGORITHM = "AES";
    public static final String DES_ALGORITHM = "DES";
    public static final String ECB_MODE = "ECB";
    public static final String CBC_MODE = "CBC";
    public static final String CFB_MODE = "CFB";
    public static final String OFB_MODE = "OFB";
    public static final String PKCS5_PADDING = "PKCS5Padding";
    public static final int HEADER_SIZE = 54; // BMP header is typically 54 bytes
    // Deterministic salt
    public static final byte[] salt = "salt".getBytes(StandardCharsets.UTF_8);

    static class KeyAndIV {
        private final byte[] key;
        private final byte[] iv;
        public KeyAndIV(byte[] key, byte[] iv) {
            this.key = key;
            this.iv = iv;
        }

        public byte[] getKey() {
            return key;
        }

        public byte[] getIV() {
            return iv;
        }
    }

    private static KeyAndIV deriveKeyAndIV(String algorithm, String mode, String password) throws Exception {
        int passwordLength = switch (algorithm) {
            case "aes128" -> 128;
            case "aes192" -> 192;
            case "aes256" -> 256;
            case "des" -> 64;
            default -> throw new IllegalArgumentException("Invalid encryption algorithm: " + algorithm);
        };

        int ivLength = switch (mode) {
            case "ecb" -> 0;
            case "cfb", "ofb", "cbc" -> 128 / (algorithm.equals("des") ? 2 : 1); // DES uses 64-bit blocks
            default -> throw new IllegalArgumentException("Invalid encryption mode: " + mode);
        };

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 10, passwordLength + ivLength);
        byte[] keyAndIVBytes = factory.generateSecret(spec).getEncoded();

        // Split the derived bytes into key and IV
        byte[] key = Arrays.copyOfRange(keyAndIVBytes, 0, passwordLength / 8);
        byte[] iv = Arrays.copyOfRange(keyAndIVBytes, passwordLength / 8, passwordLength / 8 + ivLength / 8);

        return new KeyAndIV(key, iv);
    }

    public static byte[] encrypt(byte[] data, String algorithm, String mode, String password) throws Exception {
        String algo = switch (algorithm) {
            case "aes128", "aes192", "aes256" -> AES_ALGORITHM;
            case "des" -> DES_ALGORITHM;
            default -> throw new IllegalArgumentException("Invalid encryption algorithm: " + algorithm);
        };
        String mo = switch (mode) {
            case "ecb" -> ECB_MODE;
            case "cfb" -> CFB_MODE;
            case "ofb" -> OFB_MODE;
            case "cbc" -> CBC_MODE;
            default -> throw new IllegalArgumentException("Invalid encryption mode: " + mode);
        };

        KeyAndIV keyAndIV = deriveKeyAndIV(algorithm, mode, password);

        Cipher cipher = Cipher.getInstance(algo + "/" + mo + "/" + PKCS5_PADDING);
        SecretKeySpec keySpec = new SecretKeySpec(keyAndIV.getKey(), algo);
        if (keyAndIV.getIV().length == 0) {
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        } else {
            IvParameterSpec ivSpec = new IvParameterSpec(keyAndIV.getIV());
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        }

        return cipher.doFinal(data);
    }

    public static byte[] decrypt(byte[] data, String algorithm, String mode, String password) throws Exception {
        String algo = switch (algorithm) {
            case "aes128", "aes192", "aes256" -> AES_ALGORITHM;
            case "des" -> DES_ALGORITHM;
            default -> throw new IllegalArgumentException("Invalid encryption algorithm: " + algorithm);
        };
        String mo = switch (mode) {
            case "ecb" -> ECB_MODE;
            case "cfb" -> CFB_MODE;
            case "ofb" -> OFB_MODE;
            case "cbc" -> CBC_MODE;
            default -> throw new IllegalArgumentException("Invalid encryption mode: " + mode);
        };

        KeyAndIV keyAndIV = deriveKeyAndIV(algorithm, mode, password);

        Cipher cipher = Cipher.getInstance(algo + "/" + mo + "/" + PKCS5_PADDING);
        SecretKeySpec keySpec = new SecretKeySpec(keyAndIV.getKey(), algo);
        if (keyAndIV.getIV().length == 0) {
            cipher.init(Cipher.DECRYPT_MODE, keySpec);
        } else {
            IvParameterSpec ivSpec = new IvParameterSpec(keyAndIV.getIV());
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        }
        return cipher.doFinal(data);
    }
}