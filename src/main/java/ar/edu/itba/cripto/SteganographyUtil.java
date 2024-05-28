package ar.edu.itba.cripto;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;

public class SteganographyUtil {
    public static final String PADDING = "NoPadding";
    public static final int HEADER_SIZE = 54; // BMP header is typically 54 bytes
    // Deterministic salt
    private static final byte[] salt = hexStringToByteArray("0000000000000000");
    private static final int iterations = 10000;

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

    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static KeyAndIV deriveKeyAndIV(Algorithm algorithm, Mode mode, String password) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        int keyBitsLength = algorithm.getKeyBitsLength();
        int ivBitsLength = mode.getIvBitsLength();
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt,iterations, keyBitsLength + ivBitsLength);
        byte[] keyAndIVBytes = factory.generateSecret(spec).getEncoded();

        // Split the derived bytes into key and IV
        byte[] key = Arrays.copyOfRange(keyAndIVBytes, 0, keyBitsLength / 8);
        byte[] iv = Arrays.copyOfRange(keyAndIVBytes, keyBitsLength / 8, (keyBitsLength + ivBitsLength) / 8);

        return new KeyAndIV(key, iv);
    }

    public static byte[] encrypt(byte[] data, Algorithm algorithm, Mode mode, String password) throws Exception {
        KeyAndIV keyAndIV = deriveKeyAndIV(algorithm, mode, password);
        System.out.println("Key derivada: " + bytesToHex(keyAndIV.getKey()));
        System.out.println("IV derivada: " + bytesToHex(keyAndIV.getIV()));

        Cipher cipher = Cipher.getInstance(algorithm.getCipherName() + "/" + mode.getModeName() + "/" + PADDING);
        SecretKeySpec keySpec = new SecretKeySpec(keyAndIV.getKey(), algorithm.getCipherName());
        if (keyAndIV.getIV().length == 0) {
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        } else {
            IvParameterSpec ivSpec = new IvParameterSpec(keyAndIV.getIV());
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        }

        return cipher.doFinal(data);
    }

    public static byte[] decrypt(byte[] data, Algorithm algorithm, Mode mode, String password) throws Exception {
        KeyAndIV keyAndIV = deriveKeyAndIV(algorithm, mode, password);
        System.out.println("Key derivada: " + bytesToHex(keyAndIV.getKey()));
        System.out.println("IV derivada: " + bytesToHex(keyAndIV.getIV()));

        Cipher cipher = Cipher.getInstance(algorithm.getCipherName() + "/" + mode.getModeName() + "/" + PADDING);
        SecretKeySpec keySpec = new SecretKeySpec(keyAndIV.getKey(), algorithm.getCipherName());
        if (keyAndIV.getIV().length == 0) {
            cipher.init(Cipher.DECRYPT_MODE, keySpec);
        } else {
            IvParameterSpec ivSpec = new IvParameterSpec(keyAndIV.getIV());
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        }
        return cipher.doFinal(data);
    }
}