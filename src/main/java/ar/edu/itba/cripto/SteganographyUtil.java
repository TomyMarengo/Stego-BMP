package ar.edu.itba.cripto;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
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

    private static byte[] getHashedPassword(String password, int bitLength) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] encodedhash = digest.digest(password.getBytes(StandardCharsets.UTF_8));

        // Truncate the hash to the desired length
        return Arrays.copyOf(encodedhash, bitLength / 8);
    }

    private static byte[] generateIV(int bitLength) {
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[bitLength];
        random.nextBytes(iv);
        return iv;
    }

    public static byte[] encrypt(byte[] data, String algorithm, String mode, String password) throws Exception {
        byte[] hashedPassword;
        String algo = switch (algorithm) {
            case "aes128" -> {
                hashedPassword = getHashedPassword(password, 128);
                yield AES_ALGORITHM;
            }
            case "aes192" -> {
                hashedPassword = getHashedPassword(password, 192);
                yield AES_ALGORITHM;
            }
            case "aes256" -> {
                hashedPassword = getHashedPassword(password, 256);
                yield AES_ALGORITHM;
            }
            case "des" -> {
                hashedPassword = getHashedPassword(password, 64);
                yield DES_ALGORITHM;
            }
            default -> throw new IllegalArgumentException("Invalid encryption algorithm: " + algorithm);
        };
        String mo = switch (mode) {
            case "ecb" -> ECB_MODE;
            case "cfb" -> CFB_MODE;
            case "ofb" -> OFB_MODE;
            case "cbc" -> CBC_MODE;
            default -> throw new IllegalArgumentException("Invalid encryption mode: " + mode);
        };

        byte[] iv;
        if (mo.equals(CBC_MODE) || mo.equals(CFB_MODE) || mo.equals(OFB_MODE)) {
            if (algo.equals(DES_ALGORITHM)) {
                iv = generateIV(8);
            }
            else { // AES
                iv = generateIV(16);
            }
        } else {
            iv = new byte[0]; // If no IV is needed, use an empty array
        }

        System.out.println("Hashed password: " + Arrays.toString(hashedPassword));
        String hashedPasswordAsString = new String(hashedPassword, StandardCharsets.UTF_8);
        System.out.println("Hashed password: " + hashedPasswordAsString);
        System.out.println("IV: " + Arrays.toString(iv));
        String IVAsString = new String(iv, StandardCharsets.UTF_8);
        System.out.println("IV: " + IVAsString);

        Cipher cipher = Cipher.getInstance(algo + "/" + mo + "/" + PKCS5_PADDING);
        SecretKeySpec keySpec = new SecretKeySpec(hashedPassword, algo);
        if (iv.length == 0) { //todo: el iv donde me viene en la desencripcion, o como lo leo?
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        } else {
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        }
        return cipher.doFinal(data);
    }

    public static byte[] decrypt(byte[] data, String algorithm, String mode, String password) throws Exception {
        Cipher cipher = Cipher.getInstance(algorithm + "/" + mode + "/" + PKCS5_PADDING);
        SecretKeySpec keySpec = new SecretKeySpec(password.getBytes(), algorithm);
        IvParameterSpec ivSpec = new IvParameterSpec(password.getBytes());
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        return cipher.doFinal(data);
    }
}