package ar.edu.itba.cripto;

public enum Algorithm {
    AES128("AES", 128),
    AES192("AES", 192),
    AES256("AES", 256),
    DES("DESede", 192);

    private final String cipherName;
    private final int keyBitsLength;

    Algorithm(String cipherName, int keyBitsLength) {
        this.cipherName = cipherName;
        this.keyBitsLength = keyBitsLength;
    }

    public String getCipherName() {
        return cipherName;
    }

    public int getKeyBitsLength() {
        return keyBitsLength;
    }

    public static Algorithm fromString(String algorithm) {
        return switch (algorithm.toLowerCase()) {
            case "aes128" -> AES128;
            case "aes192" -> AES192;
            case "aes256" -> AES256;
            case "des" -> DES;
            default -> throw new IllegalArgumentException("Invalid algorithm: " + algorithm);
        };
    }
}
