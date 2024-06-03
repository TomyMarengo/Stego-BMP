package ar.edu.itba.cripto;

public enum Mode {
    ECB("ECB", 0),
    CBC("CBC", 128),
    CFB8("CFB8", 128),
    CFB("CFB", 128),
    OFB8("OFB8", 128),
    OFB("OFB", 128);

    private final String modeName;
    private final int ivBitsLength;

    Mode(String modeName, int ivBitsLength) {
        this.modeName = modeName;
        this.ivBitsLength = ivBitsLength;
    }

    public String getModeName() {
        return modeName;
    }

    public int getIvBitsLength() {
        return ivBitsLength;
    }

    public static Mode fromString(String mode) {
        return switch (mode.toLowerCase()) {
            case "ecb" -> ECB;
            case "cbc" -> CBC;
            case "cfb8" -> CFB8;
            case "cfb" -> CFB;
            case "ofb8" -> OFB8;
            case "ofb" -> OFB;
            default -> throw new IllegalArgumentException("Invalid mode: " + mode);
        };
    }
}