package ar.edu.itba.cripto;

public class Operator {
    final String outFilePath;
    final String pBitmapFilePath;
    final String stegMethod;
    final String algorithm;
    final String mode;
    final String password;

    public Operator(String outFile, String pBitmapFile, String stegMethod, String algorithm, String mode, String password) {
        this.outFilePath = outFile;
        this.pBitmapFilePath = pBitmapFile;
        this.stegMethod = stegMethod;
        this.algorithm = algorithm;
        this.mode = mode;
        this.password = password;
    }
}
