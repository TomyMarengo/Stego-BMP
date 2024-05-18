package ar.edu.itba.cripto;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class Steganography {
    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("No arguments provided");
            return;
        }

        Map<String, String> params = parseArguments(args);

        String operation = params.containsKey("-embed") ? "embed" : params.containsKey("-extract") ? "extract" : null;
        if (operation == null || (params.containsKey("-embed") && params.containsKey("-extract"))) {
            System.out.println("Operation not specified or both embed and extract operations specified");
            return;
        }

        String inFile = params.get("-in");
        String outFile = params.get("-out");
        String pBitmapFile = params.get("-p");
        String stegMethod = params.get("-steg");
        String algorithm = params.getOrDefault("-a", "aes128");
        String mode = params.getOrDefault("-m", "cbc");
        String password = params.get("-pass");

        if (pBitmapFile == null || outFile == null || stegMethod == null) {
            System.out.println("Missing p, out or steg parameters");
            return;
        }

        if (operation.equals("embed") && inFile == null) {
            System.out.println("Missing in parameter for embed operation");
            return;
        }

        System.out.println("Operation: " + operation);
        System.out.println("Input File: " + inFile);
        System.out.println("Output File: " + outFile);
        System.out.println("Bitmap File: " + pBitmapFile);
        System.out.println("Steganography Method: " + stegMethod);
        System.out.println("Encryption Algorithm: " + algorithm);
        System.out.println("Encryption Mode: " + mode);
        System.out.println("Password: " + (password != null ? "Provided" : "Not Provided"));

        if (operation.equals("embed")) {
            System.out.println("Embedding...");
            Embedder embedder = new Embedder(inFile, outFile, pBitmapFile, stegMethod, algorithm, mode, password);
            try {
                embedder.embed();
            } catch (IOException e) {
                System.out.println("Error embedding file: " + e.getMessage());
            }
        } else {
            System.out.println("Extracting...");
            Extractor extractor = new Extractor(outFile, pBitmapFile, stegMethod, algorithm, mode, password);
            extractor.extract();
        }
    }

    private static Map<String, String> parseArguments(String[] args) {
        Map<String, String> params = new HashMap<>();
        for (int i = 0; i < args.length; i++) {
            if (args[i].startsWith("-") && i + 1 < args.length && !args[i + 1].startsWith("-")) {
                params.put(args[i], args[i + 1]);
                i++;
            } else if (args[i].startsWith("-")) {
                params.put(args[i], null);
            }
        }

        return params;
    }
}
