package org.avate;

import javax.crypto.*;
import java.io.*;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.SecureRandom;

/**
 * Encrypt and decrypt file with AES.
 * <p>
 * java Crypto -genkey keyfile
 * java Crypto -encrypt plaintext encrypted keyfile
 * java Crypto -decrypt encrypted decrypted keyfile
 */
public class Crypto {

    private static String help = "Generate key:\n" +
            "java Crypto -genkey keyfile\n" +
            "\n" +
            "encrypt file:\n" +
            "java Crypto -encrypt plaintext encrypted keyfile\n" +
            "\n" +
            "decrypt file:\n" +
            "java Crypto -decrypt encrypted decrypted keyfile";

    public static void main(String[] args) throws GeneralSecurityException, IOException, ClassNotFoundException {
        validate(args);
        if (args[0].equals("-genkey")) {

            KeyGenerator keygen = KeyGenerator.getInstance("AES");
            SecureRandom random = new SecureRandom();
            keygen.init(random);
            SecretKey key = keygen.generateKey();

            try (ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(args[1]))) {
                out.writeObject(key);
            }

        } else {
            int mode;
            switch (args[0]) {
                case "-encrypt":
                    mode = Cipher.ENCRYPT_MODE;
                    break;
                case "-decrypt":
                    mode = Cipher.DECRYPT_MODE;
                    break;
                default:
                    throw new IllegalArgumentException(help);
            }

            try (ObjectInputStream keyIn = new ObjectInputStream(new FileInputStream(args[3]));
                 InputStream in = new FileInputStream(args[1]);
                 OutputStream out = new FileOutputStream(args[2])) {

                Key key = (Key) keyIn.readObject();
                Cipher cipher = Cipher.getInstance("AES");
                cipher.init(mode, key);
                crypt(in, out, cipher);
            }
        }
    }

    private static void crypt(InputStream in, OutputStream out, Cipher cipher) throws IOException, ShortBufferException, BadPaddingException, IllegalBlockSizeException {

        int blockSize = cipher.getBlockSize();
        int outputSize = cipher.getOutputSize(blockSize);
        byte[] inBytes = new byte[blockSize];
        byte[] outBytes = new byte[outputSize];
        int inLength;


        boolean more = true;
        while (more) {
            inLength = in.read(inBytes);
            if (inLength == blockSize) {
                int outLength = cipher.update(inBytes, 0, blockSize, outBytes);
                out.write(outBytes, 0, outLength);
            } else {
                more = false;
            }
            if (inLength > 0) {
                outBytes = cipher.doFinal(inBytes, 0, inLength);
            } else {
                outBytes = cipher.doFinal();
            }
            out.write(outBytes);
        }
    }

    private static void validate(String[] args) {
        if (args == null || args.length < 2) {
            System.out.println(help);
        } else if (!args[0].equals("-genkey") && !args[0].equals("-encrypt") && !args[0].equals("-decrypt")) {
            System.out.println(help);
        } else if ((args[0].equals("-encrypt") || args[0].equals("-decrypt")) || args.length < 4) {
            System.out.println(help);
        }
    }
}
