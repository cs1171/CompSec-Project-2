package cs4351;

import java.io.*;
import java.security.*;
import java.util.Base64;
import javax.crypto.*;

class Encrypt {

    public static void main(String[] args) {
        // This program reads a public key from file
        // converts a message string to a byte array,
        // encrypts the message with the public key,
        // encodes using Base64 encoding, 
        // and saves the encrypted message.
        // Written by Luc Longpre for Computer Security, Spring 2018
        
        ObjectInputStream objectInput;
        File file;
        PublicKey pubKey;
        Cipher cipher;
        String messageToEncrypt = "Computer Security Spring 2018";
        System.out.println("The plaintext is: " + messageToEncrypt);       
        byte[] encryptedByteArray;
        String encryptedString;

        // Read public key from file
        pubKey = PemUtils.readPublicKey("publicKey.pem");
        
        encryptedByteArray = encrypt(pubKey, messageToEncrypt.getBytes());
        encryptedString = Base64.getEncoder().encodeToString(encryptedByteArray);
        System.out.println("The encrypted string is: " + encryptedString);

        file = new File("cs4351/encryptedMessage.txt");
        try (PrintWriter output = new PrintWriter(file)) {
            output.print(encryptedString);
        } catch (Exception e) {
            System.out.println("Could not create encryptedMessage file");
        }
    }
        public static byte[] encrypt(PublicKey pubKey, byte[] bytes) {
            // encrypts a byte array using a public key
            // and returns the encryption as a byte array
        
        Cipher cipher;
        byte[] encryptedByteArray;

        try {
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
            System.out.println("Could not initialize encryption");
            return null;
        }
        try {
            return cipher.doFinal(bytes);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            System.out.println("Encryption error");
            return null;
        }    
    }
}
