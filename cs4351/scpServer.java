package cs4351;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Random;
import java.util.Scanner;

public class scpServer {
    public static void main(String[] args) {

        System.out.println("Secure protocol server started.");
        int sessionID = 0; // assign incremental session ids to each client connection

        try {
            ServerSocket s = new ServerSocket(8008);
            // The server runs until an error occurs
            // or is stopped externally
            for (;;) {
                Socket incoming = s.accept();
                // start a connection with the client
                // in a new thread and wait for another
                // connection
                new scpServer.ClientHandler(incoming, ++sessionID).start();
                // start() causes the thread to begin execution
                // the JVM calls the run() method of this thread
            }
        } catch (Exception e) {
            System.out.println("Error: " + e);
        }
        System.out.println("Secure protocol server stopped.");
    }

    private static class ClientHandler extends Thread {

        protected Socket incoming;
        protected int id;

        public ClientHandler(Socket incoming, int id) {
            this.incoming = incoming;
            this.id = id;
        }

        public void run() {
            try {
                // in and out for socket communication using strings
                BufferedReader in
                        = new BufferedReader(
                        new InputStreamReader(incoming.getInputStream()));
                PrintWriter out
                        = new PrintWriter(
                        new OutputStreamWriter(incoming.getOutputStream()));
                // We could use Base64 encoding and communicate with strings using in and out
                // However, we show here how to send and receive serializable java objects
                ObjectInputStream objectInput = new ObjectInputStream(incoming.getInputStream());
                ObjectOutputStream objectOutput = new ObjectOutputStream(incoming.getOutputStream());

                byte[] serverRandomBytes, clientRandomBytes;
                Cipher cipherRSA, cipherEnc;

                // read and send certificate
                try {
                    // read and send certificate to client
                    File file = new File("cs4351/server1Certificate.txt");
                    Scanner input = new Scanner(file);
                    String line;
                    while (input.hasNextLine()) {
                        line = input.nextLine();
                        out.println(line);
                    }
                    out.flush();
                } catch (FileNotFoundException e){
                    System.out.println("certificate file not found");
                    return;
                }
                File clientCert = new File("cs4351/clientCert.txt");
                FileWriter fileWriter;
                // Receive Client certificate
                // Will need to verify the certificate and extract the Client public keys
                try {
                    fileWriter = new FileWriter("clientCert.txt");
                    String line = in.readLine();
                    fileWriter.write(line+"\n");
                    while (!"-----END SIGNATURE-----".equals(line)) {
                        line = in.readLine();
                        fileWriter.write(line+"\n");
                    }
                    fileWriter.flush();
                    fileWriter.close();
                } catch (Exception ex) {
                    System.out.println("problem reading the certificate from client");
                    return;
                }

                PublicKey serverKey1 = PemUtils.readPublicKey("serverkey1.pem");
                PublicKey serverKey2 = PemUtils.readPublicKey("serverkey2.pem");
                PublicKey pubKey1 = PemUtils.readPublicKey("publicKey1.pem");
                PublicKey pubKey2 = PemUtils.readPublicKey("publicKey2.pem");

                // generate random bytes for shared secret
                serverRandomBytes = new byte[8];
                new Random().nextBytes(serverRandomBytes);

                // encrypt and send random bytes and signature
                try {
                    cipherEnc = Cipher.getInstance("SHA256");
                    cipherEnc.init(Cipher.ENCRYPT_MODE, pubKey1);
                    byte[] encryptedBytes = cipherEnc.doFinal(serverRandomBytes);
                    objectOutput.writeObject(encryptedBytes);
                    cipherEnc.init(Cipher.ENCRYPT_MODE, pubKey1);
                    cipherEnc = Cipher.getInstance("SHA1withRSA");
                    byte[] signatureBytes = cipherEnc.doFinal(encryptedBytes);
                    objectOutput.writeObject(signatureBytes);
                } catch (Exception ex) {
                    System.out.println("Error computing or sending the signature for random bytes");
                    return;
                }

                // receive random bytes/signature
                try {
                    // initialize object streams
                    objectOutput = new ObjectOutputStream(incoming.getOutputStream());
                    objectInput = new ObjectInputStream(incoming.getInputStream());
                    // receive encrypted random bytes from server
                    cipherRSA = Cipher.getInstance("SHA256");
                    cipherRSA.init(Cipher.DECRYPT_MODE, pubKey1);

                    byte[] encryptedBytes = (byte[]) objectInput.readObject();

                    clientRandomBytes = cipherRSA.doFinal(encryptedBytes);
                    // receive signature of hash of random bytes from server
                    byte[] signatureBytes = (byte[]) objectInput.readObject();
                    // will need to verify the signature and decrypt the random bytes

                } catch (Exception ex) {
                    System.out.println("Problem with receiving random bytes from server");
                    return;
                }
                byte[] sharedSecret = new byte[16];

                System.arraycopy(serverRandomBytes, 0, sharedSecret, 0, 8);
                System.arraycopy(clientRandomBytes, 0, sharedSecret, 8, 8);
                SecretKeySpec secretKey;

                byte[] iv;
                try {
                    // we will use AES encryption, CBC chaining and PCS5 block padding
                    cipherEnc = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    // generate an AES key derived from randomBytes array
                    secretKey = new SecretKeySpec(sharedSecret, "AES");
                    cipherEnc.init(Cipher.ENCRYPT_MODE, secretKey);
                    iv = cipherEnc.getIV();
                    objectOutput.writeObject(iv);
                } catch (/** IOException | **/ NoSuchAlgorithmException
                        | NoSuchPaddingException | InvalidKeyException e) {
                    System.out.println("error setting up the AES encryption");
                    return;
                }
                byte[] encryptedByte;
                String str;

                // loop to keep communication going
                for (;;) {
                    // get the encrypted bytes from the client as an object
                    encryptedByte = (byte[]) objectInput.readObject();
                    // decrypt the bytes
                    str = new String(cipherEnc.doFinal(encryptedByte));
                    cipherEnc.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
                    encryptedByte = cipherEnc.doFinal(str.getBytes());
                    objectOutput.writeObject(encryptedByte);
                    objectOutput.flush();
                    iv = (byte[]) objectInput.readObject();
                    cipherEnc.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));

                    // print the message received from the client
                    System.out.println("Received from session " + id + ": " + str);
                    if (str.trim().equals("BYE")) {
                        break;
                    }
                }
                System.out.println("Session " + id + " ended.");
                incoming.close();

            } catch (Exception e) {
                System.out.println("Error: " + e);
                e.printStackTrace();
            }
        }
    }
}