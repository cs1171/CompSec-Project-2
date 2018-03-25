import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class EchoClientSkeleton {
    // This code includes socket code originally provided
    // by Dr. Yoonsik Cheon at least 10 years ago.
    // This version used for Computer Security, Spring 2018.    
    public static void main(String[] args) {

        //String host = "localhost";
        String host = "cspl000.utep.edu";
        BufferedReader in; // for reading strings from socket
        PrintWriter out;   // for writing strings to socket
        ObjectInputStream objectInput;   // for reading objects from socket        
        ObjectOutputStream objectOutput; // for writing objects to socket
        Cipher cipheRSA, cipherEnc;
        byte[] clientRandomBytes;
        PublicKey[] pkpair;
        Socket socket;
        // Handshake
        try {
            // socket initialization
            socket = new Socket(host, 8008);
            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            out = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()));
        } catch (IOException e) {
            System.out.println("socket initialization error");
            return;
        }
        // Send hello to server
        out.println("hello");
        out.flush();
        // Receive Server certificate
        // Will need to verify the certificate and extract the Server public keys
        try {
            String line = in.readLine();
            while (!"-----END SIGNATURE-----".equals(line)) {
                line = in.readLine();
            }
        } catch (IOException e) {
            System.out.println("problem reading the certificate from server");
            return;
        }

        try {   
            // read and send certificate to server
            File file = new File("client1Certificate.txt");
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
        try {
            // initialize object streams
            objectOutput = new ObjectOutputStream(socket.getOutputStream());
            objectInput = new ObjectInputStream(socket.getInputStream());
            // receive encrypted random bytes from server
            byte[] encryptedBytes = (byte[]) objectInput.readObject();
            // receive signature of hash of random bytes from server
            byte[] signatureBytes = (byte[]) objectInput.readObject();
            // will need to verify the signature and decrypt the random bytes
            
        } catch (IOException | ClassNotFoundException ex) { 
            System.out.println("Problem with receiving random bytes from server");
            return;
        }
        // generate random bytes for shared secret
        clientRandomBytes = new byte[8];
        // the next line would initialize the byte array to random values
        // new Random().nextBytes(clientRandomBytes);
        // here we leave all bytes to zeroes.
        // The server shifts to testing mode when receiving all byte 
        // values zeroes and uses all zeroes as shared secret
        try {
            // you need to encrypt and send the the random byte array
            // here, precalculated encrypted bytes using zeroes as shared secret
            byte[] encryptedBytes = {-127,-39,2,29,-88,-43,-17,-70,-115,94,-85,
                -126,-56,97,36,81,106,33,-75,125,-7,89,110,37,-10,19,-70,-112,
                -19,-103,-109,10,-86,-26,-43,115,-89,49,-6,62,87,-113,82,-93,
                -125,21,-83,1,-41,83,-104,54,109,-112,118,30,-107,123,62,-34,
                52,-15,66,119,110,-53,-79,104,-101,50,18,-99,101,-124,-13,-45,
                121,-48,107,-12,93,85,-12,-92,-83,-75,-123,-51,-60,-20,-34,
                -105,-86,-23,-105,-49,-42,17,-77,-121,-29,-45,-39,22,-49,-73,
                110,53,-20,47,8,-10,60,-36,-40,25,27,70,58,-126,-98,61,-13,94,
                -57,11,96,-57};
            objectOutput.writeObject(encryptedBytes);
            // you need to generate a signature of the hash of the random bytes
            // here, precalculated signature using the client secret key associated with the certificate
            byte[] signatureBytes = {48, 17, -50, -3, 125, -10, -88, -6, -33, 
                10, 14, 93, 112, 14, 74, -32, -27, -56, -86, 91, -101, 87, 117, 
                109, 41, 1, 6, -4, -94, 47, 83, -46, 44, 76, 61, 83, 72, 36, 
                -127, -44, 5, -77, 121, 19, 107, 91, -123, 31, 123, -22, 114, 
                -79, 103, 39, 122, -122, 73, -99, -16, 22, 20, 37, 27, 14, 31, 
                11, 36, 12, -118, 38, 120, 47, 57, -110, -27, -14, 31, -37, 85, 
                -56, -108, 100, -71, 29, 26, 26, 8, -47, 49, -66, 88, 6, 73, 
                124, -35, 9, 16, 59, 44, -113, 62, -61, -31, 58, -116, 113, 35, 
                119, 5, -117, -91, -109, -8, 123, -40, -105, -96, -71, -50, 41, 
                78, -113, -32, -75, 36, -29, 89, -51};
            objectOutput.writeObject(signatureBytes);
        } catch (IOException e) {
            System.out.println("error computing or sending the signature for random bytes");
            return;
        }
        // initialize the shared secret with all zeroes
        // will need to generate from a combination of the server and 
        // the client random bytes generated
        byte[] sharedSecret = new byte[16];
        //System.arraycopy(serverRandomBytes, 0, sharedSecret, 0, 8);
        //System.arraycopy(clientRandomBytes, 8, sharedSecret, 8, 8);
        try {
            // we will use AES encryption, CBC chaining and PCS5 block padding
            cipherEnc = Cipher.getInstance("AES/CBC/PKCS5Padding");            
            // generate an AES key derived from randomBytes array
            SecretKeySpec secretKey = new SecretKeySpec(sharedSecret, "AES");
            cipherEnc.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] iv = cipherEnc.getIV();
            objectOutput.writeObject(iv);
        } catch (IOException | NoSuchAlgorithmException 
                | NoSuchPaddingException | InvalidKeyException e) {
            System.out.println("error setting up the AES encryption");
            return;
        }
        try {
            // Encrypted communication
            System.out.println("Starting messages to the server. Type messages, type BYE to end");    
            Scanner userInput = new Scanner(System.in);
            boolean done = false;
            while (!done) {
                // Read message from the user
                String userStr = userInput.nextLine();
                // Encrypt the message
                byte[] encryptedBytes = cipherEnc.doFinal(userStr.getBytes());
                // Send encrypted message as an object to the server
                objectOutput.writeObject(encryptedBytes);
                // If user says "BYE", end session
                if (userStr.trim().equals("BYE")) {
                    System.out.println("client session ended");
                    done = true;
                } else {
                    // Wait for reply from server,
                    encryptedBytes = (byte[]) objectInput.readObject();
                    // will need to decrypt and print the reply to the screen
                    System.out.println("Encrypted echo received, but not decrypted");
                }
            }            
        } catch (IllegalBlockSizeException | BadPaddingException 
                | IOException | ClassNotFoundException e) {
            System.out.println("error in encrypted communication with server");
        }
    }
}
