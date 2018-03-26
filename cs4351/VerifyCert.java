package cs4351;

import java.io.*;
import java.security.*;
import java.util.*;

class VerifyCert {
    private static String fileName = "cs4351/";

    public static void main(String[] args) {
        // This program reads a certificate file named certificate.txt
        // and the certificate authority's public key file CApublicKey.pem,
        // parses the certificate for formatting,
        // and uses the public key to verify the signature.
        // The program uses PemUtils.java.
        // Written by Luc Longpre for Computer Security, Spring 2018

        BufferedReader input;
        PublicKey pubKey;
        String contents;
        String signature;
        Signature sig;

        // get the public key of the signer from file
        // Read public key from file
        pubKey = PemUtils.readPublicKey("cs4351/CApublicKey.pem");
        if (pubKey == null) {
            return;
        }

        try {
            System.out.println("Reading certificate");
            input = new BufferedReader(new FileReader(fileName));
        } catch (FileNotFoundException e) {
            System.out.println("File not found, " + e);
            return;
        }
        PublicKey[] pk = vCert(input);
        if (pk==null)
            System.out.println("certificate verification failed");
        else
            System.out.println("certificate verification succeeded");
    }

    public void setFileName(String fn) {
        this.fileName = fileName + fn;
    }

    public static PublicKey[] vCert(BufferedReader input) {
        PublicKey pubKey;
        String contents;
        String encPubKey;
        String sigPubKey;
        String signature;
        Signature sig;

        // get the certificate and signature
        try {
            String line = input.readLine();
            if (!"-----BEGIN INFORMATION-----".equals(line)) {
                System.out.println("expecting:-----BEGIN INFORMATION-----");
                System.out.println("got:" + line);
                return null;
            }
            contents = line + "\r\n";
            line = input.readLine();
            while (line != null && !"-----END INFORMATION-----".equals(line)) {
                contents += line + "\r\n";
                line = input.readLine();
            }
            contents += line + "\r\n";
            line = input.readLine();
            if (line != null && !"-----BEGIN PUBLIC KEY-----".equals(line)) {
                System.out.println("expecting:-----BEGIN PUBLIC KEY-----");
                System.out.println("got:" + line);
                return null;
            }
            encPubKey = "";
            while (line != null && !"-----END PUBLIC KEY-----".equals(line)) {
                contents += line + "\r\n";
                encPubKey += line + "\r\n";
                line = input.readLine();
            }
            contents += line + "\r\n";
            encPubKey += line + "\r\n";
            line = input.readLine();
            while (line != null && line.trim().length() == 0) {
                contents += line + "\r\n";
                line = input.readLine();
            }
            if (!"-----BEGIN PUBLIC KEY-----".equals(line)) {
                System.out.println("expecting:-----BEGIN PUBLIC KEY-----");
                System.out.println("got:" + line);
                return null;
            }
            sigPubKey = "";
            while (line != null && !"-----END PUBLIC KEY-----".equals(line)) {
                contents += line + "\r\n";
                sigPubKey += line + "\r\n";
                line = input.readLine();
            }
            contents += line + "\r\n";
            sigPubKey += line + "\r\n";
            line = input.readLine();
                        while (line != null && line.trim().length() == 0) {
                contents += line + "\r\n";
                line = input.readLine();
            }
            if (!"-----BEGIN SIGNATURE-----".equals(line)) {
                System.out.println("expecting:-----BEGIN SIGNATURE-----");
                System.out.println("got:" + line);
                return null;
            }
            signature = input.readLine();
            line = input.readLine();
            if (!"-----END SIGNATURE-----".equals(line)) {
                System.out.println("expecting:-----END SIGNATURE-----");
                System.out.println("got:" + line);
                return null;
            }
        } catch (IOException e) {
            System.out.println("error occurred while reading the certificate, " + e);
            return null;
        } 
        PublicKey[] pkpair = new PublicKey[2];
        // construct the encryption public key retrieved from the certificate
        pkpair[0] = PemUtils.constructPublicKey(encPubKey);
        // construct the signature public key retrieved from the certificate
        pkpair[1] = PemUtils.constructPublicKey(sigPubKey);

        try {
            // get the public key of the signer from file
            // Read public key from file
            pubKey = PemUtils.readPublicKey("cs4351/CApublicKey.pem");
            if (pubKey == null) {
                return null;
            }
            // verify the signature
            sig = Signature.getInstance("SHA1withRSA");
            sig.initVerify(pubKey);
            sig.update(contents.getBytes());
            if (sig.verify(Base64.getDecoder().decode(signature))) {
                //Signature verification succeeded
                return pkpair;
            } else {
                //Signature verification failed
                return null;
            }
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            System.out.println("error occurred while trying to verify signature" + e);
            return null;
        }
    }
}
