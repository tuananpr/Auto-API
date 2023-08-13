package core.core;

import io.restassured.builder.ResponseBuilder;
import io.restassured.response.Response;

import javax.crypto.*;
import javax.crypto.spec.DESedeKeySpec;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.lang.Object;

public class Encrypt {

    public static String pubKey = "-----BEGIN PUBLIC KEY-----\n" +
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvE/pIIm8OEwLWPR/oOrv\n" +
            "ATkR1ivw+g/qZtLzfzmsKQqmynMIHFz6YWqZWvZtR8AbL1dkBG3sfm37VcZ61oBb\n" +
            "jg2ZBLDvjj6fzzlX5VeoeYgVqp2EyZOoHjbpmdmz98kvtQ6kuF/Y6JCvJM3PUZJw\n" +
            "yFJdpJlchaQrdu69Ae7Jqdp+uzCIW8RLNd8RA1+GomDmGN37oh8pL1Nn+8jhDyOO\n" +
            "s99lhjLKjFWfqn+Z1y0hU5KW95GGdMehRPe5nULVevKZq4KrRY6xCjuuhIyaJDAd\n" +
            "qytnbRUujK/F4XNbPIAQtCKhQ1x2hDMsY9fV4rUsoeznLL9q4hK9xO9ltWVo5dQk\n" +
            "4wIDAQAB\n" +
            "-----END PUBLIC KEY-----";

    private static String randomPass(int n) {


        return null;

    }

    public static PublicKey getPublicKeyFromStr(String primaryKeyStr) {
        // Read in the key into a String
        StringBuilder pkcs8Lines = new StringBuilder();
        BufferedReader rdr = new BufferedReader(new StringReader(primaryKeyStr));
        String line;


        try {
            while ((line = rdr.readLine()) != null) {
                pkcs8Lines.append(line);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        // Remove the "BEGIN" and "END" lines, as well as any whitespace

        String pkcs8Pem = pkcs8Lines.toString();
        pkcs8Pem = pkcs8Pem.replace("-----BEGIN PUBLIC KEY-----", "");
        pkcs8Pem = pkcs8Pem.replace("-----END PUBLIC KEY-----", "");
        pkcs8Pem = pkcs8Pem.replaceAll("\\s+", "");

        // Base64 decode the result


        byte[] pkcs8EncodedBytes = org.bouncycastle.util.encoders.Base64.decode(pkcs8Pem);

        // extract the private key

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(pkcs8EncodedBytes);
        KeyFactory kf = null;
        try {
            kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }

        return null;
    }

    private static String encrypt(byte[] data, Key key, String type) {
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(type);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return Base64.getEncoder().encodeToString(cipher.doFinal(data));
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException e) {
            e.printStackTrace();
        }
        return null;

    }

    private static byte[] decrypt(byte[] data, Key key, String type) {
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(type);
            cipher.init(Cipher.DECRYPT_MODE, key);
            return cipher.doFinal(data);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException e) {
            e.printStackTrace();
        }
        return null;

    }


    public static Map<String, Object> encryptRequest(String requestBody) {

        byte[] pass = "chuoi24kytubatky-autoapi".getBytes();

        DESedeKeySpec dks = null;
        Map<String, Object> body = null;

        try {
            dks = new DESedeKeySpec(pass);
            SecretKeyFactory keyFactory = SecretKeyFactory
                    .getInstance("DESede");
            SecretKey secretKey = keyFactory.generateSecret(dks);

            //SecretKey secretKey = new SecretKeySpec(pass, 0, pass.length, "DES");
            PublicKey publicKey = getPublicKeyFromStr(pubKey);

            // Encrypt
            String d = encrypt(requestBody.getBytes(), secretKey, secretKey.getAlgorithm());
            String k = encrypt(pass, publicKey, "RSA/ECB/OAEPPadding");

            // Request
            body = new HashMap<>();
            body.put("d", d);
            body.put("k", k);

        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return body;
    }

    public static Response getDecryptRS(Response responseEncrypt){
        ResponseBuilder responseBuilder = new ResponseBuilder();
        responseBuilder.clone(responseEncrypt);
        responseBuilder.setBody(Base64.getDecoder().decode(responseEncrypt.path("d").toString()));
        return responseBuilder.build();
    }

}
