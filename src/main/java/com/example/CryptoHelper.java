package com.example;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.util.Base64;  // Modifica l'importazione qui

public class CryptoHelper {

    public static String encrypt(String toEncrypt, String key) throws Exception {
        try {
            // Utilizzo MD5 per generare una chiave da 24 byte per TripleDES
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] keyArray = md.digest(key.getBytes("UTF-8"));
            byte[] keyTripleDES = new byte[24];
            System.arraycopy(keyArray, 0, keyTripleDES, 0, 16);
            System.arraycopy(keyArray, 0, keyTripleDES, 16, 8);

            // Impostazioni per TripleDES
            SecretKey secretKey = new SecretKeySpec(keyTripleDES, "DESede");
            Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            // Cifrazione dei dati
            byte[] plainTextBytes = toEncrypt.getBytes("UTF-8");
            byte[] buf = cipher.doFinal(plainTextBytes);
            String base64Bytes = Base64.getEncoder().encodeToString(buf);  // Modifica qui
            return base64Bytes;
        } catch (Exception e) {
            throw new Exception("Errore nella cifratura: " + e.getMessage(), e);
        }
    }

    public static String decrypt(String cipherText, String key) throws Exception {
        try {
            // Generazione chiave con MD5
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] keyArray = md.digest(key.getBytes("UTF-8"));
            byte[] keyTripleDES = new byte[24];
            System.arraycopy(keyArray, 0, keyTripleDES, 0, 16);
            System.arraycopy(keyArray, 0, keyTripleDES, 16, 8);

            // Impostazioni per TripleDES
            SecretKey secretKey = new SecretKeySpec(keyTripleDES, "DESede");
            Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);

            // Decifrazione dei dati
            byte[] encrypedPwdBytes = Base64.getDecoder().decode(cipherText);  // Modifica qui
            byte[] plainTextPwdBytes = cipher.doFinal(encrypedPwdBytes);
            return new String(plainTextPwdBytes);
        } catch (Exception e) {
            throw new Exception("Errore nella decifrazione: " + e.getMessage(), e);
        }
    }
}
