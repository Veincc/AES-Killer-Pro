package burp.strategy.impl;

import burp.strategy.CipherStrategyFactory;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class Sm4CbcPkcs7PaddingStrategyFactory implements CipherStrategyFactory {
    @Override
    public String encrypt(String message, String key, String iv, String mode) throws Exception {
        Cipher cipher = Cipher.getInstance(mode); // SM4/CBC/PKCS7Padding
        SecretKey secretKey = new SecretKeySpec(key.getBytes(), "SM4");
        IvParameterSpec ivSpec = new IvParameterSpec(iv.getBytes());
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    @Override
    public String decrypt(String message, String key, String iv, String mode) throws Exception {
        Cipher cipher = Cipher.getInstance(mode); // SM4/CBC/PKCS7Padding
        SecretKey secretKey = new SecretKeySpec(key.getBytes(), "SM4");
        IvParameterSpec ivSpec = new IvParameterSpec(iv.getBytes());
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(message));
        return new String(decryptedBytes);
    }
}