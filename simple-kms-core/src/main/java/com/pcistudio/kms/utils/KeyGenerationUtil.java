package com.pcistudio.kms.utils;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class KeyGenerationUtil {
    public static SecretKey generateKey(String algorithm, int keySize, SecureRandom secureRandom) throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance(algorithm);
        keyGen.init(keySize, secureRandom);
        return keyGen.generateKey();
    }

    public static SecretKey generateKeyAES(SecureRandom secureRandom, int keySize) throws NoSuchAlgorithmException {
        if (keySize != 128 && keySize != 192 && keySize != 256) {
            throw new IllegalArgumentException("Key size must be 128, 192, or 256 bits.");
        }
        return generateKey("AES", keySize, secureRandom);
    }

    public static SecretKey loadAESKeyFromBase64(String base64Key) {
        return new SecretKeySpec(Base64.getDecoder().decode(base64Key), "AES");
    }

    public static String keyToBase64(SecretKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public static String toToBase64(ByteBuffer byteBuffer) {
        return Base64.getEncoder().encodeToString(byteBuffer.array());
    }
}
