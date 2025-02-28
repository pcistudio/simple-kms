package com.pcistudio.kms.utils;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class KeyGenerationUtil {
    public static SecretKey generateKey(String algorithm, int keySize, SecureRandom secureRandom) throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance(algorithm);
        keyGen.init(keySize, secureRandom);
        return keyGen.generateKey();
    }

    public static SecretKey generateKeyAES(SecureRandom secureRandom, int keySize) {
        if (keySize != 128 && keySize != 192 && keySize != 256) {
            throw new IllegalArgumentException("Key size must be 128, 192, or 256 bits.");
        }
        try {
            return generateKey("AES", keySize, secureRandom);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Algorithm not valid", e);
        }
    }

    public static SecretKey loadAESKeyFromBase64(String base64Key) {
        return new SecretKeySpec(Base64.getDecoder().decode(base64Key), "AES");
    }

    public static String keyToBase64(SecretKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    //TODO check that base64 is in one line
    public static String toToBase64(ByteBuffer byteBuffer) {
        return toToBase64(byteBuffer.array());
    }

    public static String toToBase64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    public static ByteBuffer fromBase64(String value) {
        return ByteBuffer.wrap(Base64.getDecoder().decode(value.getBytes(StandardCharsets.UTF_8)));
    }
}
