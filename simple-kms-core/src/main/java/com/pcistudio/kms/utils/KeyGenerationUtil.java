package com.pcistudio.kms.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.function.Supplier;

public final class KeyGenerationUtil {
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final Logger log = LoggerFactory.getLogger(KeyGenerationUtil.class);

    private KeyGenerationUtil() {}

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

    public static SecretKey generateKeyAES(int keySize) {
        return generateKeyAES(SECURE_RANDOM, keySize);
    }

    public static Supplier<ByteBuffer> ivSupplier(int bits) {
        if (bits % 8 != 0) {
            throw new IllegalArgumentException("Invalid bits number for initialization vector");
        }
        if (bits < 128) {
            log.warn("IV size is not recommended to be less than 128 . Current size: {}", bits);
        }

        return () -> ByteBuffer.wrap(SECURE_RANDOM.generateSeed(bits/8));
    }

    public static SecretKey loadAESKeyFromBase64(String base64Key) {
        return new SecretKeySpec(Base64.getDecoder().decode(base64Key), "AES");
    }

    public static String keyToBase64(SecretKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

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
