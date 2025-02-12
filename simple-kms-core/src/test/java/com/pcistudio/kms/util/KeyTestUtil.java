package com.pcistudio.kms.util;

import com.pcistudio.kms.utils.KeyGenerationUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.function.Supplier;


public class KeyTestUtil {
    private static final Logger log = LoggerFactory.getLogger(KeyTestUtil.class);
    private static final String MASTER_KEY = "WgBhmFfd+SN2mw6GjCjJ2J9xDtPSoQXUQ+gf6Rc397c=";
    private static final String KEK = "3jFdaAHNNiCoDNTIhKI7jLF2FejoOaWvapnZ501gdko=";
    private static final SecureRandom secureRandom = new SecureRandom();

    public static SecretKey getKEK() throws NoSuchAlgorithmException {
//        return KeyGenerationUtil.generateKeyAES(secureRandom, 256);
        return KeyGenerationUtil.loadAESKeyFromBase64(KEK);
    }

    public static SecretKey getMasterKey() throws NoSuchAlgorithmException {
//        return KeyGenerationUtil.generateKeyAES(secureRandom, 256);
        return KeyGenerationUtil.loadAESKeyFromBase64(MASTER_KEY);
    }

    public static Supplier<ByteBuffer> ivGenerator() {
//        return () -> ByteBuffer.wrap(secureRandom.generateSeed(12));
        return () -> ByteBuffer.wrap(new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12});
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        SecretKey masterKey = getMasterKey();
        log.info("masterKey={}", KeyGenerationUtil.keyToBase64(masterKey));
        SecretKey kek = getKEK();
        log.info("kek={}", KeyGenerationUtil.keyToBase64(kek));
    }
}
