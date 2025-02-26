package com.pcistudio.kms.util;

import com.pcistudio.kms.utils.KeyGenerationUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.function.Supplier;


public class RandomKeyHelper implements TestKeyHelper {
    private static final Logger log = LoggerFactory.getLogger(RandomKeyHelper.class);
    private static final SecureRandom secureRandom = new SecureRandom();

    private SecretKey kek;
    private SecretKey masterKey;
    private Supplier<ByteBuffer> ivSupplier;

    public RandomKeyHelper(int keySize, int ivSizeBytes) {
        kek = KeyGenerationUtil.generateKeyAES(secureRandom, keySize);
        log.trace("KEK={}", KeyGenerationUtil.keyToBase64(kek));
        masterKey = KeyGenerationUtil.generateKeyAES(secureRandom, keySize);
        log.trace("MASTER_KEY={}", KeyGenerationUtil.keyToBase64(masterKey));
        ivSupplier = () -> ByteBuffer.wrap(secureRandom.generateSeed(ivSizeBytes));
    }

    public SecretKey getKEK() {
        return kek;
    }

    public SecretKey getMasterKey() {
        return masterKey;
    }

    public Supplier<ByteBuffer> ivGenerator() {
        return ivSupplier;
    }
}
