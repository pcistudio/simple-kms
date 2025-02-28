package com.pcistudio.kms.util;

import com.pcistudio.kms.utils.KeyGenerationUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;


public class RandomKeyHelper implements TestKeyHelper {
    private static final Logger log = LoggerFactory.getLogger(RandomKeyHelper.class);
    private static final SecureRandom secureRandom = new SecureRandom();

    private final int keySize;
    private final List<SecretKey> masterKeys = new ArrayList<>();
    private Supplier<ByteBuffer> ivSupplier;

    public RandomKeyHelper(int keySize, int ivSizeBytes) {
        this.keySize = keySize;
        SecretKey masterKey = KeyGenerationUtil.generateKeyAES(secureRandom, keySize);
        masterKeys.add(masterKey);
        log.trace("MASTER_KEY={}", KeyGenerationUtil.keyToBase64(masterKey));
        ivSupplier = () -> ByteBuffer.wrap(secureRandom.generateSeed(ivSizeBytes));
    }

    public SecretKey getKEK() {
        SecretKey kek = KeyGenerationUtil.generateKeyAES(secureRandom, keySize);
        log.trace("KEK={}", KeyGenerationUtil.keyToBase64(kek));
        return kek;
    }

    public List<SecretKey> getMasterKeys() {
        return masterKeys;
    }

    public Supplier<ByteBuffer> ivGenerator() {
        return ivSupplier;
    }

    @Override
    public SecretKey currentMasterKey() {
        return masterKeys.get(masterKeys.size() - 1);
    }

    @Override
    public synchronized void rotateKey() {
        SecretKey masterKey = KeyGenerationUtil.generateKeyAES(secureRandom, keySize);
        masterKeys.add(masterKey);
        log.trace("MASTER_KEY={}", KeyGenerationUtil.keyToBase64(masterKey));
    }
}
