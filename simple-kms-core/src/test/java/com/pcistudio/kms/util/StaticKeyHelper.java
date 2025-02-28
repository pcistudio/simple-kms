package com.pcistudio.kms.util;

import com.pcistudio.kms.utils.KeyGenerationUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;


public class StaticKeyHelper implements TestKeyHelper {
    private static final Logger log = LoggerFactory.getLogger(StaticKeyHelper.class);

    private final StaticKeys staticKeys;
    private final AtomicInteger counter = new AtomicInteger(0);
    private final AtomicInteger currentMasterKey = new AtomicInteger(0);

    public StaticKeyHelper(StaticKeys staticKeys) {
        this.staticKeys = staticKeys;
        log.trace("MASTER_KEY={}", staticKeys.getMasterKeys());
        log.trace("KEK={}", staticKeys.getKeys());
    }

    public StaticKeyHelper() {
        this(StaticKeys.DEFAULT);
    }

    public SecretKey getKEK() {
        List<String> keys = staticKeys.getKeys();
        String nextKey = keys.get(counter.incrementAndGet() % keys.size());
        return KeyGenerationUtil.loadAESKeyFromBase64(nextKey);
    }

    public List<SecretKey> getMasterKeys() {
        return staticKeys.getMasterKeys().subList(0, currentMasterKey.get() + 1)
                .stream()
                .map(KeyGenerationUtil::loadAESKeyFromBase64)
                .toList();
    }

    public Supplier<ByteBuffer> ivGenerator() {
        return () -> ByteBuffer.wrap(new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12});
    }

    @Override
    public SecretKey currentMasterKey() {
        if (staticKeys.getMasterKeys().size() <= currentMasterKey.get()) throw new IllegalStateException("");

        return KeyGenerationUtil.loadAESKeyFromBase64(staticKeys.getMasterKeys().get(currentMasterKey.get()));
    }

    @Override
    public void rotateKey() {
        currentMasterKey.updateAndGet(current -> {
            if (current + 1 < staticKeys.getMasterKeys().size()) {
                return current + 1;
            }
            return current;
        });
    }
}
