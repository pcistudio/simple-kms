package com.pcistudio.kms.util;

import com.pcistudio.kms.utils.KeyGenerationUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.util.function.Supplier;


public class StaticKeyHelper implements TestKeyHelper {
    private static final Logger log = LoggerFactory.getLogger(StaticKeyHelper.class);

    private static final String MASTER_KEY = "WgBhmFfd+SN2mw6GjCjJ2J9xDtPSoQXUQ+gf6Rc397c=";
    private static final String KEK = "3jFdaAHNNiCoDNTIhKI7jLF2FejoOaWvapnZ501gdko=";

    public StaticKeyHelper() {
        log.trace("MASTER_KEY={}", MASTER_KEY);
        log.trace("KEK={}", KEK);
    }

    public SecretKey getKEK() {
        return KeyGenerationUtil.loadAESKeyFromBase64(KEK);
    }

    public SecretKey getMasterKey() {
        return KeyGenerationUtil.loadAESKeyFromBase64(MASTER_KEY);
    }

    public Supplier<ByteBuffer> ivGenerator() {
        return () -> ByteBuffer.wrap(new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12});
    }
}
