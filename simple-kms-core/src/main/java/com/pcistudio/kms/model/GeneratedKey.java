package com.pcistudio.kms.model;


import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;


public final class GeneratedKey {
    private final SecretKey key;
    private final ByteBuffer encryptedKey;

    public GeneratedKey(SecretKey key, ByteBuffer encryptedKey) {
        this.key = key;
        this.encryptedKey = encryptedKey.asReadOnlyBuffer();
    }

    public SecretKey getKey() {
        return key;
    }

    @SuppressFBWarnings("EI_EXPOSE_REP")
    public ByteBuffer getEncryptedKey() {
        return encryptedKey;
    }

}
