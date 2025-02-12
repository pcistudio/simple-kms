package com.pcistudio.kms.model;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;

public class GeneratedKey {
    private SecretKey key;
    @SuppressFBWarnings({"EI_EXPOSE_REP2", "EI_EXPOSE_REP"})
    private ByteBuffer encryptedKey;

    public SecretKey getKey() {
        return key;
    }

    public GeneratedKey setKey(SecretKey key) {
        this.key = key;
        return this;
    }

    public ByteBuffer getEncryptedKey() {
        return encryptedKey;
    }

    public GeneratedKey setEncryptedKey(ByteBuffer encryptedKey) {
        this.encryptedKey = encryptedKey;
        return this;
    }
}
