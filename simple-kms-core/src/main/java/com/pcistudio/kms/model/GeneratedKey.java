package com.pcistudio.kms.model;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;

public class GeneratedKey {
    private SecretKey key;
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
