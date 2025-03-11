package com.pcistudio.kms.model;


import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;

@SuppressFBWarnings("EI_EXPOSE_REP")
public record GeneratedKey(SecretKey key, ByteBuffer encryptedKey) {
    public GeneratedKey(SecretKey key, ByteBuffer encryptedKey) {
        this.encryptedKey = encryptedKey.asReadOnlyBuffer();
        this.key = key;
    }
}
