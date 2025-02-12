package com.pcistudio.kms.model;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.Base64;

public record EncryptedKeyInfo(int id, ByteBuffer encryptedKey, Instant createdAt) {
    public KeyInfo toKeyInfo(SecretKey key) {
        return new KeyInfo(id(), key, createdAt());
    }

    public String toString() {
        return "[id=%s, encryptedKey=%s, createdAt=%s]".formatted(id(), Base64.getEncoder().encodeToString(encryptedKey().array()), createdAt());
    }
}