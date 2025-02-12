package com.pcistudio.kms.model;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.Base64;

public record KeyInfo(int id, SecretKey key, Instant createdAt) {
    public KeyInfo(int id, SecretKey key) {
        this(id, key, Instant.now());
    }

    public EncryptedKeyInfo toEncryptedKeyInfo(ByteBuffer encryptedKey) {
        return new EncryptedKeyInfo(id(), encryptedKey, createdAt());
    }

    public String toString() {
        return "[id=%s, key=%s, createdAt=%s]".formatted(id(), Base64.getEncoder().encodeToString(key().getEncoded()), createdAt());
    }
}