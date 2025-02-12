package com.pcistudio.kms.model;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class EncryptedKeyInfoTest {
    private static final Logger log = LoggerFactory.getLogger(EncryptedKeyInfoTest.class);

    @Test
    void testToString() {
        EncryptedKeyInfo encryptedKeyInfo1 = new EncryptedKeyInfo(1, ByteBuffer.wrap("encryptedKey1".getBytes(StandardCharsets.UTF_8)), Instant.now());
        log.info("key: {}", encryptedKeyInfo1);
        log.info("key: {}", encryptedKeyInfo1);
        assertNotNull(encryptedKeyInfo1.toString());

    }
}