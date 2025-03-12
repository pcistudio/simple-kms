package org.test;


import com.pcistudio.kms.engine.EncryptionEngine;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest
@ActiveProfiles("local")
class LocalApplicationTest {

    private static final Logger log = LoggerFactory.getLogger(LocalApplicationTest.class);

    @Autowired
    private EncryptionEngine encryptionEngine;

    @Test
    void test() {
        ByteBuffer encrypt = encryptionEngine.encrypt(ByteBuffer.wrap("hello world".getBytes(StandardCharsets.UTF_8)));

        ByteBuffer decrypt = encryptionEngine.decrypt(encrypt);

        assertEquals("hello world", new String(decrypt.array(), StandardCharsets.UTF_8));
        log.info("Decrypted test -> {} encryptedSize={}", new String(decrypt.array(), StandardCharsets.UTF_8), encrypt.capacity());
    }
}
