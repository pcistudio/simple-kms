package org.test;


import com.pcistudio.kms.KmsClientBuilderConfiguration;
import com.pcistudio.kms.engine.EncryptionEngine;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.testcontainers.junit.jupiter.EnabledIfDockerAvailable;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest(classes = Application.class)
@ActiveProfiles("docker-aws")
@Import(KmsClientBuilderConfiguration.class)
@EnabledIfDockerAvailable
class AwsApplicationTest {

    @Autowired
    private EncryptionEngine encryptionEngine;

    @Test
    void test() {
        ByteBuffer encrypt = encryptionEngine.encrypt(ByteBuffer.wrap("hello world".getBytes(StandardCharsets.UTF_8)));

        ByteBuffer decrypt = encryptionEngine.decrypt(encrypt);

        assertEquals("hello world", new String(decrypt.array(), StandardCharsets.UTF_8));
    }
}
