package com.pcistudio.kms.local;

import com.pcistudio.kms.model.GeneratedKey;
import com.pcistudio.kms.util.TestKeyHelper;
import com.pcistudio.kms.utils.KeyGenerationUtil;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class LocalKmsServiceTest {
    private static final Logger log = LoggerFactory.getLogger(LocalKmsServiceTest.class);

    @ParameterizedTest
    @MethodSource("com.pcistudio.kms.util.TestKeyHelpers#all")
    void generateKey(TestKeyHelper testKeyHelper) {
        SecretKey masterKey = KeyGenerationUtil.generateKeyAES(new SecureRandom(), 256);
        log.info("masterKey={}", KeyGenerationUtil.keyToBase64(masterKey));
        LocalKmsService kmsService = new LocalKmsService(List.of(masterKey), new AESEncryptionService(testKeyHelper.ivGenerator()), testKeyHelper.getKEKSupplier());

        GeneratedKey generatedKey = kmsService.generateKey();
        assertNotNull(generatedKey.getKey());
        assertNotNull(generatedKey.getEncryptedKey());

        assertArrayEquals(generatedKey.getKey().getEncoded(), kmsService.decrypt(generatedKey.getEncryptedKey()).array());
    }

    @ParameterizedTest
    @MethodSource("com.pcistudio.kms.util.TestKeyHelpers#all")
    void liveRotation(TestKeyHelper testKeyHelper) {
        SecretKey masterKey = KeyGenerationUtil.generateKeyAES(new SecureRandom(), 256);
        LocalKmsService kmsService = new LocalKmsService(List.of(masterKey), new AESEncryptionService(testKeyHelper.ivGenerator()), testKeyHelper.getKEKSupplier());

        GeneratedKey generatedKey = kmsService.generateKey();
        assertNotNull(generatedKey.getKey());
        assertNotNull(generatedKey.getEncryptedKey());

        assertArrayEquals(generatedKey.getKey().getEncoded(), kmsService.decrypt(generatedKey.getEncryptedKey()).array());

        SecretKey masterKey2 = KeyGenerationUtil.generateKeyAES(new SecureRandom(), 256);
        kmsService.liveRotation(masterKey2);
        GeneratedKey generatedKey2 = kmsService.generateKey();
        assertArrayEquals(generatedKey2.getKey().getEncoded(), kmsService.decrypt(generatedKey2.getEncryptedKey()).array());

        generatedKey.getEncryptedKey().rewind();
        assertArrayEquals(generatedKey.getKey().getEncoded(), kmsService.decrypt(generatedKey.getEncryptedKey()).array());
    }
}