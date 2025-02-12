package com.pcistudio.kms.local;

import com.pcistudio.kms.model.GeneratedKey;
import com.pcistudio.kms.utils.KeyGenerationUtil;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class LocalKmsServiceTest {
    private static final Logger log = LoggerFactory.getLogger(LocalKmsServiceTest.class);

    @Test
    void generateKey() throws NoSuchAlgorithmException {
        SecretKey masterKey = KeyGenerationUtil.generateKeyAES(new SecureRandom(), 256);
        log.info("masterKey={}", KeyGenerationUtil.keyToBase64(masterKey));
        LocalKmsService kmsService = new LocalKmsService(List.of(masterKey), 256);

        GeneratedKey generatedKey = kmsService.generateKey();
        assertNotNull(generatedKey.getKey());
        assertNotNull(generatedKey.getEncryptedKey());

        assertArrayEquals(generatedKey.getKey().getEncoded(), kmsService.decrypt(generatedKey.getEncryptedKey()).array());
    }

    @Test
    void liveRotation() throws NoSuchAlgorithmException {
        SecretKey masterKey = KeyGenerationUtil.generateKeyAES(new SecureRandom(), 256);
        LocalKmsService kmsService = new LocalKmsService(List.of(masterKey), 256);

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