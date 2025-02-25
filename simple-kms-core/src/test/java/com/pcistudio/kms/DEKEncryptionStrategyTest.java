package com.pcistudio.kms;

import com.pcistudio.kms.local.AESEncryptionService;
import com.pcistudio.kms.local.LocalKmsService;
import com.pcistudio.kms.model.EncryptionData;
import com.pcistudio.kms.util.KeyTestUtil;
import com.pcistudio.kms.utils.KeyGenerationUtil;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class DEKEncryptionStrategyTest {
    private static final Logger log = LoggerFactory.getLogger(DEKEncryptionStrategyTest.class);

    @Test
    void encryptDecrypt() throws NoSuchAlgorithmException {
        SecretKey masterKey = KeyTestUtil.getMasterKey();
        log.info("masterKey={}", KeyGenerationUtil.keyToBase64(masterKey));
        AESEncryptionService aesEncryptionService = new AESEncryptionService(KeyTestUtil.ivGenerator());
        DEKEncryptionStrategy kekStrategy = new DEKEncryptionStrategy(new LocalKmsService(List.of(masterKey), 256, aesEncryptionService, null), aesEncryptionService);

        EncryptionData encryptionData = kekStrategy.encrypt(ByteBuffer.wrap("test".getBytes()));
        assertNotNull(encryptionData);
        ByteBuffer decrypted = kekStrategy.decrypt(encryptionData);
        assertNotNull(decrypted);
        assertEquals("test", new String(decrypted.array()));
    }

    @Test
    void encrypt100DecryptBack() throws NoSuchAlgorithmException {
        SecretKey masterKey = KeyTestUtil.getMasterKey();
        log.info("masterKey={}", KeyGenerationUtil.keyToBase64(masterKey));
        AESEncryptionService aesEncryptionService = new AESEncryptionService(KeyTestUtil.ivGenerator());
        DEKEncryptionStrategy kekStrategy = new DEKEncryptionStrategy(new LocalKmsService(List.of(masterKey), 256, aesEncryptionService), aesEncryptionService);

        List<EncryptionData> list = new ArrayList<>();
        for (int i = 0; i < 100; i++) {
            EncryptionData encryptionData = kekStrategy.encrypt(ByteBuffer.wrap(("test" + i).getBytes()));
            list.add(encryptionData);
        }

        for (int i = 0; i < 100; i++) {
            ByteBuffer decrypted = kekStrategy.decrypt(list.get(i));
            assertNotNull(decrypted);
            assertEquals("test" + i, new String(decrypted.array(), StandardCharsets.UTF_8));
        }
    }


}