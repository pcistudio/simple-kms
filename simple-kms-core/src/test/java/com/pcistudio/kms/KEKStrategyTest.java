package com.pcistudio.kms;

import com.pcistudio.kms.local.AESEncryptionService;
import com.pcistudio.kms.local.InMemoryKeyStorage;
import com.pcistudio.kms.local.LocalKmsService;
import com.pcistudio.kms.util.KeyTestUtil;
import com.pcistudio.kms.utils.KeyGenerationUtil;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class KEKStrategyTest {
    private static final Logger log = LoggerFactory.getLogger(KEKStrategyTest.class);

    @Test
    void encryptDecrypt() throws NoSuchAlgorithmException {
        SecretKey masterKey = KeyTestUtil.getMasterKey();
        log.info("masterKey={}", KeyGenerationUtil.keyToBase64(masterKey));
        KEKStrategy kekStrategy = new KEKStrategy(
                new LocalKmsService(List.of(masterKey), 256),
                new InMemoryKeyStorage(),
                keyInfo -> false,
                256
        );
        ByteBuffer encrypted = kekStrategy.encrypt(ByteBuffer.wrap("test".getBytes()));
        assertNotNull(encrypted);
        ByteBuffer decrypted = kekStrategy.decrypt(encrypted);
        assertNotNull(decrypted);
        assertEquals("test", new String(decrypted.array()));
    }

    @Test
    void encryptDecryptKeyAlreadyInStore() throws NoSuchAlgorithmException {
        SecretKey masterKey = KeyTestUtil.getMasterKey();
        log.info("masterKey={}", KeyGenerationUtil.keyToBase64(masterKey));

        SecretKey kek = KeyTestUtil.getKEK();
        AESEncryptionService aesEncryptionService = new AESEncryptionService(KeyResolvers.master(masterKey), 256, KeyTestUtil.testRandom());
        ByteBuffer encryptedKEK = aesEncryptionService.encrypt(kek.getEncoded());

        InMemoryKeyStorage inMemoryKeyStorage = new InMemoryKeyStorage();
        inMemoryKeyStorage.addKey(encryptedKEK);

        KEKStrategy kekStrategy = new KEKStrategy(
                new LocalKmsService(List.of(masterKey), 256),
                inMemoryKeyStorage,
                keyInfo -> false,
                256
        );
        ByteBuffer encrypted = kekStrategy.encrypt(ByteBuffer.wrap("test".getBytes()));
        assertNotNull(encrypted);
        log.info("{}", encrypted);
        ByteBuffer decrypted = kekStrategy.decrypt(encrypted);
        assertNotNull(decrypted);
        assertEquals("test", new String(decrypted.array()));
    }

}