package com.pcistudio.kms.local;

import com.pcistudio.kms.KeyResolvers;
import com.pcistudio.kms.util.KeyTestUtil;
import com.pcistudio.kms.utils.KeyGenerationUtil;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.*;

class AESEncryptionServiceTest {
    private static final Logger log = LoggerFactory.getLogger(AESEncryptionServiceTest.class);

    @Test
    void testEncryptDecrypt() throws NoSuchAlgorithmException {
        SecretKey masterKey = KeyTestUtil.getMasterKey();

        AESEncryptionService aesEncryptionService = new AESEncryptionService(KeyResolvers.master(masterKey), 256, KeyTestUtil.testRandom());
        ByteBuffer encrypt = aesEncryptionService.encrypt("test".getBytes());
        assertNotNull(encrypt);
        ByteBuffer decrypted = aesEncryptionService.decrypt(encrypt);
        assertNotNull(decrypted);
        assertEquals("test", new String(decrypted.array(), StandardCharsets.UTF_8));
    }


    @Test
    void testDecryptKey() throws NoSuchAlgorithmException {
        SecretKey masterKey = KeyTestUtil.getMasterKey();
        SecretKey kek = KeyTestUtil.getKEK();

        AESEncryptionService aesEncryptionService = new AESEncryptionService(KeyResolvers.master(masterKey), 256, KeyTestUtil.testRandom());
        ByteBuffer encrypt = aesEncryptionService.encrypt(kek.getEncoded());
        assertNotNull(encrypt);

        SecretKey decrypted = aesEncryptionService.decryptKey(encrypt);
        assertNotNull(decrypted);
        assertArrayEquals(kek.getEncoded(), decrypted.getEncoded());
    }

    @Test
    void testNestedEncryptDecrypt() throws NoSuchAlgorithmException {
        SecretKey masterKey = KeyTestUtil.getMasterKey();

        SecretKey kek = KeyTestUtil.getKEK();

        AESEncryptionService masterEncryptionService = new AESEncryptionService(KeyResolvers.master(masterKey), 256, KeyTestUtil.testRandom());


        ByteBuffer encrypt = masterEncryptionService.encrypt(kek.getEncoded());
        assertNotNull(encrypt);
        ByteBuffer decrypted = masterEncryptionService.decrypt(encrypt);
        assertNotNull(decrypted);

        AESEncryptionService kekEncryptionService = new AESEncryptionService(KeyResolvers.kek(() -> {
            encrypt.rewind();
            log.trace("kek resolver decrypting key={}", KeyGenerationUtil.toToBase64(encrypt));
            SecretKey secretKey = masterEncryptionService.decryptKey(encrypt);
            log.trace("kek resolver decrypted key={}", KeyGenerationUtil.keyToBase64(secretKey));
            return secretKey;
        }), 256, KeyTestUtil.testRandom());


        ByteBuffer encrypt2 = kekEncryptionService.encrypt("mapping".getBytes());
        assertNotNull(encrypt2);
        ByteBuffer decrypted2 = kekEncryptionService.decrypt(encrypt2);
        assertNotNull(decrypted2);

        assertEquals("mapping", new String(decrypted2.array(), StandardCharsets.UTF_8));
    }

}