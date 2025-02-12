package com.pcistudio.kms.local;

import com.pcistudio.kms.KeyResolvers;
import com.pcistudio.kms.util.KeyTestUtil;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.*;

class AESKeyResolverEncryptionServiceTest {
    private static final Logger log = LoggerFactory.getLogger(AESEncryptionServiceTest.class);

    @Test
    void testEncryptDecrypt() throws NoSuchAlgorithmException {
        SecretKey masterKey = KeyTestUtil.getMasterKey();

        AESKeyResolverEncryptionService aesEncryptionService = new AESKeyResolverEncryptionService(KeyResolvers.master(masterKey), new AESEncryptionService(KeyTestUtil.ivGenerator()));
        ByteBuffer encrypt = aesEncryptionService.encrypt(ByteBuffer.wrap("test".getBytes(StandardCharsets.UTF_8)));
        assertNotNull(encrypt);
        ByteBuffer decrypted = aesEncryptionService.decrypt(encrypt);
        assertNotNull(decrypted);
        assertEquals("test", new String(decrypted.array(), StandardCharsets.UTF_8));
    }


    @Test
    void testDecryptKey() throws NoSuchAlgorithmException {
        SecretKey masterKey = KeyTestUtil.getMasterKey();
        SecretKey kek = KeyTestUtil.getKEK();

        AESKeyResolverEncryptionService aesEncryptionService = new AESKeyResolverEncryptionService(KeyResolvers.master(masterKey),  new AESEncryptionService(KeyTestUtil.ivGenerator()));
        ByteBuffer encrypt = aesEncryptionService.encrypt(ByteBuffer.wrap(kek.getEncoded()));
        assertNotNull(encrypt);

        SecretKey decrypted = aesEncryptionService.decryptKey(encrypt);
        assertNotNull(decrypted);
        assertArrayEquals(kek.getEncoded(), decrypted.getEncoded());
    }

//    @Test
//    void testNestedEncryptDecrypt() throws NoSuchAlgorithmException {
//        SecretKey masterKey = KeyTestUtil.getMasterKey();
//
//        SecretKey kek = KeyTestUtil.getKEK();
//
//        AESKeyResolverEncryptionService masterEncryptionService = new AESKeyResolverEncryptionService(KeyResolvers.master(masterKey),  new AESEncryptionService(KeyTestUtil.ivGenerator()));
//
//
//        ByteBuffer encrypt = masterEncryptionService.encrypt(ByteBuffer.wrap(kek.getEncoded()));
//        assertNotNull(encrypt);
//        ByteBuffer decrypted = masterEncryptionService.decrypt(encrypt);
//        assertNotNull(decrypted);
//
//        AESKeyResolverEncryptionService kekEncryptionService = new AESKeyResolverEncryptionService(KeyResolvers.kek(() -> {
//            encrypt.rewind();
//            log.trace("kek resolver decrypting key={}", KeyGenerationUtil.toToBase64(encrypt));
//            SecretKey secretKey = masterEncryptionService.decryptKey(encrypt);
//            log.trace("kek resolver decrypted key={}", KeyGenerationUtil.keyToBase64(secretKey));
//            return secretKey;
//        }), 256, KeyTestUtil.ivGenerator());
//
//
//        ByteBuffer encrypt2 = kekEncryptionService.encrypt(ByteBuffer.wrap("mapping".getBytes(StandardCharsets.UTF_8)));
//        assertNotNull(encrypt2);
//        ByteBuffer decrypted2 = kekEncryptionService.decrypt(encrypt2);
//        assertNotNull(decrypted2);
//
//        assertEquals("mapping", new String(decrypted2.array(), StandardCharsets.UTF_8));
//    }
}