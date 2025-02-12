package com.pcistudio.kms.local;

import com.pcistudio.kms.util.KeyTestUtil;
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

        AESEncryptionService aesEncryptionService = new AESEncryptionService(KeyTestUtil.ivGenerator());
        ByteBuffer encrypt = aesEncryptionService.encrypt(masterKey, ByteBuffer.wrap("test".getBytes()));
        assertNotNull(encrypt);
        ByteBuffer decrypted = aesEncryptionService.decrypt(masterKey, encrypt);
        assertNotNull(decrypted);
        assertEquals("test", new String(decrypted.array(), StandardCharsets.UTF_8));
    }


    @Test
    void testDecryptKey() throws NoSuchAlgorithmException {
        SecretKey masterKey = KeyTestUtil.getMasterKey();
        SecretKey kek = KeyTestUtil.getKEK();

        AESEncryptionService aesEncryptionService = new AESEncryptionService(KeyTestUtil.ivGenerator());
        ByteBuffer encrypt = aesEncryptionService.encrypt(masterKey, ByteBuffer.wrap(kek.getEncoded()));
        assertNotNull(encrypt);

        ByteBuffer decrypt = aesEncryptionService.decrypt(masterKey, encrypt);
        assertNotNull(decrypt);
        assertArrayEquals(kek.getEncoded(), decrypt.array());
    }


}