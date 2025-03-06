package com.pcistudio.kms.local;

import com.pcistudio.kms.util.TestKeyHelper;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class AESEncryptionServiceTest {

    @ParameterizedTest
    @MethodSource("com.pcistudio.kms.util.TestKeyHelpers#all")
    void testEncryptDecrypt(TestKeyHelper testKeyHelper) {
        SecretKey masterKey = testKeyHelper.currentMasterKey();

        AESEncryptionService aesEncryptionService = new AESEncryptionService(testKeyHelper.ivGenerator());
        ByteBuffer encrypt = aesEncryptionService.encrypt(masterKey, ByteBuffer.wrap("test".getBytes()));
        assertNotNull(encrypt);
        ByteBuffer decrypted = aesEncryptionService.decrypt(masterKey, encrypt);
        assertNotNull(decrypted);
        assertEquals("test", new String(decrypted.array(), StandardCharsets.UTF_8));
    }


    @ParameterizedTest
    @MethodSource("com.pcistudio.kms.util.TestKeyHelpers#all")
    void testDecryptKey(TestKeyHelper testKeyHelper) {
        SecretKey masterKey = testKeyHelper.currentMasterKey();
        SecretKey kek = testKeyHelper.getKEK();

        AESEncryptionService aesEncryptionService = new AESEncryptionService(testKeyHelper.ivGenerator());
        ByteBuffer encrypt = aesEncryptionService.encrypt(masterKey, ByteBuffer.wrap(kek.getEncoded()));
        assertNotNull(encrypt);

        ByteBuffer decrypt = aesEncryptionService.decrypt(masterKey, encrypt);
        assertNotNull(decrypt);
        assertArrayEquals(kek.getEncoded(), decrypt.array());
    }
}