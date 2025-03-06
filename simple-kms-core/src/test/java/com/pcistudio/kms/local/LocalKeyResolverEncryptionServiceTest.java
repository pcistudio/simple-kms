package com.pcistudio.kms.local;

import com.pcistudio.kms.KeyResolvers;
import com.pcistudio.kms.util.TestKeyHelper;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class LocalKeyResolverEncryptionServiceTest {

    @ParameterizedTest
    @MethodSource("com.pcistudio.kms.util.TestKeyHelpers#all")
    void testEncryptDecrypt(TestKeyHelper testKeyHelper) {
        SecretKey masterKey = testKeyHelper.currentMasterKey();

        LocalKeyResolverEncryptionService aesEncryptionService = new LocalKeyResolverEncryptionService(KeyResolvers.master(masterKey), new AESEncryptionService(testKeyHelper.ivGenerator()));
        ByteBuffer encrypt = aesEncryptionService.encrypt(ByteBuffer.wrap("test".getBytes(StandardCharsets.UTF_8)));
        assertNotNull(encrypt);
        ByteBuffer decrypted = aesEncryptionService.decrypt(encrypt);
        assertNotNull(decrypted);
        assertEquals("test", new String(decrypted.array(), StandardCharsets.UTF_8));
    }


    @ParameterizedTest
    @MethodSource("com.pcistudio.kms.util.TestKeyHelpers#all")
    void testDecryptKey(TestKeyHelper testKeyHelper) {
        SecretKey masterKey = testKeyHelper.currentMasterKey();
        SecretKey kek = testKeyHelper.getKEK();

        LocalKeyResolverEncryptionService aesEncryptionService = new LocalKeyResolverEncryptionService(KeyResolvers.master(masterKey), new AESEncryptionService(testKeyHelper.ivGenerator()));
        ByteBuffer encrypt = aesEncryptionService.encrypt(ByteBuffer.wrap(kek.getEncoded()));
        assertNotNull(encrypt);

        SecretKey decrypted = aesEncryptionService.decryptKey(encrypt);
        assertNotNull(decrypted);
        assertArrayEquals(kek.getEncoded(), decrypted.getEncoded());
    }
}