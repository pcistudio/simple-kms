package com.pcistudio.kms;

import com.pcistudio.kms.local.LocalAESEncryptionProvider;
import com.pcistudio.kms.util.KeyTestUtil;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class SmartEncryptionTest {

    @Test
    void test() throws NoSuchAlgorithmException {
        EncryptionProviderManager encryptionProviderManager = new EncryptionProviderManager()
                        .register(new LocalAESEncryptionProvider(List.of(KeyTestUtil.getMasterKey()), 256, KeyTestUtil.ivGenerator(), ()-> KeyTestUtil.getKEK()), true);

        SmartEncryption smartEncryption = new SmartEncryption(encryptionProviderManager);

        ByteBuffer encrypted = smartEncryption.encrypt(ByteBuffer.wrap("test".getBytes()));


        ByteBuffer decrypt = smartEncryption.decrypt(encrypted);

        assertEquals("test", new String(decrypt.array(), StandardCharsets.UTF_8));
    }
}