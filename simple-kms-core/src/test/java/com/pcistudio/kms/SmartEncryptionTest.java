package com.pcistudio.kms;

import com.pcistudio.kms.local.LocalAESEncryptionProvider;
import com.pcistudio.kms.serialization.Serializer;
import com.pcistudio.kms.util.TestKeyHelper;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SmartEncryptionTest {

    @ParameterizedTest
    @MethodSource("com.pcistudio.kms.util.TestKeyHelpers#all")
    void test(TestKeyHelper testKeyHelper) {
        LocalAESEncryptionProvider localAESEncryptionProvider = LocalAESEncryptionProvider.builder()
                .masterKeysHistory(List.of(testKeyHelper.getMasterKey()))
                .ivSupplier(testKeyHelper.ivGenerator())
                .keySupplier(testKeyHelper.getKEKSupplier())
                .serializer(Serializer.JSON)
                .build();

        EncryptionProviderManager encryptionProviderManager = new EncryptionProviderManager()
                .register(localAESEncryptionProvider, true);

        SmartEncryption smartEncryption = new SmartEncryption(encryptionProviderManager);

        ByteBuffer encrypted = smartEncryption.encrypt(ByteBuffer.wrap("test".getBytes()));

        ByteBuffer decrypt = smartEncryption.decrypt(encrypted);

        assertEquals("test", new String(decrypt.array(), StandardCharsets.UTF_8));
    }
}