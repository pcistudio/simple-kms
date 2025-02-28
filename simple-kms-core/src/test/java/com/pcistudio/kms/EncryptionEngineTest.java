package com.pcistudio.kms;

import com.pcistudio.kms.engine.serialization.Serializer;
import com.pcistudio.kms.engine.EncryptionEngine;
import com.pcistudio.kms.engine.EncryptionProvider;
import com.pcistudio.kms.engine.EncryptionProviderManager;
import com.pcistudio.kms.util.TestKeyHelper;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;

class EncryptionEngineTest {

    private static final Logger log = LoggerFactory.getLogger(EncryptionEngineTest.class);

    @ParameterizedTest
    @MethodSource("com.pcistudio.kms.util.TestKeyHelpers#all")
    void test(TestKeyHelper testKeyHelper) {
        EncryptionProvider localAESEncryptionProvider = testKeyHelper.localProvider(Serializer.JSON);

        EncryptionProviderManager encryptionProviderManager = new EncryptionProviderManager()
                .register(localAESEncryptionProvider, true);

        EncryptionEngine encryptionEngine = new EncryptionEngine(encryptionProviderManager);

        ByteBuffer encrypted = encryptionEngine.encrypt(ByteBuffer.wrap("test".getBytes()));

        ByteBuffer decrypt = encryptionEngine.decrypt(encrypted);

        assertEquals("test", new String(decrypt.array(), StandardCharsets.UTF_8));
    }

    @ParameterizedTest
    @MethodSource("com.pcistudio.kms.util.TestKeyHelpers#staticsOnly")
    void test2(TestKeyHelper testKeyHelper) {
        EncryptionProvider localAESEncryptionProvider = testKeyHelper.localProvider(Serializer.JSON);

        EncryptionProviderManager encryptionProviderManager = new EncryptionProviderManager()
                .register(localAESEncryptionProvider, true);

        EncryptionEngine encryptionEngine = new EncryptionEngine(encryptionProviderManager);

        ByteBuffer encrypted = encryptionEngine.encrypt(ByteBuffer.wrap("test".getBytes()));

        ByteBuffer decrypt = encryptionEngine.decrypt(encrypted);

        assertEquals("test", new String(decrypt.array(), StandardCharsets.UTF_8));
    }

    @ParameterizedTest
    @MethodSource("com.pcistudio.kms.util.TestKeyHelpers#staticDefault")
    void test3(TestKeyHelper testKeyHelper) {

        EncryptionProvider localAESEncryptionProvider = testKeyHelper.localProvider(Serializer.JSON);

        EncryptionProviderManager encryptionProviderManager = new EncryptionProviderManager()
                .register(localAESEncryptionProvider, true);

        EncryptionEngine encryptionEngine = new EncryptionEngine(encryptionProviderManager);

        ByteBuffer encrypted = encryptionEngine.encrypt(ByteBuffer.wrap("test".getBytes()));

        ByteBuffer decrypt = encryptionEngine.decrypt(encrypted);

        assertEquals("test", new String(decrypt.array(), StandardCharsets.UTF_8));

        testKeyHelper.rotateKey();

        EncryptionProvider localAESEncryptionProvider2 = testKeyHelper.localProvider(Serializer.JSON);
        EncryptionProviderManager encryptionProviderManager2 = new EncryptionProviderManager()
                .register(localAESEncryptionProvider2, true);
        EncryptionEngine encryptionEngine2 = new EncryptionEngine(encryptionProviderManager2);
        encrypted.rewind();
        log.info("--------------------------------------");
        ByteBuffer decrypt2 = encryptionEngine2.decrypt(encrypted);
        assertEquals("test", new String(decrypt2.array(), StandardCharsets.UTF_8));


        ByteBuffer encrypted2 = encryptionEngine2.encrypt(ByteBuffer.wrap("test2".getBytes()));

        decrypt2 = encryptionEngine2.decrypt(encrypted2);

        assertEquals("test2", new String(decrypt2.array(), StandardCharsets.UTF_8));

    }

    @ParameterizedTest
    @MethodSource("com.pcistudio.kms.util.TestKeyHelpers#staticDefault")
    void test4(TestKeyHelper testKeyHelper) {

        EncryptionProvider localAESEncryptionProvider = testKeyHelper.localProvider(Serializer.JSON);

        EncryptionProviderManager encryptionProviderManager = new EncryptionProviderManager()
                .register(localAESEncryptionProvider, true);

        EncryptionEngine encryptionEngine = new EncryptionEngine(encryptionProviderManager);

        ByteBuffer encrypted = encryptionEngine.encrypt(ByteBuffer.wrap("test".getBytes()));

        ByteBuffer decrypt = encryptionEngine.decrypt(encrypted);

        assertEquals("test", new String(decrypt.array(), StandardCharsets.UTF_8));

        testKeyHelper.rotateKey();

        EncryptionProvider localAESEncryptionProvider2 = testKeyHelper.localProvider(Serializer.BSON);
        EncryptionProviderManager encryptionProviderManager2 = new EncryptionProviderManager()
                .register(localAESEncryptionProvider)
                .register(localAESEncryptionProvider2, true);
        EncryptionEngine encryptionEngine2 = new EncryptionEngine(encryptionProviderManager2);
        encrypted.rewind();
        log.info("--------------------------------------");
        ByteBuffer decrypt2 = encryptionEngine2.decrypt(encrypted);
        assertEquals("test", new String(decrypt2.array(), StandardCharsets.UTF_8));

        ByteBuffer encrypted2 = encryptionEngine2.encrypt(ByteBuffer.wrap("test2".getBytes()));

        decrypt2 = encryptionEngine2.decrypt(encrypted2);

        assertEquals("test2", new String(decrypt2.array(), StandardCharsets.UTF_8));

    }
}