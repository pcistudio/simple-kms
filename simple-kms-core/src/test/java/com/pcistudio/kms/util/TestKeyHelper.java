package com.pcistudio.kms.util;

import com.pcistudio.kms.engine.EncryptionProvider;
import com.pcistudio.kms.engine.LocalAESEncryptionProvider;
import com.pcistudio.kms.engine.serialization.Serializer;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.function.Supplier;


public interface TestKeyHelper {
    SecretKey getKEK();

    List<SecretKey> getMasterKeys();

    Supplier<ByteBuffer> ivGenerator();

    default Supplier<SecretKey> getKEKSupplier() {
        return this::getKEK;
    }

    SecretKey currentMasterKey();

    void rotateKey();

    default EncryptionProvider localProvider(Serializer serializer) {
        return LocalAESEncryptionProvider.builder()
                .masterKeysHistory(getMasterKeys())
                .ivSupplier(ivGenerator())
                .keySupplier(getKEKSupplier())
                .serializer(serializer)
                .build();
    }
}
