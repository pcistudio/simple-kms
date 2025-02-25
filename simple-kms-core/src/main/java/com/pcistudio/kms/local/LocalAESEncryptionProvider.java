package com.pcistudio.kms.local;

import com.pcistudio.kms.DEKEncryptionStrategy;
import com.pcistudio.kms.EncryptionContext;
import com.pcistudio.kms.EncryptionProvider;
import com.pcistudio.kms.serialization.Serializer;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

public class LocalAESEncryptionProvider implements EncryptionProvider {
    private static final int IV_SIZE = 12;

    private final List<SecretKey> masterKeysHistory;
    private final int keySize;
    private final Supplier<ByteBuffer> ivSupplier;
    private final Supplier<SecretKey> keySupplier;

    public LocalAESEncryptionProvider(List<SecretKey> masterKeysHistory, int keySize) {
        this(masterKeysHistory, keySize, null, null);
    }

    public LocalAESEncryptionProvider(List<SecretKey> masterKeysHistory, int keySize, Supplier<ByteBuffer> ivSupplier, Supplier<SecretKey> keySupplier) {
        this.masterKeysHistory = new ArrayList<>(masterKeysHistory);
        this.keySize = keySize;
        this.ivSupplier = ivSupplier;
        this.keySupplier = keySupplier;
    }

    @Override
    public EncryptionContext getContext() {
        AESEncryptionService aesEncryptionService = ivSupplier != null ? new AESEncryptionService(ivSupplier) : new AESEncryptionService(IV_SIZE);
        return new EncryptionContext(
                new DEKEncryptionStrategy(
                        new LocalKmsService(masterKeysHistory, keySize, aesEncryptionService, keySupplier),
                        aesEncryptionService
                ),
                Serializer.JSON
        );
    }

    @Override
    public String getName() {
        return "LOCAL/AES/%d/JSON".formatted(keySize);
    }
}
