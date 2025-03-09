package com.pcistudio.kms.engine;

import com.pcistudio.kms.DEKEncryptionStrategy;
import com.pcistudio.kms.engine.serialization.Serializer;
import com.pcistudio.kms.local.AESEncryptionService;
import com.pcistudio.kms.local.LocalKmsService;
import edu.umd.cs.findbugs.annotations.Nullable;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.Supplier;

public final class LocalAESEncryptionProvider implements EncryptionProvider {
    private final EncryptionDescriptor encryptionDescriptor;
    private final String name;

    private LocalAESEncryptionProvider(LocalAESEncryptionProviderBuilder builder) {
        Supplier<ByteBuffer> ivSupplier = Objects.requireNonNull(builder.ivSupplier, "ivSupplier cannot be null");
        Supplier<SecretKey> keySupplier = Objects.requireNonNull(builder.keySupplier, "keySupplier cannot be null");
        List<SecretKey> masterKeysHistory = Objects.requireNonNull(builder.masterKeysHistory, "masterKeysHistory cannot be null");
        Serializer serializer = Objects.requireNonNull(builder.serializer, "serializer cannot be null");


        AESEncryptionService aesEncryptionService = new AESEncryptionService(Objects.requireNonNull(ivSupplier));
        LocalKmsService localKmsService = new LocalKmsService(masterKeysHistory, aesEncryptionService, Objects.requireNonNull(keySupplier));
        encryptionDescriptor = new EncryptionDescriptor(
                new DEKEncryptionStrategy(
                        localKmsService,
                        aesEncryptionService
                ),
                serializer
        );

        name = "LOCAL/AES%d/IV%d/%s".formatted(keySupplier.get().getEncoded().length * 8, ivSupplier.get().capacity() * 8, serializer.name());
    }

    @Override
    public EncryptionDescriptor getContext() {
        return encryptionDescriptor;
    }

    @Override
    public String getName() {
        return name;
    }

    public static LocalAESEncryptionProviderBuilder builder() {
        return new LocalAESEncryptionProviderBuilder();
    }

    public static class LocalAESEncryptionProviderBuilder implements EncryptionProviderBuilder {
        @Nullable
        private List<SecretKey> masterKeysHistory;
        @Nullable
        private Supplier<ByteBuffer> ivSupplier;
        @Nullable
        private Supplier<SecretKey> keySupplier;
        @Nullable
        private Serializer serializer;

        public LocalAESEncryptionProviderBuilder masterKeysHistory(List<SecretKey> masterKeysHistory) {
            this.masterKeysHistory = new ArrayList<>(masterKeysHistory);
            return this;
        }

        public LocalAESEncryptionProviderBuilder ivSupplier(Supplier<ByteBuffer> ivSupplier) {
            this.ivSupplier = ivSupplier;
            return this;
        }

        public LocalAESEncryptionProviderBuilder keySupplier(Supplier<SecretKey> keySupplier) {
            this.keySupplier = keySupplier;
            return this;
        }

        public LocalAESEncryptionProviderBuilder serializer(Serializer serializer) {
            this.serializer = serializer;
            return this;
        }

        @Override
        public LocalAESEncryptionProvider build() {
            return new LocalAESEncryptionProvider(this);
        }
    }
}
