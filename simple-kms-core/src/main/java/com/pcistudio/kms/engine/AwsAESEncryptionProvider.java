package com.pcistudio.kms.engine;

import com.pcistudio.kms.DEKEncryptionStrategy;
import com.pcistudio.kms.aws.AwsKmsService;
import com.pcistudio.kms.engine.serialization.Serializer;
import com.pcistudio.kms.local.AESEncryptionService;
import edu.umd.cs.findbugs.annotations.Nullable;
import software.amazon.awssdk.services.kms.KmsClientBuilder;
import software.amazon.awssdk.services.kms.model.DataKeySpec;

import java.nio.ByteBuffer;
import java.util.Objects;
import java.util.function.Supplier;

public final class AwsAESEncryptionProvider implements EncryptionProvider {
    private final EncryptionDescriptor encryptionDescriptor;
    private final String name;

    private AwsAESEncryptionProvider(AwsAESEncryptionProviderBuilder builder) {
        Supplier<ByteBuffer> ivSupplier = Objects.requireNonNull(builder.ivSupplier, "ivSupplier cannot be null");
        Serializer serializer = Objects.requireNonNull(builder.serializer, "serializer cannot be null");
        String keyId = Objects.requireNonNull(builder.keyId, "keyId cannot be null");
        KmsClientBuilder kmsClientBuilder = Objects.requireNonNull(builder.kmsClientBuilder, "kmsClient cannot be null");
        DataKeySpec dataKeySpec = Objects.requireNonNull(builder.dataKeySpec, "dataKeySpec cannot be null");


        AESEncryptionService aesEncryptionService = new AESEncryptionService(Objects.requireNonNull(ivSupplier));
        AwsKmsService awsKmsService = new AwsKmsService(keyId, kmsClientBuilder, dataKeySpec);
        encryptionDescriptor = new EncryptionDescriptor(
                new DEKEncryptionStrategy(
                        awsKmsService,
                        aesEncryptionService
                ),
                serializer
        );

        name = "AWS/%s/IV%d/%s@%s".formatted(dataKeySpec.name(), ivSupplier.get().capacity() * 8, serializer.name(), keyId.substring(0, Math.min(keyId.length(), 8)));
    }

    @Override
    public EncryptionDescriptor getContext() {
        return encryptionDescriptor;
    }

    @Override
    public String getName() {
        return name;
    }

    public static AwsAESEncryptionProviderBuilder builder() {
        return new AwsAESEncryptionProviderBuilder();
    }

    public static class AwsAESEncryptionProviderBuilder implements EncryptionProviderBuilder {
        @Nullable
        private String keyId;
        @Nullable
        private DataKeySpec dataKeySpec;
        @Nullable
        private Supplier<ByteBuffer> ivSupplier;
        @Nullable
        private KmsClientBuilder kmsClientBuilder;
        @Nullable
        private Serializer serializer;

        public AwsAESEncryptionProviderBuilder keyId(String keyId) {
            this.keyId = keyId;
            return this;
        }

        public AwsAESEncryptionProviderBuilder ivSupplier(Supplier<ByteBuffer> ivSupplier) {
            this.ivSupplier = ivSupplier;
            return this;
        }

        public AwsAESEncryptionProviderBuilder kmsClientBuilder(KmsClientBuilder kmsClientBuilder) {
            this.kmsClientBuilder = kmsClientBuilder;
            return this;
        }

        public AwsAESEncryptionProviderBuilder serializer(Serializer serializer) {
            this.serializer = serializer;
            return this;
        }

        public AwsAESEncryptionProviderBuilder dataKeySpec(DataKeySpec dataKeySpec) {
            this.dataKeySpec = dataKeySpec;
            return this;
        }

        public AwsAESEncryptionProvider build() {
            return new AwsAESEncryptionProvider(this);
        }
    }
}
