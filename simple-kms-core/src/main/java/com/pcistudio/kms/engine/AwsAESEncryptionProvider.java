package com.pcistudio.kms.engine;

import com.pcistudio.kms.DEKEncryptionStrategy;
import com.pcistudio.kms.aws.AwsKmsService;
import com.pcistudio.kms.engine.serialization.Serializer;
import com.pcistudio.kms.local.AESEncryptionService;
import edu.umd.cs.findbugs.annotations.Nullable;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DataKeySpec;

import java.nio.ByteBuffer;
import java.util.Objects;
import java.util.function.Supplier;

@SuppressFBWarnings("EI_EXPOSE_REP2")
public final class AwsAESEncryptionProvider implements EncryptionProvider {
    private final EncryptionDescriptor encryptionDescriptor;
    private final String name;

    @SuppressWarnings("PMD.CloseResource")
    private AwsAESEncryptionProvider(AwsAESEncryptionProviderBuilder builder) {
        Supplier<ByteBuffer> ivSupplier = Objects.requireNonNull(builder.ivSupplier, "ivSupplier cannot be null");
        Serializer serializer = Objects.requireNonNull(builder.serializer, "serializer cannot be null");
        String keyId = Objects.requireNonNull(builder.keyId, "keyId cannot be null");
        KmsClient kmsClient = Objects.requireNonNull(builder.kmsClient, "kmsClient cannot be null");
        DataKeySpec dataKeySpec = Objects.requireNonNull(builder.dataKeySpec, "dataKeySpec cannot be null");


        AESEncryptionService aesEncryptionService = new AESEncryptionService(Objects.requireNonNull(ivSupplier));
        AwsKmsService awsKmsService = new AwsKmsService(keyId, kmsClient, dataKeySpec);
        encryptionDescriptor = new EncryptionDescriptor(
                new DEKEncryptionStrategy(
                        awsKmsService,
                        aesEncryptionService
                ),
                serializer
        );

        name = "AWS/%s/IV%d/%s".formatted(dataKeySpec.name(), ivSupplier.get().capacity() * 8, serializer.name());
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

    public static class AwsAESEncryptionProviderBuilder {
        @Nullable
        private String keyId;
        @Nullable
        private DataKeySpec dataKeySpec;
        @Nullable
        private Supplier<ByteBuffer> ivSupplier;
        @Nullable
        private KmsClient kmsClient;
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

        public AwsAESEncryptionProviderBuilder kmsClient(KmsClient kmsClient) {
            this.kmsClient = kmsClient;
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
