package com.pcistudio.kms.engine;

import com.pcistudio.kms.engine.serialization.Serializer;
import com.pcistudio.kms.model.EncryptionData;
import org.slf4j.Logger;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Payload
 * serid|{p:"provider",ek:encryptedKey,ed:encryptedData}|
 * encryptedKey=masterKeyId,vi:encryptedKey   -- when using a kms this piece is not needed
 * encryptedData=vi:encryptedData
 */
//TODO create a metric for

public class EncryptionEngine {
    private static final Logger logger = org.slf4j.LoggerFactory.getLogger(EncryptionEngine.class);

    private final EncryptionProviderManager encryptionProviderManager;

    public EncryptionEngine(EncryptionProviderManager encryptionProviderManager) {
        this.encryptionProviderManager = encryptionProviderManager;
    }

    public ByteBuffer encrypt(ByteBuffer data) {
        EncryptionProvider encryptionProvider = encryptionProviderManager.getDefault();

        EncryptionDescriptor encryptionDescriptor = encryptionProvider.getContext();
        EncryptionData encryptionData = encryptionDescriptor.getEncryptionStrategy().encrypt(data);

        ByteBuffer serialize = encryptionDescriptor.getDataSerializer()
                .serialize(SecureEnvelope.of(encryptionProvider.getName(), encryptionData));

        ByteBuffer byteBuffer = ByteBuffer.allocate(1 + serialize.capacity())
                .put(encryptionDescriptor.getSerializerId())
                .put(serialize);

        if (logger.isDebugEnabled()) {
            logger.debug("Encrypting data with provider={}, serializer={}, serializerId={} result size={}",
                    encryptionProvider.getName(), encryptionDescriptor.getSerializer().name(), encryptionDescriptor.getSerializerId(), byteBuffer.capacity());
        }
        if (logger.isTraceEnabled()) {
            ByteBuffer encryptedData = Serializer.JSON.getDataSerializer()
                    .serialize(SecureEnvelope.of(encryptionProvider.getName(), encryptionData));
            logger.trace("Encrypting data with provider {} and data {}", encryptionProvider.getName(), new String(encryptedData.array(), StandardCharsets.UTF_8));
        }
        byteBuffer.flip();
        return byteBuffer;
    }

    public ByteBuffer decrypt(ByteBuffer data) {
        byte serializerId = data.get();
        Serializer serializer = Serializer.lookup(serializerId);

        if (logger.isTraceEnabled() && serializer == Serializer.JSON) {
            logger.trace("decrypt data with serializer {} and data {}", serializerId, new String(data.array(), StandardCharsets.UTF_8));
        }
        SecureEnvelope encryptionData = serializer.getDataSerializer().deserializeRemaining(data);

        Optional<EncryptionProvider> encryptionProviderOptional = encryptionProviderManager.get(encryptionData.getP());

        EncryptionProvider encryptionProvider = encryptionProviderOptional
                .orElseThrow(() -> new IllegalStateException("No encryption provider found for " + encryptionData.getP()));

        return encryptionProvider
                .getContext()
                .getEncryptionStrategy()
                .decrypt(new EncryptionData(encryptionData.getEk(), encryptionData.getEd()));
    }
}
