package com.pcistudio.kms;

import com.pcistudio.kms.model.EncryptionData;
import com.pcistudio.kms.model.ProviderEncryptionData;
import com.pcistudio.kms.serialization.DataSerializer;
import com.pcistudio.kms.serialization.Serializer;
import org.slf4j.Logger;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Optional;


// payload
//serid|{p:"provider",ek:encryptedKey,ed:encryptedData}|
//encryptedKey=masterKeyId,vi:encryptedKey   -- when using a kms this piece is not needed
//encryptedData=vi:encryptedData
//TODO create a metric for


//TODO You need to know the serializer beferehands
//First byte could be and byte with the serializer id
public class SmartEncryption {
    private static final Logger logger = org.slf4j.LoggerFactory.getLogger(SmartEncryption.class);

    private final EncryptionProviderManager encryptionProviderManager;

    public SmartEncryption(EncryptionProviderManager encryptionProviderManager) {
        this.encryptionProviderManager = encryptionProviderManager;
    }

    public ByteBuffer encrypt(ByteBuffer data) {
        EncryptionProvider encryptionProvider = encryptionProviderManager.getDefault();

        EncryptionContext encryptionContext = encryptionProvider.getContext();
        EncryptionData encryptionData = encryptionContext.getEncryptionStrategy().encrypt(data);

        ByteBuffer serialize = encryptionContext.getDataSerializer()
                .serialize(ProviderEncryptionData.of(encryptionProvider.getName(), encryptionData));

        ByteBuffer byteBuffer = ByteBuffer.allocate(1 + serialize.capacity())
                .put(encryptionContext.getSerializerId())
                .put(serialize);

        if (logger.isDebugEnabled()) {
            logger.debug("Encrypting data with provider {} and serializer {}", encryptionProvider.getName(), encryptionContext.getSerializerId());
        }
        if (logger.isTraceEnabled()) {
            logger.trace("Encrypting data with provider {} and data {}", encryptionProvider.getName(), new String(byteBuffer.array(), StandardCharsets.UTF_8));
        }
        byteBuffer.flip();
        return byteBuffer;
    }

    public ByteBuffer decrypt(ByteBuffer data) {
        byte serializerId = data.get();
        DataSerializer dataSerializer = Serializer.lookup(serializerId).getDataSerializer();

        if (logger.isTraceEnabled()) {
            logger.trace("decrypt data with serializer {} and data {}", serializerId, new String(data.array(), StandardCharsets.UTF_8));
        }
        ProviderEncryptionData encryptionData = dataSerializer.deserialize(data);

        Optional<EncryptionProvider> encryptionProviderOptional = encryptionProviderManager.get(encryptionData.getP());

        EncryptionProvider encryptionProvider = encryptionProviderOptional
                .orElseThrow(() -> new IllegalStateException("No encryption provider found for " + encryptionData.getP()));

        return encryptionProvider
                .getContext()
                .getEncryptionStrategy()
                .decrypt(new EncryptionData(encryptionData.getEk(), encryptionData.getEd()));
    }
}
