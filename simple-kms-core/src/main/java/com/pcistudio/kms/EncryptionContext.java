package com.pcistudio.kms;

import com.pcistudio.kms.serialization.DataSerializer;
import com.pcistudio.kms.serialization.Serializer;

public final class EncryptionContext {
    private final EncryptionStrategy encryptionStrategy;

    private final Serializer serializer;

    public EncryptionContext(EncryptionStrategy encryptionStrategy, Serializer serializer) {
        this.encryptionStrategy = encryptionStrategy;
        this.serializer = serializer;
    }

    public EncryptionStrategy getEncryptionStrategy() {
        return encryptionStrategy;
    }

    public DataSerializer getDataSerializer() {
        return serializer.getDataSerializer();
    }

    public byte getSerializerId() {
        return serializer.getId();
    }
}
