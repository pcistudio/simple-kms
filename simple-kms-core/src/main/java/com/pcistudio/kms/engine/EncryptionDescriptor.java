package com.pcistudio.kms.engine;

import com.pcistudio.kms.EncryptionStrategy;
import com.pcistudio.kms.engine.serialization.DataSerializer;
import com.pcistudio.kms.engine.serialization.Serializer;

public final class EncryptionDescriptor {
    private final EncryptionStrategy encryptionStrategy;

    private final Serializer serializer;

    public EncryptionDescriptor(EncryptionStrategy encryptionStrategy, Serializer serializer) {
        this.encryptionStrategy = encryptionStrategy;
        this.serializer = serializer;
    }

    public EncryptionStrategy getEncryptionStrategy() {
        return encryptionStrategy;
    }


    public Serializer getSerializer() {
        return serializer;
    }

    public DataSerializer getDataSerializer() {
        return serializer.getDataSerializer();
    }

    public byte getSerializerId() {
        return serializer.getId();
    }
}
