package com.pcistudio.kms.serialization;

import com.pcistudio.kms.model.ProviderEncryptionData;

import java.nio.ByteBuffer;

public sealed interface DataSerializer permits AvroDataSerializer, GsonDataSerializer, ProtoDataSerializer, ThriftDataSerializer {
    ByteBuffer serialize(ProviderEncryptionData data);

    ProviderEncryptionData deserialize(byte[] data);

    default ProviderEncryptionData deserialize(ByteBuffer data) {
        byte[] bytes = new byte[data.remaining()];
        data.get(bytes);
        return deserialize(bytes);
    }
}
