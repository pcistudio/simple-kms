package com.pcistudio.kms.engine.serialization;

import com.pcistudio.kms.engine.SecureEnvelope;

import java.nio.ByteBuffer;

public sealed interface DataSerializer permits AvroDataSerializer, GsonDataSerializer, ProtoDataSerializer, BsonDataSerializer {
    ByteBuffer serialize(SecureEnvelope data);

    SecureEnvelope deserialize(byte[] data);

    default SecureEnvelope deserializeRemaining(ByteBuffer data) {
        byte[] bytes = new byte[data.remaining()];
        data.get(bytes);
        return deserialize(bytes);
    }
}
