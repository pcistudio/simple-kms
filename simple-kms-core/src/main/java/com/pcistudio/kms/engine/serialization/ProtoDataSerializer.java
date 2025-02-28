package com.pcistudio.kms.engine.serialization;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.pcistudio.kms.engine.SecureEnvelope;
import com.pcistudio.kms.model.generated.SecureEnvelopeProto;

import java.nio.ByteBuffer;

public final class ProtoDataSerializer implements DataSerializer {

    ProtoDataSerializer() {
        //Avoid direct instantiation.
    }

    @Override
    public ByteBuffer serialize(SecureEnvelope data) {

        SecureEnvelopeProto.Envelope providerData = SecureEnvelopeProto.Envelope
                .newBuilder()
                .setProvider(data.getP())
                .setEncryptedKey(ByteString.copyFrom(data.getEk()))
                .setEncryptedData(ByteString.copyFrom(data.getEd()))
                .build();
        return ByteBuffer.wrap(providerData.toByteArray());
    }

    @Override
    public SecureEnvelope deserialize(byte[] data) {
        try {
            SecureEnvelopeProto.Envelope providerData = SecureEnvelopeProto.Envelope.parseFrom(data);
            return new SecureEnvelope(
                    providerData.getProvider(),
                    ByteBuffer.wrap(providerData.getEncryptedKey().toByteArray()),
                    ByteBuffer.wrap(providerData.getEncryptedData().toByteArray())
            );
        } catch (InvalidProtocolBufferException ex) {
            throw new IllegalStateException("Error serializing to protobuf", ex);
        }
    }
}
