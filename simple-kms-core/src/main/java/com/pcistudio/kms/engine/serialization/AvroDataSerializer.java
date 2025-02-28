package com.pcistudio.kms.engine.serialization;

import com.pcistudio.kms.engine.SecureEnvelope;
import com.pcistudio.kms.model.generated.SecureEnvelopeAvro;

import java.io.IOException;
import java.nio.ByteBuffer;

public final class AvroDataSerializer implements DataSerializer {

    AvroDataSerializer() {
        //Avoid direct instantiation.
    }

    @Override
    public ByteBuffer serialize(SecureEnvelope data) {
        SecureEnvelopeAvro encryptionDataAvro = SecureEnvelopeAvro.newBuilder()
                .setProvider(data.getP())
                .setEncryptedKey(data.getEk())
                .setEncryptedData(data.getEd())
                .build();

        try {
            return encryptionDataAvro.toByteBuffer();
        } catch (IOException ex) {
            throw new IllegalStateException("Error serializing to avro", ex);
        }
    }

    @Override
    public SecureEnvelope deserialize(byte[] data) {
        try {
            SecureEnvelopeAvro secureEnvelopeAvro = SecureEnvelopeAvro.fromByteBuffer(ByteBuffer.wrap(data));
            return new SecureEnvelope(
                    secureEnvelopeAvro.getProvider().toString(),
                    secureEnvelopeAvro.getEncryptedKey(),
                    secureEnvelopeAvro.getEncryptedData()
            );
        } catch (IOException ex) {
            throw new IllegalStateException("Error deserialize from avro", ex);
        }
    }
}
