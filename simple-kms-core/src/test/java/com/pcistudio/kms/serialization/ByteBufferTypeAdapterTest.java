package com.pcistudio.kms.serialization;

import com.pcistudio.kms.engine.SecureEnvelope;
import com.pcistudio.kms.engine.serialization.Serializer;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ByteBufferTypeAdapterTest {

    @Test
    void testJsonSerializer() {
        SecureEnvelope data =
                new SecureEnvelope("provider", ByteBuffer.wrap("key".getBytes()), ByteBuffer.wrap("serialization and deserialization properly.".getBytes()));
        ByteBuffer serialize = Serializer.JSON.getDataSerializer().serialize(data);

        SecureEnvelope deserialize = Serializer.JSON.getDataSerializer().deserializeRemaining(serialize);

        assertEquals(data.getP(), deserialize.getP());
        assertEquals(data.getEk(), deserialize.getEk());
        assertEquals(data.getEd(), deserialize.getEd());
    }

}