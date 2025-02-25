package com.pcistudio.kms.serialization;

import com.pcistudio.kms.model.ProviderEncryptionData;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ByteBufferTypeAdapterTest {

    @Test
    void testJsonSerializer() {
        ProviderEncryptionData data =
                new ProviderEncryptionData("provider", ByteBuffer.wrap("key".getBytes()), ByteBuffer.wrap("serialization and deserialization properly.".getBytes()));
        ByteBuffer serialize = Serializer.JSON.getDataSerializer().serialize(data);

        ProviderEncryptionData deserialize = Serializer.JSON.getDataSerializer().deserialize(serialize);

        assertEquals(data.getP(), deserialize.getP());
        assertEquals(data.getEk(), deserialize.getEk());
        assertEquals(data.getEd(), deserialize.getEd());
    }

}