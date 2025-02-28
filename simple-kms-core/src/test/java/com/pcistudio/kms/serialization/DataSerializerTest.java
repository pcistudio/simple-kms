package com.pcistudio.kms.serialization;

import com.pcistudio.kms.engine.SecureEnvelope;
import com.pcistudio.kms.engine.serialization.DataSerializer;
import com.pcistudio.kms.engine.serialization.Serializer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;

class DataSerializerTest {

    private static final Logger log = LoggerFactory.getLogger(DataSerializerTest.class);

    @ParameterizedTest
    @EnumSource(Serializer.class)
    void testSerialization(Serializer serializer) {

        DataSerializer dataSerializer = serializer.getDataSerializer();
        ByteBuffer serialize = dataSerializer.serialize(new SecureEnvelope(
                "provider",
                ByteBuffer.wrap("key1".getBytes(StandardCharsets.UTF_8)),
                ByteBuffer.wrap("key2".getBytes(StandardCharsets.UTF_8))
        ));

        SecureEnvelope encryptionData = dataSerializer.deserializeRemaining(serialize);

        assertEquals("provider", encryptionData.getP());

        assertEquals("key1", new String(encryptionData.getEk().array(), StandardCharsets.UTF_8));
        assertEquals("key2", new String(encryptionData.getEd().array(), StandardCharsets.UTF_8));

    }

    @Test
    void testSerializationSize() {
        SecureEnvelope encryptionData = new SecureEnvelope(
                "provider",
                ByteBuffer.wrap("key1".getBytes(StandardCharsets.UTF_8)),
                ByteBuffer.wrap("key2".getBytes(StandardCharsets.UTF_8))
        );

        ByteBuffer bsonData = Serializer.BSON.getDataSerializer().serialize(encryptionData);

        ByteBuffer jsonData = Serializer.JSON.getDataSerializer().serialize(encryptionData);

        ByteBuffer avroData = Serializer.AVRO.getDataSerializer().serialize(encryptionData);

        ByteBuffer protoData = Serializer.PROTOBUF.getDataSerializer().serialize(encryptionData);

        log.info("jsonSize={}, bsonSize={}, avroData={}, protoData={}",
                jsonData.array().length, bsonData.array().length, avroData.array().length, protoData.array().length);


    }
}