package com.pcistudio.kms;

import com.pcistudio.kms.engine.serialization.Serializer;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

class SimpleKmsAutoConfigurationTest {

    @Test
    void testSerializerLazyInit() {
        assertDoesNotThrow(() -> Serializer.JSON);
        assertDoesNotThrow(() -> Serializer.BSON);
        assertDoesNotThrow(() -> Serializer.AVRO);
        assertDoesNotThrow(() -> Serializer.PROTOBUF);
    }
}