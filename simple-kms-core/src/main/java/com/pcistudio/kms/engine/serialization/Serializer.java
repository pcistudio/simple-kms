package com.pcistudio.kms.engine.serialization;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

public enum Serializer {
    JSON((byte) 1, GsonDataSerializer.class),
    BSON((byte) 2, BsonDataSerializer.class),
    AVRO((byte) 3, AvroDataSerializer.class),
    PROTOBUF((byte) 4, ProtoDataSerializer.class);

    private static final Map<Byte, Serializer> LOOKUP_MAP = new ConcurrentHashMap<>();

    static {
        for (Serializer s : values()) {
            if (LOOKUP_MAP.containsKey(s.id)) {
                throw new IllegalStateException("Duplicate serializer id: " + s.id);
            }
            LOOKUP_MAP.put(s.id, s);
        }
    }

    private final byte id;
    private final Class<? extends DataSerializer> dataSerializerClass;
    private final AtomicReference<DataSerializer> serializerRef = new AtomicReference<>();

    Serializer(byte id, Class<? extends DataSerializer> dataSerializerClass) {
        this.id = id;
        this.dataSerializerClass = dataSerializerClass;
    }

    public byte getId() {
        return id;
    }

    public DataSerializer getDataSerializer() {
        serializerRef.updateAndGet(dataSerializer -> {
            if (dataSerializer == null) {
                try {
                    return dataSerializerClass.getDeclaredConstructor().newInstance();
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
            return dataSerializer;
        });

        return serializerRef.get();
    }

    public static Serializer lookup(byte id) {
        return LOOKUP_MAP.get(id);
    }
}
