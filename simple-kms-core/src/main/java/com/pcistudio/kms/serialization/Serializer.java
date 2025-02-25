package com.pcistudio.kms.serialization;

import java.util.HashMap;
import java.util.Map;

public enum Serializer {
    JSON((byte) 1, new GsonDataSerializer()),
    AVRO((byte) 2, new AvroDataSerializer()),
    PROTOBUF((byte) 3, new ProtoDataSerializer()),
    THRIFT((byte) 4, new ThriftDataSerializer());

    private static final Map<Byte, Serializer> LOOKUP_MAP = new HashMap<>();

    static {
        for (Serializer s : values()) {
            if (LOOKUP_MAP.containsKey(s.id)) {
                throw new IllegalStateException("Duplicate serializer id: " + s.id);
            }
            LOOKUP_MAP.put(s.id, s);
        }
    }

    private final byte id;
    private final DataSerializer dataSerializer;

    Serializer(byte id, DataSerializer dataSerializer) {
        this.id = id;
        this.dataSerializer = dataSerializer;
    }

    public byte getId() {
        return id;
    }

    public DataSerializer getDataSerializer() {
        return dataSerializer;
    }

    public static Serializer lookup(byte id) {
        return LOOKUP_MAP.get(id);
    }
}
