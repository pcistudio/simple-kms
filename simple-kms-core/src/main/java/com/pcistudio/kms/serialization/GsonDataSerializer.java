package com.pcistudio.kms.serialization;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.pcistudio.kms.model.ProviderEncryptionData;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

public final class GsonDataSerializer implements DataSerializer {

    private static final Gson GSON = new GsonBuilder()
            .registerTypeAdapter(byte[].class, new ByteArrayAdapter())
            .create();

    @Override
    public ByteBuffer serialize(ProviderEncryptionData data) {
        String json = GSON.toJson(data);
        return ByteBuffer.wrap(json.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public ProviderEncryptionData deserialize(byte[] data) {
        return GSON.fromJson(new String(data, StandardCharsets.UTF_8), ProviderEncryptionData.class);
    }
}
