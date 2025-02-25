package com.pcistudio.kms.serialization;

import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import com.google.gson.stream.JsonWriter;

import java.io.IOException;
import java.util.Base64;

public class ByteArrayAdapter extends TypeAdapter<byte[]> {
    @Override
    public void write(JsonWriter out, byte[] bytes) throws IOException {
        if (bytes == null) {
            out.nullValue();
            return;
        }

        out.value(Base64.getEncoder().encodeToString(bytes)); // Encode as Base64 string
    }

    @Override
    public byte[] read(JsonReader in) throws IOException {
        if (in.peek() == JsonToken.NULL) {
            in.nextNull();
            return new byte[0];
        }
        String base64String = in.nextString();
        return Base64.getDecoder().decode(base64String); // Decode from Base64 string
    }
}
