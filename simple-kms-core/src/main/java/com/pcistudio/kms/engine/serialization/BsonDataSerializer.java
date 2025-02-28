package com.pcistudio.kms.engine.serialization;

import com.pcistudio.kms.engine.SecureEnvelope;
import org.bson.BsonBinary;
import org.bson.BsonBinaryReader;
import org.bson.BsonBinaryWriter;
import org.bson.io.BasicOutputBuffer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

public final class BsonDataSerializer implements DataSerializer {

    BsonDataSerializer() {
        //Avoid direct instantiation.
    }

    @Override
    public ByteBuffer serialize(SecureEnvelope data) {
        try (BasicOutputBuffer bsonOutput = new BasicOutputBuffer();
             BsonBinaryWriter writer = new BsonBinaryWriter(bsonOutput)
        ) {
            writer.writeStartDocument();

            writer.writeString("p", data.getP());
            writer.writeBinaryData("ek", new BsonBinary(data.getEk().array()));
            writer.writeBinaryData("ed", new BsonBinary(data.getEd().array()));
            writer.writeEndDocument();

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream(bsonOutput.getSize());
            bsonOutput.pipe(outputStream);
            return ByteBuffer.wrap(outputStream.toByteArray());
        } catch (IOException ex) {
            throw new IllegalStateException("Error serializing to bson", ex);
        }
    }

    @Override
    public SecureEnvelope deserialize(byte[] data) {
        return deserializeRemaining(ByteBuffer.wrap(data));
    }

    @Override
    public SecureEnvelope deserializeRemaining(ByteBuffer data) {
        try (BsonBinaryReader reader = new BsonBinaryReader(data)) {
            reader.readStartDocument();
            SecureEnvelope result = new SecureEnvelope(
                    reader.readString("p"),
                    ByteBuffer.wrap(reader.readBinaryData("ek").getData()),
                    ByteBuffer.wrap(reader.readBinaryData("ed").getData())
            );
            reader.readEndDocument();
            return result;
        }
    }
}
