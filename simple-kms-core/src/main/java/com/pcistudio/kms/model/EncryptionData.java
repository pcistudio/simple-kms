package com.pcistudio.kms.model;

import java.nio.ByteBuffer;

public record EncryptionData(ByteBuffer encryptedKey, ByteBuffer encryptedData) {
}
