package com.pcistudio.kms;

import com.pcistudio.kms.model.EncryptionData;

import java.nio.ByteBuffer;

public interface EncryptionStrategy {
    EncryptionData encrypt(ByteBuffer data);

    ByteBuffer decrypt(EncryptionData encryptionData);
}
