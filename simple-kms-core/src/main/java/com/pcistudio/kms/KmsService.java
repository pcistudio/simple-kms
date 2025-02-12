package com.pcistudio.kms;

import com.pcistudio.kms.model.GeneratedKey;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
/**
 * Interface for generating secure keys.
 * It should have a kms service in the back to use the master key to encrypt the key.
 */
public interface KmsService {
    GeneratedKey generateKey();
    ByteBuffer encrypt(ByteBuffer data);
    ByteBuffer decrypt(ByteBuffer encryptedKey);
    String getKeyAlgorithm();

    SecretKey decryptKey(ByteBuffer encryptedKey);
}
