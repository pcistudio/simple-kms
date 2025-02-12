package com.pcistudio.kms;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;

/**
 * Encryption service it will generate the iv and encrypt the data
 * it will also decrypt the data
 */
public interface EncryptionService {

    ByteBuffer encrypt(SecretKey secretKey, ByteBuffer data);

    ByteBuffer decrypt(SecretKey secretKey, ByteBuffer data);

    String getKeyAlgorithm();
}
