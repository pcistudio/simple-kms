package com.pcistudio.kms;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;

public interface KeyResolverEncryptionService {

    ByteBuffer encrypt(ByteBuffer data);

    ByteBuffer decrypt(ByteBuffer encryptedKey);

    String getKeyAlgorithm();

    default SecretKey decryptKey(ByteBuffer encryptedKey) {
        ByteBuffer keyDecrypted = decrypt(encryptedKey);
        return new SecretKeySpec(keyDecrypted.array(), getKeyAlgorithm());
    }
}
