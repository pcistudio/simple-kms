package com.pcistudio.kms;

import com.pcistudio.kms.model.EncryptionData;
import com.pcistudio.kms.model.GeneratedKey;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;

public class DEKEncryptionStrategy implements EncryptionStrategy {
    private final KmsService kmsService;
    private final EncryptionService encryptionService;

    public DEKEncryptionStrategy(KmsService kmsService, EncryptionService encryptionService) {
        this.kmsService = kmsService;
        this.encryptionService = encryptionService;
    }

    /**
     * Encrypts the data using a generated key. EncryptionData contains the encrypted data and the encrypted key.
     * they can be store together because the encrypted key size is not fixed
     *
     * @param data the data to encrypt
     * @return the encrypted data and the encrypted key
     */
    @Override
    public EncryptionData encrypt(ByteBuffer data) {
        GeneratedKey generatedKey = kmsService.generateKey();
        ByteBuffer encryptedData = encryptionService.encrypt(generatedKey.getKey(), data);
        return new EncryptionData(generatedKey.getEncryptedKey(), encryptedData);
    }

    @Override
    public ByteBuffer decrypt(EncryptionData encryptionData) {
        SecretKey secretKey = kmsService.decryptKey(encryptionData.encryptedKey());
        return encryptionService.decrypt(secretKey, encryptionData.encryptedData());
    }


}
