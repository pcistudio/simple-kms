package com.pcistudio.kms;

import com.pcistudio.kms.model.EncryptionData;
import com.pcistudio.kms.model.GeneratedKey;
import com.pcistudio.kms.reuse.KeyReuseStrategy;
import com.pcistudio.kms.reuse.KeyReuseStrategyBuilder;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;

public class DEKEncryptionStrategy implements EncryptionStrategy {
    private final KmsService kmsService;
    private final EncryptionService encryptionService;
    private final KeyReuseStrategy keyReuseStrategy;

    public DEKEncryptionStrategy(KmsService kmsService, EncryptionService encryptionService) {
        this(kmsService,encryptionService, KeyReuseStrategy.builder());
    }

    public DEKEncryptionStrategy(KmsService kmsService, EncryptionService encryptionService, KeyReuseStrategyBuilder<? extends KeyReuseStrategy, ? extends KeyReuseStrategyBuilder> reuseStrategyBuilder) {
        this.kmsService = kmsService;
        this.encryptionService = encryptionService;
        this.keyReuseStrategy = reuseStrategyBuilder
                .keySupplier(this.kmsService::generateKey)
                .build();
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
        GeneratedKey generatedKey = keyReuseStrategy.generateKey();
        ByteBuffer encryptedData = encryptionService.encrypt(generatedKey.key(), data);
        return new EncryptionData(generatedKey.encryptedKey(), encryptedData);
    }

    @Override
    public ByteBuffer decrypt(EncryptionData encryptionData) {
        SecretKey secretKey = kmsService.decryptKey(encryptionData.encryptedKey());
        return encryptionService.decrypt(secretKey, encryptionData.encryptedData());
    }

}
