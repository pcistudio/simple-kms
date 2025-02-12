package com.pcistudio.kms;

import com.pcistudio.kms.local.AESEncryptionService;
import com.pcistudio.kms.model.EncryptedKeyInfo;
import com.pcistudio.kms.model.GeneratedKey;
import com.pcistudio.kms.model.KeyInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;

public class KEKStrategy {
    private static final Logger log = LoggerFactory.getLogger(KEKStrategy.class);
    private final KmsService kmsService;
    private final KeyStorage keyStorage;
    private final RotationPolicy rotationPolicy;
    private final EncryptionService encryptionService;

    private KeyInfo currentKEK;

    public KEKStrategy(KmsService kmsService, KeyStorage keyStorage, RotationPolicy rotationPolicy, EncryptionService encryptionService) {
        this.kmsService = kmsService;
        this.keyStorage = keyStorage;
        this.rotationPolicy = rotationPolicy;
        this.encryptionService = encryptionService;
    }

    /**
     * Constructor for KEKStrategy
     *
     * @param kmsService     KMS service
     * @param keyStorage     Key storage
     * @param rotationPolicy Rotation policy
     * @param keySize        Key size for the encryption service (dek)
     */
    public KEKStrategy(KmsService kmsService, KeyStorage keyStorage, RotationPolicy rotationPolicy, int keySize) {
        this.kmsService = kmsService;
        this.keyStorage = keyStorage;
        this.rotationPolicy = rotationPolicy;
        this.encryptionService = new AESEncryptionService(new KEKKeyResolver(), keySize);
    }

    public ByteBuffer encrypt(ByteBuffer data) {
        setupKEK();
        return encryptionService.encrypt(data);
    }

    public ByteBuffer decrypt(ByteBuffer encryptData) {
        setupKEK();
        return encryptionService.decrypt(encryptData);
    }

    private void setupKEK() {
        if (currentKEK == null) { //TODO concurrency check AtomicReference
            EncryptedKeyInfo encryptedKeyInfo = keyStorage.getCurrentKey();

            SecretKey secretKey;
            if (encryptedKeyInfo == null || rotationPolicy.shouldRotateKey(encryptedKeyInfo)) {
                log.info("Setting up KEK for the first time or rotating KEK, using kmsService: {}", kmsService.getClass().getSimpleName());
                GeneratedKey generatedKey = kmsService.generateKey();
                secretKey = generatedKey.getKey();

                encryptedKeyInfo = keyStorage.addKey(generatedKey.getEncryptedKey());//side effect
                log.trace("Adding key to keyStorage: {}", encryptedKeyInfo);
            } else {
                secretKey = kmsService.decryptKey(encryptedKeyInfo.encryptedKey());
                log.trace("Decrypted kek from keystore {}", encryptedKeyInfo);
            }
            currentKEK = encryptedKeyInfo.toKeyInfo(secretKey);
//            TODO: remove form code
            log.trace("[REMOVE]Current KEK: {}", currentKEK);
        }
    }

    private class KEKKeyResolver implements KeyResolver {
        @Override
        public SecretKey resolve(int keyId) {
            return kmsService.decryptKey(keyStorage.get(keyId).encryptedKey());
        }

        @Override
        public KeyInfo currentKey() {
            return currentKEK;
        }

        @Override
        public String resolverName() {
            return "kek";
        }
    }
}
