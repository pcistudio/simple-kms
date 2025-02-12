package com.pcistudio.kms.local;

import com.pcistudio.kms.KeyResolver;
import com.pcistudio.kms.KeyResolverEncryptionService;
import com.pcistudio.kms.KmsService;
import com.pcistudio.kms.model.GeneratedKey;
import com.pcistudio.kms.model.KeyInfo;
import com.pcistudio.kms.utils.KeyGenerationUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static com.pcistudio.kms.local.AESEncryptionService.SECURE_RANDOM;

/**
 * Only use this if you don't have any way to get a KMS or HSM
 * This implementation expect that the key is in a env variable
 */
public class LocalKmsService implements KmsService {
    private static final Logger log = LoggerFactory.getLogger(LocalKmsService.class);
    private static final String ALGORITHM = "AES";

    private final List<SecretKey> masterKeysHistory;
    private int keySize;
    private KeyInfo masterKeyInfo;
    private final KeyResolverEncryptionService encryptionService;

    public LocalKmsService(List<SecretKey> masterKeysHistory, int keySize) {
        this.masterKeysHistory = new ArrayList<>(masterKeysHistory);
        this.masterKeyInfo = new KeyInfo(masterKeysHistory.size() - 1, masterKeysHistory.get(masterKeysHistory.size() - 1));
        this.encryptionService = new AESKeyResolverEncryptionService(
                new LocalKmsServiceKeyResolver(),
                new AESEncryptionService()
        );
        this.keySize = keySize;
    }

    public static LocalKmsService fromStringList(List<String> masterKeys, int keySize) {
        List<SecretKey> keys = masterKeys.stream()
                .map(masterKey -> (SecretKey) new SecretKeySpec(Base64.getDecoder().decode(masterKey), ALGORITHM))
                .toList();
        return new LocalKmsService(keys, keySize);
    }

    @Override
    public GeneratedKey generateKey() {
        try {
            SecretKey key = KeyGenerationUtil.generateKeyAES(SECURE_RANDOM, keySize);
            return new GeneratedKey()
                    .setKey(key)
                    .setEncryptedKey(encrypt(ByteBuffer.wrap(key.getEncoded())));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Encrypts the given data using AES/GCM/NoPadding.
     *
     * @param data The data to encrypt.
     * @return The encrypted data as a ByteBuffer.
     */
    public ByteBuffer encrypt(ByteBuffer dataBuffer) {
        return encryptionService.encrypt(dataBuffer);
    }

    @Override
    public ByteBuffer decrypt(ByteBuffer encryptedKey) {
        return encryptionService.decrypt(encryptedKey);
    }

    @Override
    public String getKeyAlgorithm() {
        return encryptionService.getKeyAlgorithm();
    }

    @Override
    public SecretKey decryptKey(ByteBuffer encryptedKey) {
        return encryptionService.decryptKey(encryptedKey);
    }

    public synchronized void liveRotation(SecretKey key) {
        masterKeysHistory.add(key);
        masterKeyInfo = new KeyInfo(masterKeysHistory.size() - 1, key);
    }

    private class LocalKmsServiceKeyResolver implements KeyResolver {
        @Override
        public SecretKey resolve(int keyId) {
            log.trace("masterKeyHistorySize={}", masterKeysHistory.size());
            log.trace("keyId={}", keyId);
            return masterKeysHistory.get(keyId);
        }

        @Override
        public KeyInfo currentKey() {
            return masterKeyInfo;
        }

        @Override
        public String resolverName() {
            return "masterkey";
        }
    }

}
