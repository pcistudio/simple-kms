package com.pcistudio.kms.local;

import com.pcistudio.kms.EncryptionService;
import com.pcistudio.kms.KeyResolver;
import com.pcistudio.kms.KeyResolverEncryptionService;
import com.pcistudio.kms.model.KeyInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.util.Base64;

//TODO Remove AES from the name
public class AESKeyResolverEncryptionService implements KeyResolverEncryptionService {
    private static final Logger log = LoggerFactory.getLogger(AESKeyResolverEncryptionService.class);

    private final KeyResolver keyResolver;

    private final EncryptionService encryptionService;

    public AESKeyResolverEncryptionService(KeyResolver keyResolver, EncryptionService encryptionService) {
        this.keyResolver = keyResolver;
        this.encryptionService = encryptionService;
    }

//    @Override
//    public GeneratedKey generateKey() {
//        try {
//            SecretKey key = KeyGenerationUtil.generateKeyAES(SECURE_RANDOM, keySize);
//            return new GeneratedKey()
//                    .setKey(key)
//                    .setEncryptedKey(encrypt(ByteBuffer.wrap(key.getEncoded())));
//        } catch (NoSuchAlgorithmException e) {
//            throw new RuntimeException(e);
//        }
//    }

    @Override
    public ByteBuffer decrypt(ByteBuffer encryptedData) {
        if (log.isTraceEnabled()) {
            log.trace("Decrypting data={} using {}. buffer position={}", Base64.getEncoder().encodeToString(encryptedData.array()), keyResolver.resolverName(), encryptedData.position());
        }

        int keyId = encryptedData.getInt();
        SecretKey key = keyResolver.resolve(keyId);
        ByteBuffer decrypt = encryptionService.decrypt(key, encryptedData);

//        if (log.isTraceEnabled()) {
//            log.trace("[REMOVE]Data decrypted with key={}[{}], data={}, result={}",
//                    keyResolver.resolverName(),
//                    Base64.getEncoder().encodeToString(key.getEncoded()),
//                    Base64.getEncoder().encodeToString(encryptedData.array()),
//                    Base64.getEncoder().encodeToString(decrypt.array()));
//        }

        return decrypt;
    }

    @Override
    public ByteBuffer encrypt(ByteBuffer dataBuffer) {
        KeyInfo keyInfo = keyResolver.currentKey();
        ByteBuffer encrypt = encryptionService.encrypt(keyInfo.key(), dataBuffer);

        ByteBuffer result = ByteBuffer.allocate(4 + encrypt.capacity());
        result.putInt(keyInfo.id());
        result.put(encrypt);
        result.flip();
        return result;
    }

    @Override
    public String getKeyAlgorithm() {
        return encryptionService.getKeyAlgorithm();
    }
}
