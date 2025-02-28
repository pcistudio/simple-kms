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

public class LocalKeyResolverEncryptionService implements KeyResolverEncryptionService {
    private static final Logger log = LoggerFactory.getLogger(LocalKeyResolverEncryptionService.class);

    private final KeyResolver keyResolver;

    private final EncryptionService encryptionService;

    public LocalKeyResolverEncryptionService(KeyResolver keyResolver, EncryptionService encryptionService) {
        this.keyResolver = keyResolver;
        this.encryptionService = encryptionService;
    }

    @Override
    public ByteBuffer decrypt(ByteBuffer encryptedData) {
        if (log.isTraceEnabled()) {
            log.trace("Decrypting data={} using {}. buffer position={}", Base64.getEncoder().encodeToString(encryptedData.array()), keyResolver.resolverName(), encryptedData.position());
        }

        int keyId = encryptedData.getInt();
        SecretKey key = keyResolver.resolve(keyId);
        return encryptionService.decrypt(key, encryptedData);
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
