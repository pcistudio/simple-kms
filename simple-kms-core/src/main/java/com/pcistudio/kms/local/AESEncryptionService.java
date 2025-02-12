package com.pcistudio.kms.local;

import com.pcistudio.kms.EncryptionService;
import com.pcistudio.kms.KeyResolver;
import com.pcistudio.kms.model.GeneratedKey;
import com.pcistudio.kms.model.KeyInfo;
import com.pcistudio.kms.utils.KeyGenerationUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.function.Supplier;

public class AESEncryptionService implements EncryptionService {
    private static final Logger log = LoggerFactory.getLogger(AESEncryptionService.class);
    private static final String ALGORITHM = "AES";
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private final int keySize;
    private static int IV_SIZE = 12;
    private final KeyResolver keyResolver;
    private final Supplier<ByteBuffer> ivGenerator;

    public AESEncryptionService(KeyResolver keyResolver, int keySize, Supplier<ByteBuffer> ivGenerator) {
        if (keySize != 128 && keySize != 192 && keySize != 256) {
            throw new IllegalArgumentException("Key size must be 128, 192, or 256 bits.");
        }
        this.keySize = keySize;
        this.keyResolver = keyResolver;
        this.ivGenerator = ivGenerator;
    }

    public AESEncryptionService(KeyResolver keyResolver, int keySize) {
        this(keyResolver, keySize, () -> ByteBuffer.wrap(SECURE_RANDOM.generateSeed(IV_SIZE)));
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

    @Override
    public ByteBuffer decrypt(ByteBuffer encryptedData) {
        try {
            if (log.isTraceEnabled()) {
                log.trace("Decrypting data={} using {}. buffer position={}", Base64.getEncoder().encodeToString(encryptedData.array()), keyResolver.resolverName(), encryptedData.position());
            }

            int keyId = encryptedData.getInt();
            byte[] iv = new byte[IV_SIZE];
            encryptedData.get(iv);
            if (log.isTraceEnabled()) {
                log.trace("keyId={}, iv={}, resolver={}", keyId, Arrays.toString(iv), keyResolver.resolverName());
            }

            byte[] encryptedBytes = new byte[encryptedData.remaining()];
            encryptedData.get(encryptedBytes);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(128, iv);
            SecretKey key = keyResolver.resolve(keyId);

            if (log.isTraceEnabled()) {
                log.trace("Decrypting using key={} from resolver={}", keyId, keyResolver.resolverName());
            }

            if (log.isTraceEnabled()) {
                log.trace("[REMOVE]Decrypting with key={}[{}], data={}",
                        keyResolver.resolverName(),
                        Base64.getEncoder().encodeToString(key.getEncoded()),
                        Base64.getEncoder().encodeToString(encryptedData.array())
                );
            }
            cipher.init(Cipher.DECRYPT_MODE, key, spec);

            if (log.isDebugEnabled()) {
                log.debug("Data decrypt using key={} from resolver={}", keyId, keyResolver.resolverName());
            }
            byte[] bytes = cipher.doFinal(encryptedBytes);
            if (log.isTraceEnabled()) {
                log.trace("[REMOVE]Data decrypted with key={}[{}], data={}, result={}",
                        keyResolver.resolverName(),
                        Base64.getEncoder().encodeToString(key.getEncoded()),
                        Base64.getEncoder().encodeToString(encryptedData.array()),
                        Base64.getEncoder().encodeToString(bytes));
            }

            return ByteBuffer.wrap(bytes);
        } catch (Exception e) {
            throw new RuntimeException(e);
        } finally {
            encryptedData.rewind();
        }
    }

    @Override
    public ByteBuffer encrypt(ByteBuffer dataBuffer) {
        byte[] data = new byte[dataBuffer.remaining()];
        dataBuffer.get(data);
        return encrypt(data);
    }

    public ByteBuffer encrypt(byte[] data) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            byte[] iv = ivGenerator.get().array();

            GCMParameterSpec spec = new GCMParameterSpec(128, iv);
            KeyInfo keyInfo = keyResolver.currentKey();
            cipher.init(Cipher.ENCRYPT_MODE, keyInfo.key(), spec, SECURE_RANDOM);

            byte[] encryptedKey = cipher.doFinal(data);
            ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + encryptedKey.length + 4);
            byteBuffer.putInt(keyInfo.id());
            byteBuffer.put(iv);
            byteBuffer.put(encryptedKey);
            byteBuffer.flip();

            //TODO Remove
            log.trace("[REMOVE]Data encrypted with data={} with key={}{}, result={}", Base64.getEncoder().encodeToString(data), keyResolver.resolverName(), keyInfo, Base64.getEncoder().encodeToString(byteBuffer.array()));

            if (log.isDebugEnabled()) {
                log.debug("Data encrypted with key={}, resolve with {}", keyInfo.id(), keyResolver.resolverName());
            }

            return byteBuffer;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public String getKeyAlgorithm() {
        return ALGORITHM;
    }
}
