package com.pcistudio.kms.local;

import com.pcistudio.kms.EncryptionService;
import com.pcistudio.kms.utils.KeyGenerationUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.function.Supplier;

public class AESEncryptionService implements EncryptionService {
    private static final Logger log = LoggerFactory.getLogger(AESEncryptionService.class);
    private static final String ALGORITHM = "AES";
    public static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final int IV_SIZE = 12;
    private final Supplier<ByteBuffer> ivGenerator;

    public AESEncryptionService(Supplier<ByteBuffer> ivGenerator) {
        this.ivGenerator = ivGenerator;
    }

    public AESEncryptionService() {
        this(() -> ByteBuffer.wrap(SECURE_RANDOM.generateSeed(IV_SIZE)));
    }


    @Override
    public ByteBuffer decrypt(SecretKey key, ByteBuffer encryptedData) {
        try {
            if (log.isTraceEnabled()) {
                log.trace("Decrypting data={}. buffer position={}", KeyGenerationUtil.toToBase64(encryptedData), encryptedData.position());
            }

            byte[] iv = new byte[IV_SIZE];
            encryptedData.get(iv);
            if (log.isTraceEnabled()) {
                log.trace("iv={}", Arrays.toString(iv));
            }

            byte[] encryptedBytes = new byte[encryptedData.remaining()];
            encryptedData.get(encryptedBytes);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(128, iv);

//            if (log.isTraceEnabled()) {
//                log.trace("[REMOVE]Decrypting with key={}, data={}",
//                        KeyGenerationUtil.keyToBase64(key),
//                        KeyGenerationUtil.toToBase64(encryptedData)
//                );
//            }
            cipher.init(Cipher.DECRYPT_MODE, key, spec);

            byte[] bytes = cipher.doFinal(encryptedBytes);
//            if (log.isTraceEnabled()) {
//                log.trace("[REMOVE]Data decrypted with key={}, data={}, result={}",
//                        KeyGenerationUtil.keyToBase64(key),
//                        KeyGenerationUtil.toToBase64(encryptedData),
//                        Base64.getEncoder().encodeToString(bytes));
//            }

            return ByteBuffer.wrap(bytes);
        } catch (Exception e) {
            throw new RuntimeException(e);
        } finally {
            encryptedData.rewind();
        }
    }

    @Override
    public ByteBuffer encrypt(SecretKey key, ByteBuffer dataBuffer) {
        return encrypt(key, dataBuffer.array());
    }

    private ByteBuffer encrypt(SecretKey key, byte[] data) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            byte[] iv = ivGenerator.get().array();

            GCMParameterSpec spec = new GCMParameterSpec(128, iv);

            cipher.init(Cipher.ENCRYPT_MODE, key, spec, SECURE_RANDOM);

            byte[] encryptedKey = cipher.doFinal(data);
            ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + encryptedKey.length + 4);
            byteBuffer.put(iv);
            byteBuffer.put(encryptedKey);
            byteBuffer.flip();

            //TODO Remove
//            log.trace("[REMOVE]Data encrypted with data={} with key={}, result={}", Base64.getEncoder().encodeToString(data), KeyGenerationUtil.keyToBase64(key), KeyGenerationUtil.toToBase64(byteBuffer));

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
