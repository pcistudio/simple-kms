package com.pcistudio.kms.local;

import com.pcistudio.kms.EncryptionException;
import com.pcistudio.kms.EncryptionService;
import com.pcistudio.kms.utils.KeyGenerationUtil;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.function.Supplier;

public class AESEncryptionService implements EncryptionService {
    private static final Logger log = LoggerFactory.getLogger(AESEncryptionService.class);
    private static final String ALGORITHM = "AES";
    public static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private final int ivSize;
    private final Supplier<ByteBuffer> ivGenerator;

    public AESEncryptionService(Supplier<ByteBuffer> ivGenerator) {
        this.ivGenerator = ivGenerator;
        this.ivSize = ivGenerator.get().capacity();
    }

    public AESEncryptionService(int ivSize) {
        this(() -> ByteBuffer.wrap(SECURE_RANDOM.generateSeed(ivSize)));
    }

    @Override
    @SuppressFBWarnings("REC_CATCH_EXCEPTION")
    public ByteBuffer decrypt(SecretKey key, ByteBuffer encryptedData) {
        try {
            if (log.isTraceEnabled()) {
                log.trace("Decrypting data={}. buffer position={}", KeyGenerationUtil.toToBase64(encryptedData), encryptedData.position());
            }

            byte[] iv = new byte[ivSize];
            encryptedData.get(iv);
            if (log.isTraceEnabled()) {
                log.trace("iv={}", Arrays.toString(iv));
            }

            byte[] encryptedBytes = new byte[encryptedData.remaining()];
            encryptedData.get(encryptedBytes);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, spec);
            if (log.isTraceEnabled()) {
                log.trace("Decrypting {} using iv={} and key={}", KeyGenerationUtil.toToBase64(encryptedBytes), Arrays.toString(iv), KeyGenerationUtil.keyToBase64(key));
            }
            byte[] bytes = cipher.doFinal(encryptedBytes);
            if (log.isTraceEnabled()) {
                log.trace("Decrypting result={}", KeyGenerationUtil.toToBase64(bytes));
            }
            return ByteBuffer.wrap(bytes);
        } catch (Exception e) {
            throw new EncryptionException("Error decrypting data", e);
        } finally {
            encryptedData.rewind();
        }
    }

    @Override
    public ByteBuffer encrypt(SecretKey key, ByteBuffer dataBuffer) {
        return encrypt(key, dataBuffer.array());
    }

    @SuppressFBWarnings("REC_CATCH_EXCEPTION")
    private ByteBuffer encrypt(SecretKey key, byte[] data) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            byte[] iv = ivGenerator.get().array();

            GCMParameterSpec spec = new GCMParameterSpec(128, iv);

            cipher.init(Cipher.ENCRYPT_MODE, key, spec, SECURE_RANDOM);
            if (log.isTraceEnabled()) {
                log.trace("Encrypting {} using iv={} and key={}", KeyGenerationUtil.toToBase64(data), Arrays.toString(iv), KeyGenerationUtil.keyToBase64(key));
            }
            byte[] encryptedKey = cipher.doFinal(data);
            if (log.isTraceEnabled()) {
                log.trace("Encrypting result={}", KeyGenerationUtil.toToBase64(encryptedKey));
            }
//            ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + encryptedKey.length + 4);
            ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + encryptedKey.length);
            byteBuffer.put(iv);
            byteBuffer.put(encryptedKey);
            byteBuffer.flip();

            return byteBuffer;
        } catch (Exception e) {
            throw new EncryptionException("Error encrypting data", e);
        }
    }

    @Override
    public String getKeyAlgorithm() {
        return ALGORITHM;
    }
}
