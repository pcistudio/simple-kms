package com.pcistudio.kms.aws;

import com.pcistudio.kms.KmsService;
import com.pcistudio.kms.model.GeneratedKey;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.KmsClientBuilder;
import software.amazon.awssdk.services.kms.model.*;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;


public class AwsKmsService implements KmsService {
    private final String keyId;
    private final KmsClient kmsClient;
    private final DataKeySpec dataKeySpec;

    public AwsKmsService(String keyId, KmsClientBuilder kmsClientBuilder, DataKeySpec dataKeySpec) {
        this.keyId = keyId;
        this.kmsClient = kmsClientBuilder.build();
        this.dataKeySpec = dataKeySpec;
        Runtime.getRuntime().addShutdownHook(new Thread(kmsClient::close));
    }

    @Override
    public GeneratedKey generateKey() {
        GenerateDataKeyRequest request = GenerateDataKeyRequest.builder()
                .keyId(keyId)
                .keySpec(dataKeySpec)
                .build();
        GenerateDataKeyResponse generateDataKeyResponse = kmsClient.generateDataKey(request);
        ByteBuffer byteBuffer = ByteBuffer.wrap(generateDataKeyResponse.ciphertextBlob().asByteArrayUnsafe());
        SecretKeySpec key = new SecretKeySpec(generateDataKeyResponse.plaintext().asByteArrayUnsafe(), getKeyAlgorithm());

        return new GeneratedKey()
                .setKey(key)
                .setEncryptedKey(byteBuffer);
    }

    @Override
    public ByteBuffer encrypt(ByteBuffer data) {
        EncryptRequest encryptRequest = EncryptRequest.builder()
                .keyId(keyId)
                .plaintext(SdkBytes.fromByteBuffer(data))
                .build();

        EncryptResponse encrypt = kmsClient.encrypt(encryptRequest);

        return ByteBuffer.wrap(encrypt.ciphertextBlob().asByteArrayUnsafe());
    }

    @Override
    public ByteBuffer decrypt(ByteBuffer encryptedKey) {
        DecryptRequest decryptRequest = DecryptRequest.builder()
                .keyId(keyId)
                .ciphertextBlob(SdkBytes.fromByteBuffer(encryptedKey))
                .build();
        DecryptResponse response = kmsClient.decrypt(decryptRequest);
        return ByteBuffer.wrap(response.plaintext().asByteArrayUnsafe());
    }

    @Override
    public String getKeyAlgorithm() {
        return "AES";
    }

    @Override
    public SecretKey decryptKey(ByteBuffer encryptedKey) {
        ByteBuffer keyDecrypted = decrypt(encryptedKey);
        return new SecretKeySpec(keyDecrypted.array(), getKeyAlgorithm());
    }
}
