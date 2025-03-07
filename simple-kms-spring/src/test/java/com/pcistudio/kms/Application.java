package com.pcistudio.kms;

import com.pcistudio.kms.autoconfigure.ProviderProperties;
import com.pcistudio.kms.engine.EncryptionEngine;
import com.pcistudio.kms.engine.serialization.Serializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.utility.DockerImageName;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.KmsClientBuilder;
import software.amazon.awssdk.services.kms.model.CreateKeyRequest;
import software.amazon.awssdk.services.kms.model.CreateKeyResponse;
import software.amazon.awssdk.services.kms.model.DataKeySpec;

import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

@SpringBootApplication
public class Application implements CommandLineRunner {


    private static final int DEFAULT_EXPOSED_PORT = 4566;
    private static final String IMAGE = "localstack/localstack";
    private static final Logger log = LoggerFactory.getLogger(Application.class);
    private static GenericContainer<?> container;
    private static String keyId;
    private static KmsClientBuilder kmsClientBuilder;
    private static String MASTER_KEY = "WgBhmFfd+SN2mw6GjCjJ2J9xDtPSoQXUQ+gf6Rc397c=";
    @Autowired
    private EncryptionEngine encryptionEngine;


    public static void main(String[] args) {
        initContainer();

        System.setProperty("spring.simple-kms.providers.provider1.type", ProviderProperties.ProviderType.AWS.name());
        System.setProperty("spring.simple-kms.providers.provider1.iv-size", "" + 12 * 8);
        System.setProperty("spring.simple-kms.providers.provider1.serializer", Serializer.PROTOBUF.name());

        System.setProperty("spring.simple-kms.providers.provider1.aws.key", keyId);
        System.setProperty("spring.simple-kms.providers.provider1.aws.data-key-spec", DataKeySpec.AES_256.toString());


        System.setProperty("spring.simple-kms.providers.provider2.default-provider", "true");
        System.setProperty("spring.simple-kms.providers.provider2.type", ProviderProperties.ProviderType.AWS.name());
        System.setProperty("spring.simple-kms.providers.provider2.iv-size", "" + 12 * 8);
        System.setProperty("spring.simple-kms.providers.provider2.serializer", Serializer.PROTOBUF.name());

        System.setProperty("spring.simple-kms.providers.provider2.aws.key", keyId);
//        System.setProperty("spring.simple-kms.providers.provider2.aws.data-key-spec", DataKeySpec.AES_128.toString());
        System.setProperty("spring.simple-kms.providers.provider2.aws.data-key-spec", DataKeySpec.AES_128.toString());

//        System.setProperty("spring.simple-kms.providers.provider3.default-provider", "true");
        System.setProperty("spring.simple-kms.providers.provider3.type", ProviderProperties.ProviderType.LOCAL.name());
        System.setProperty("spring.simple-kms.providers.provider3.iv-size", "" + 12 * 8);
        System.setProperty("spring.simple-kms.providers.provider3.serializer", Serializer.PROTOBUF.name());

//        System.setProperty("spring.simple-kms.providers.provider3.local.key", keyId);
//        System.setProperty("spring.simple-kms.providers.provider3.local.data-key-spec", DataKeySpec.AES_128.toString());

        System.setProperty("spring.simple-kms.providers.provider3.local.master-keys", MASTER_KEY);

        SpringApplication.run(Application.class);
    }

    static void initContainer() {
        container = new GenericContainer<>(DockerImageName.parse(IMAGE))
                .withExposedPorts(DEFAULT_EXPOSED_PORT)
                .withEnv("SERVICES", "kms");
        container.start();
        kmsClientBuilder = KmsClient.builder()
                .region(Region.US_EAST_1)
                .endpointOverride(URI.create("http://%s:%d".formatted(container.getHost(), container.getFirstMappedPort())))
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create("test", "test")
                ));
        KmsClient kmsClient = kmsClientBuilder.build();
        CreateKeyResponse key = kmsClient.createKey(CreateKeyRequest.builder().build());
        keyId = key.keyMetadata().keyId();
    }

    @Configuration
    public static class KmsClientBuilderConfiguration {
        @Bean
        KmsClientBuilder kmsClientBuilder() {
            return kmsClientBuilder;
        }
    }

    @Override
    public void run(String... args) throws Exception {
        ByteBuffer encrypt = encryptionEngine.encrypt(ByteBuffer.wrap("hello world".getBytes(StandardCharsets.UTF_8)));

        ByteBuffer decrypt = encryptionEngine.decrypt(encrypt);

        log.info("Decrypted test -> {} encryptedSize={}", new String(decrypt.array(), StandardCharsets.UTF_8), encrypt.capacity());
    }
}