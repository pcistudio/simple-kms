package com.pcistudio.kms;

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

import java.net.URI;

@Configuration
public class KmsClientBuilderConfiguration {
    private static final int DEFAULT_EXPOSED_PORT = 4566;
    private static final String IMAGE = "localstack/localstack";
    private static GenericContainer<?> container;
    private static String keyId;
    private static KmsClientBuilder kmsClientBuilder;

    static {
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
        System.setProperty("spring.simple-kms.providers.provider1.aws.key", keyId);
        System.setProperty("spring.simple-kms.providers.provider2.aws.key", keyId);
    }

    @Bean
    KmsClientBuilder kmsClientBuilder() {
        return kmsClientBuilder;
    }

}