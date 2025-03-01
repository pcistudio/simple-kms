package com.pcistudio.kms.engine;

import com.pcistudio.kms.engine.serialization.Serializer;
import com.pcistudio.kms.util.TestKeyHelper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.CreateKeyResponse;
import software.amazon.awssdk.services.kms.model.DataKeySpec;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;


@Testcontainers
class AwsEncryptionEngineTest {

    private static final int DEFAULT_EXPOSED_PORT = 4566;
    private static final String IMAGE = "localstack/localstack";
    private static final Logger log = LoggerFactory.getLogger(AwsEncryptionEngineTest.class);

    @Container
    private final GenericContainer<?> container = new GenericContainer<>(DockerImageName.parse(IMAGE))
            .withExposedPorts(DEFAULT_EXPOSED_PORT)
            .waitingFor(Wait.forListeningPorts(DEFAULT_EXPOSED_PORT))
            .withEnv("SERVICES", "kms");
    KmsClient kmsClient;

    @BeforeEach
    void setUp() {
        kmsClient = KmsClient.builder()
                .region(Region.US_EAST_1)
                .endpointOverride(java.net.URI.create("http://%s:%d".formatted(container.getHost(), container.getFirstMappedPort())))
                .credentialsProvider(StaticCredentialsProvider.create(
                        software.amazon.awssdk.auth.credentials.AwsBasicCredentials.create("test", "test")
                ))
                .build();
    }

    @AfterEach
    void tearDown() {
        this.kmsClient.close();
    }

    @Test
    void testAwsAESEncryptionProvider() {
        assertThat(container.isRunning()).isTrue();

        CreateKeyResponse createKeyResponse = kmsClient.createKey();
        String keyId = createKeyResponse.keyMetadata().keyId();

        EncryptionProvider awsAESEncryptionProvider = AwsAESEncryptionProvider.builder()
                .dataKeySpec(DataKeySpec.AES_256)
                .ivSupplier(() -> ByteBuffer.wrap(new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}))
                .kmsClient(kmsClient)
                .keyId(keyId)
                .serializer(Serializer.JSON)
                .build();

        EncryptionProviderManager encryptionProviderManager = new EncryptionProviderManager()
                .register(awsAESEncryptionProvider, true);

        EncryptionEngine encryptionEngine = new EncryptionEngine(encryptionProviderManager);

        ByteBuffer encrypted = encryptionEngine.encrypt(ByteBuffer.wrap("test".getBytes()));

        ByteBuffer decrypt = encryptionEngine.decrypt(encrypted);

        assertEquals("test", new String(decrypt.array(), StandardCharsets.UTF_8));

    }

    @ParameterizedTest
    @MethodSource("com.pcistudio.kms.util.TestKeyHelpers#staticDefault")
    void testEncryptionWithTwoProviders(TestKeyHelper testKeyHelper) {
        String test = "Length prefixes are another major concept in the wire format. " +
                "The LEN wire type has a dynamic length, specified by a varint immediately after the tag, " +
                "which is followed by the payload as usual.";

        EncryptionProvider localAESEncryptionProvider = testKeyHelper.localProvider(Serializer.JSON);

        EncryptionProviderManager encryptionProviderManager = new EncryptionProviderManager()
                .register(localAESEncryptionProvider, true);

        EncryptionEngine encryptionEngine = new EncryptionEngine(encryptionProviderManager);

        ByteBuffer encrypted = encryptionEngine.encrypt(ByteBuffer.wrap(test.getBytes()));

        ByteBuffer decrypt = encryptionEngine.decrypt(encrypted);

        assertEquals(test, new String(decrypt.array(), StandardCharsets.UTF_8));

        CreateKeyResponse createKeyResponse = kmsClient.createKey();
        String keyId = createKeyResponse.keyMetadata().keyId();

        EncryptionProvider awsAESEncryptionProvider = AwsAESEncryptionProvider.builder()
                .dataKeySpec(DataKeySpec.AES_256)
                .ivSupplier(() -> ByteBuffer.wrap(new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}))
                .kmsClient(kmsClient)
                .keyId(keyId)
                .serializer(Serializer.PROTOBUF)
                .build();
        encryptionProviderManager.register(awsAESEncryptionProvider, true);


        encrypted.rewind();
        log.info("--------------------------------------");
        ByteBuffer decrypt2 = encryptionEngine.decrypt(encrypted);
        assertEquals(test, new String(decrypt2.array(), StandardCharsets.UTF_8));

        String test2 = test + "2";
        ByteBuffer encrypted2 = encryptionEngine.encrypt(ByteBuffer.wrap(test2.getBytes()));

        decrypt2 = encryptionEngine.decrypt(encrypted2);

        assertEquals(test2, new String(decrypt2.array(), StandardCharsets.UTF_8));
    }
}