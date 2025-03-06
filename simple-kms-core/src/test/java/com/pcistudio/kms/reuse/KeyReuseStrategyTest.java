package com.pcistudio.kms.reuse;

import com.pcistudio.kms.local.LocalKmsService;
import com.pcistudio.kms.model.GeneratedKey;
import com.pcistudio.kms.util.TestKeyHelper;
import com.pcistudio.kms.util.TestKeyHelpers;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertNotNull;

@ExtendWith(OutputCaptureExtension.class)
class KeyReuseStrategyTest {

    private static final Logger log = LoggerFactory.getLogger(KeyReuseStrategyTest.class);

    @ParameterizedTest
    @MethodSource("com.pcistudio.kms.util.TestKeyHelpers#staticDefault")
    void testNewKeyReuseStrategy(TestKeyHelper testKeyHelper) {
        LocalKmsService localKmsService = testKeyHelper.kmsService();
        NewKeyReuseStrategy newKeyReuseStrategy = KeyReuseStrategy.builder()
                .keySupplier(localKmsService::generateKey)
                .build();

        assertNotNull(newKeyReuseStrategy);
        GeneratedKey generatedKey = newKeyReuseStrategy.generateKey();
        assertNotNull(generatedKey);
        GeneratedKey generatedKey2 = newKeyReuseStrategy.generateKey();
        Assertions.assertThat(generatedKey.getKey().getEncoded()).isNotEqualTo(generatedKey2.getKey().getEncoded());
    }

    @Test
    void testCountKeyReuseStrategy(CapturedOutput capturedOutput) {
        TestKeyHelper testKeyHelper = TestKeyHelpers.staticDefault().findFirst().get();
        LocalKmsService localKmsService = testKeyHelper.kmsService();
        CountKeyReuseStrategy countKeyReuseStrategy = KeyReuseStrategy.builder()
                .keySupplier(localKmsService::generateKey)
                .countBase()
                .maxReuseCount(20)
                .build();

        GeneratedKey generatedKey = countKeyReuseStrategy.generateKey();

        for (int i = 2; i <= 20; i++) {
            GeneratedKey sameKey = countKeyReuseStrategy.generateKey();
            log.info("iteration={}", i);
            Assertions.assertThat(generatedKey.getKey().getEncoded()).isEqualTo(sameKey.getKey().getEncoded());
        }

        GeneratedKey nextKey = countKeyReuseStrategy.generateKey();
        Assertions.assertThat(generatedKey.getKey().getEncoded()).isNotEqualTo(nextKey.getKey().getEncoded());

        for (int i = 2; i <= 20; i++) {
            GeneratedKey sameKey = countKeyReuseStrategy.generateKey();
            log.info("iteration={}", i);
            Assertions.assertThat(nextKey.getKey().getEncoded()).isEqualTo(sameKey.getKey().getEncoded());
        }

        Assertions.assertThat(capturedOutput.getOut()).contains("new key generated after 20");
    }

    @Test
    void testTimeKeyReuseStrategy(CapturedOutput capturedOutput) throws InterruptedException {
        TestKeyHelper testKeyHelper = TestKeyHelpers.staticDefault().findFirst().get();
        LocalKmsService localKmsService = testKeyHelper.kmsService();
        TimeKeyReuseStrategy timeKeyReuseStrategy = KeyReuseStrategy.builder()
                .keySupplier(localKmsService::generateKey)
                .timeBase()
                .generationInterval(Duration.ofSeconds(5))
                .build();

        GeneratedKey generatedKey = timeKeyReuseStrategy.generateKey();

        for (int i = 2; i <= 20; i++) {
            GeneratedKey sameKey = timeKeyReuseStrategy.generateKey();
            log.info("iteration={}", i);
            Assertions.assertThat(generatedKey.getKey().getEncoded()).isEqualTo(sameKey.getKey().getEncoded());
        }
        Thread.sleep(5000);

        GeneratedKey nextKey = timeKeyReuseStrategy.generateKey();
        Assertions.assertThat(generatedKey.getKey().getEncoded()).isNotEqualTo(nextKey.getKey().getEncoded());

        Thread.sleep(5000);

        timeKeyReuseStrategy.generateKey();
        Assertions.assertThat(capturedOutput.getOut()).containsPattern("new key generated after PT5.\\d+S");
    }


}