package com.pcistudio.kms.util;

import com.pcistudio.kms.utils.KeyGenerationUtil;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;

class StaticKeysTest {

    private static final Logger log = LoggerFactory.getLogger(StaticKeysTest.class);

    @ParameterizedTest
    @ValueSource(ints = {1, 2, 3})
    @DisplayName("This test will help you generate more keys in case more static keys are needed")
    void generateKey(int keys) {
        SecureRandom secureRandom = new SecureRandom();
        SecretKey masterKey = KeyGenerationUtil.generateKeyAES(secureRandom, 256);
        log.info("masterKey={}", KeyGenerationUtil.keyToBase64(masterKey));

        List<SecretKey> keyList = new ArrayList<>();
        for (int i = 0; i < keys; i++) {
            keyList.add(KeyGenerationUtil.generateKeyAES(secureRandom, 256));
        }

        log.info("keys={}", keyList.stream().map(KeyGenerationUtil::keyToBase64).collect(Collectors.joining(",")));
        assertEquals(keys, keyList.size());
    }

}