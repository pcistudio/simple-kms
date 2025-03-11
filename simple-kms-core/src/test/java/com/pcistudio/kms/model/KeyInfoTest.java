package com.pcistudio.kms.model;

import com.pcistudio.kms.utils.KeyGenerationUtil;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class KeyInfoTest {
    private static final Logger log = LoggerFactory.getLogger(KeyInfoTest.class);

    @Test
    void testToString() {
        SecretKey secretKey = KeyGenerationUtil.generateKeyAES(new SecureRandom(), 256);
        KeyInfo keyInfo = new KeyInfo(1, secretKey);
        log.info("key: {}", keyInfo);
        assertNotNull(keyInfo.toString());
    }
}