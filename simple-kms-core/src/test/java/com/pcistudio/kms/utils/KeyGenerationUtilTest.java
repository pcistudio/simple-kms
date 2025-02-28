package com.pcistudio.kms.utils;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class KeyGenerationUtilTest {

    private static final Logger log = LoggerFactory.getLogger(KeyGenerationUtilTest.class);

    @Test
    void testToToBase64() {
        String toBase64 = KeyGenerationUtil.toToBase64("A filter file is an XML document with a top-level FindBugsFilter element which has some number of Match elements as children. Each Match element represents a predicate which is applied to generated bug instances. Usually, a filter will be used to exclude bug instances. For example:".getBytes(StandardCharsets.UTF_8));
        log.info("{}", toBase64);
        assertNotNull(toBase64);
    }
}