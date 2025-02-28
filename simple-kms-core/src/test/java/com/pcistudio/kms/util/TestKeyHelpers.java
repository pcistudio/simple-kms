package com.pcistudio.kms.util;

import java.util.stream.Stream;

import static com.pcistudio.kms.util.StaticKeys.TWO_KEYS;
import static com.pcistudio.kms.util.StaticKeys.TWO_MASTER_KEYS;


public class TestKeyHelpers {
    public static Stream<TestKeyHelper> all() {
        return Stream.of(
                new StaticKeyHelper(),
                new RandomKeyHelper(256, 12)
        );
    }

    /**
     * Use while debugging
     * @return Stream
     */
    public static Stream<TestKeyHelper> staticsOnly() {
        return Stream.of(
                new StaticKeyHelper(),
                new StaticKeyHelper(StaticKeys.DEFAULT_TWO_KEYS),
                new StaticKeyHelper(StaticKeys.DEFAULT_THREE_KEYS),
                new StaticKeyHelper(TWO_KEYS),
                new StaticKeyHelper(StaticKeys.THREE_KEYS)
        );
    }

    public static Stream<TestKeyHelper> staticDefault() {
        return Stream.of(
                new StaticKeyHelper(TWO_MASTER_KEYS)
        );
    }
}
