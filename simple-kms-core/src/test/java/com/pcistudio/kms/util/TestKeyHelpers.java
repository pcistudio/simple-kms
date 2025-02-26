package com.pcistudio.kms.util;

import java.util.stream.Stream;


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
    public static Stream<TestKeyHelper> staticOnly() {
        return Stream.of(
                new StaticKeyHelper()
        );
    }
}
