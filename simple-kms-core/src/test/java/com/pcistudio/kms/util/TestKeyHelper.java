package com.pcistudio.kms.util;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.util.function.Supplier;


public interface TestKeyHelper {
    SecretKey getKEK();

    SecretKey getMasterKey();

    Supplier<ByteBuffer> ivGenerator();

    default Supplier<SecretKey> getKEKSupplier() {
        return this::getKEK;
    }

    default Supplier<SecretKey> getMasterKeySupplier() {
        return this::getMasterKey;
    }
}
