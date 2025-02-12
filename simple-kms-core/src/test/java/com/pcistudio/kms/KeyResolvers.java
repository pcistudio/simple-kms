package com.pcistudio.kms;

import com.pcistudio.kms.model.KeyInfo;

import javax.crypto.SecretKey;
import java.util.function.Supplier;

public interface KeyResolvers {

    static KeyResolver master(SecretKey key) {
        return new KeyResolver() {
            @Override
            public SecretKey resolve(int keyId) {
                return key;
            }

            @Override
            public KeyInfo currentKey() {
                return new KeyInfo(0, key);
            }

            @Override
            public String resolverName() {
                return "master";
            }
        };
    }

    static KeyResolver kek(Supplier<SecretKey> keySupplier) {
        return new KeyResolver() {
            @Override
            public SecretKey resolve(int keyId) {
                return keySupplier.get();
            }

            @Override
            public KeyInfo currentKey() {
                return new KeyInfo(0, keySupplier.get());
            }

            @Override
            public String resolverName() {
                return "kek";
            }
        };
    }
}
