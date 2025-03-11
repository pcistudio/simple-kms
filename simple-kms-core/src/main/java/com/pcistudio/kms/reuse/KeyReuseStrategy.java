package com.pcistudio.kms.reuse;

import com.pcistudio.kms.model.GeneratedKey;

public interface KeyReuseStrategy {
    GeneratedKey generateKey();

    static NewKeyReuseStrategy.ReuseStrategyBuilder builder() {
        return new NewKeyReuseStrategy.ReuseStrategyBuilder();
    }
}