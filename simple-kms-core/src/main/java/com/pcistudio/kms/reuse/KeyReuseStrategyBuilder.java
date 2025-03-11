package com.pcistudio.kms.reuse;

import com.pcistudio.kms.model.GeneratedKey;

import java.util.function.Supplier;

public interface KeyReuseStrategyBuilder<T extends KeyReuseStrategy, B extends KeyReuseStrategyBuilder<T,B>> {
    B keySupplier(Supplier<GeneratedKey> keySupplier);
    T build();
}