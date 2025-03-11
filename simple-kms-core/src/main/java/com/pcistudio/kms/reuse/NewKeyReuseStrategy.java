package com.pcistudio.kms.reuse;

import com.pcistudio.kms.model.GeneratedKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.function.Supplier;

public class NewKeyReuseStrategy implements KeyReuseStrategy {

    private final Supplier<GeneratedKey> keySupplier;

    protected NewKeyReuseStrategy(Supplier<GeneratedKey> keySupplier) {
        this.keySupplier = keySupplier;

    }

    @Override
    public GeneratedKey generateKey() {
        return keySupplier.get();
    }

    public static class ReuseStrategyBuilder implements KeyReuseStrategyBuilder<NewKeyReuseStrategy, ReuseStrategyBuilder> {

        private static final Logger log = LoggerFactory.getLogger(ReuseStrategyBuilder.class);
        private Supplier<GeneratedKey> keySupplier;

        @Override
        public ReuseStrategyBuilder keySupplier(Supplier<GeneratedKey> keySupplier) {
            this.keySupplier = keySupplier;
            return this;
        }

        public CountKeyReuseStrategy.CountKeyReuseStrategyBuilder countBase() {
            return new CountKeyReuseStrategy.CountKeyReuseStrategyBuilder()
                    .keySupplier(keySupplier);
        }

        public TimeKeyReuseStrategy.TimeKeyReuseStrategyBuilder timeBase() {
            return new TimeKeyReuseStrategy.TimeKeyReuseStrategyBuilder()
                    .keySupplier(keySupplier);
        }

        @Override
        public NewKeyReuseStrategy build() {
            NewKeyReuseStrategy newKeyReuseStrategy = new NewKeyReuseStrategy(keySupplier);
            log.info("Created NewKeyReuseStrategy");
            return newKeyReuseStrategy;
        }
    }
}