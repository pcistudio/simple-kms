package com.pcistudio.kms.reuse;

import com.pcistudio.kms.model.GeneratedKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.function.Supplier;

public final class TimeKeyReuseStrategy extends AbstractKeyReuseStrategy {

    private static final Logger log = LoggerFactory.getLogger(TimeKeyReuseStrategy.class);
    private Instant lastGeneration;
    private final Duration generationInterval;

    private TimeKeyReuseStrategy(TimeKeyReuseStrategyBuilder builder) {
        super(builder.keySupplier);
        this.lastGeneration = Instant.now();
        this.generationInterval = builder.generationInterval;
    }

    @Override
    protected boolean generateCondition() {
        return lastGeneration.plus(generationInterval).isBefore(Instant.now());
    }

    @Override
    protected void postGenerateAction() {
        if (log.isDebugEnabled()) {
            log.debug("new key generated after {}", Duration.between(lastGeneration, Instant.now()));
        }
        this.lastGeneration = Instant.now();
    }

    @Override
    protected void usageAction() {
        //Nothing to do here
    }

    public static class TimeKeyReuseStrategyBuilder implements KeyReuseStrategyBuilder<TimeKeyReuseStrategy, TimeKeyReuseStrategyBuilder> {
        private Duration generationInterval;
        private Supplier<GeneratedKey> keySupplier;

        public TimeKeyReuseStrategyBuilder generationInterval(Duration generationInterval) {
            this.generationInterval = generationInterval;
            return this;
        }

        @Override
        public TimeKeyReuseStrategyBuilder keySupplier(Supplier<GeneratedKey> keySupplier) {
            this.keySupplier = keySupplier;
            return this;
        }

        @Override
        public TimeKeyReuseStrategy build() {
            return new TimeKeyReuseStrategy(this);
        }
    }
}