package com.pcistudio.kms.reuse;

import com.pcistudio.kms.model.GeneratedKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.atomic.LongAdder;
import java.util.function.Supplier;

public final class CountKeyReuseStrategy extends AbstractKeyReuseStrategy {

    private static final Logger log = LoggerFactory.getLogger(CountKeyReuseStrategy.class);
    private final int maxReuseCount;
    private final LongAdder count = new LongAdder();

    private CountKeyReuseStrategy(CountKeyReuseStrategyBuilder builder) {
        super(builder.keySupplier);
        this.maxReuseCount = builder.maxReuseCount;
    }

    @Override
    protected boolean generateCondition() {
        return count.intValue() >= maxReuseCount;
    }

    @Override
    protected void postGenerateAction() {
        if (log.isDebugEnabled()) {
            log.debug("new key generated after {}", count.intValue());
        }
        count.reset();
    }

    @Override
    protected void usageAction() {
        count.increment();
        if (log.isTraceEnabled()) {
            log.trace("usage count {}", count.intValue());
        }
    }

    public static class CountKeyReuseStrategyBuilder implements KeyReuseStrategyBuilder<CountKeyReuseStrategy, CountKeyReuseStrategyBuilder>  {
        private int maxReuseCount;
        private Supplier<GeneratedKey> keySupplier;

        public CountKeyReuseStrategyBuilder maxReuseCount(int maxReuseCount) {
            this.maxReuseCount = maxReuseCount;
            return this;
        }

        @Override
        public CountKeyReuseStrategyBuilder keySupplier(Supplier<GeneratedKey> keySupplier) {
            this.keySupplier = keySupplier;
            return this;
        }

        @Override
        public CountKeyReuseStrategy build() {
            return new CountKeyReuseStrategy(this);
        }
    }
}