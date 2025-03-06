package com.pcistudio.kms.reuse;

import com.pcistudio.kms.model.GeneratedKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;

public abstract class AbstractKeyReuseStrategy extends NewKeyReuseStrategy {

    private static final Logger log = LoggerFactory.getLogger(AbstractKeyReuseStrategy.class);

    private GeneratedKey generatedKey;
    private final ReentrantLock lock = new ReentrantLock();

    protected AbstractKeyReuseStrategy(Supplier<GeneratedKey> keySupplier) {
        super(keySupplier);
        generatedKey = keySupplier.get();
    }

    @Override
    public GeneratedKey generateKey() {
        if (generateCondition()) {
            try {
                updateKey();
            } catch (RuntimeException ex) {
                log.error("Error generating key", ex);
            }
        }
        usageAction();
        return generatedKey;
    }

    protected abstract boolean generateCondition();

    protected abstract void postGenerateAction();

    protected abstract void usageAction();

    private void updateKey() {
        if (lock.tryLock()) {
            try {
                generatedKey = super.generateKey();
                postGenerateAction();
            } finally {
                lock.unlock();
            }
        }
    }
}