package com.pcistudio.kms.local;


import com.pcistudio.kms.KeyStorage;
import com.pcistudio.kms.model.EncryptedKeyInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * KeyManager implementation Just to testing
 * It will lose all the keys when the application is restarted
 */
public class InMemoryKeyStorage implements KeyStorage {
    private static final Logger log = LoggerFactory.getLogger(InMemoryKeyStorage.class);
    private final List<EncryptedKeyInfo> keys = new ArrayList<>();
    private final Clock clock;

    public InMemoryKeyStorage(Clock clock) {
        this.clock = clock;
    }

    public InMemoryKeyStorage() {
        this(Clock.systemUTC());
    }

    @Override
    public synchronized EncryptedKeyInfo addKey(ByteBuffer key) {
        EncryptedKeyInfo encryptedKeyInfo = new EncryptedKeyInfo(keys.size(), key, Instant.now(clock));
        keys.add(encryptedKeyInfo);
        log.debug("Added key {} to the key storge", encryptedKeyInfo);
        return encryptedKeyInfo;
    }

    @Override
    public EncryptedKeyInfo get(int id) {
        if (id >= keys.size()) {
            throw new IllegalStateException("Key %d not present".formatted(id));
        }
        return keys.get(id);
    }

    @Override
    public EncryptedKeyInfo getCurrentKey() {
        if (keys.isEmpty()) {
            return null;
        }

        return keys.get(keys.size() - 1);
    }
}
