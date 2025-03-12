package com.pcistudio.kms.engine;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

public class EncryptionProviderManager {
    private static final Logger log = LoggerFactory.getLogger(EncryptionProviderManager.class);
    private final Map<String, EncryptionProvider> encryptionProviderMap = new ConcurrentHashMap<>();
    private final AtomicReference<EncryptionProvider> defaultEncryptionProvider = new AtomicReference<>();

    public EncryptionProviderManager register(EncryptionProvider encryptionProvider) {
        encryptionProviderMap.compute(encryptionProvider.getName(), (key, existing) -> {
            if (existing != null) {
                throw new IllegalStateException("Encryption provider already registered: " + key);
            }
            return encryptionProvider;
        });

        log.info("Register EncryptionProvider={}", encryptionProvider.getName());//NOPMD
        return this;
    }

    public EncryptionProviderManager register(EncryptionProvider encryptionProvider, boolean defaultProvider) {
        register(encryptionProvider);
        if (defaultProvider) {
            defaultProvider(encryptionProvider.getName());
        }
        return this;
    }

    /**
     * Override the previous provider. Useful on testing
     *
     * @param encryptionProvider
     * @return
     */
    public EncryptionProviderManager update(EncryptionProvider encryptionProvider) {
        encryptionProviderMap.put(encryptionProvider.getName(), encryptionProvider);

        log.info("Updated Register EncryptionProvider={}", encryptionProvider.getName());//NOPMD
        return this;
    }

    public void defaultProvider(String name) {
        EncryptionProvider provider = encryptionProviderMap.get(name);
        if (provider == null) {
            throw new IllegalArgumentException("Default encryption provider not found: " + name);
        }
        defaultEncryptionProvider.set(provider);
    }

    public Optional<EncryptionProvider> get(String name) {
        return Optional.ofNullable(encryptionProviderMap.get(name));
    }

    public EncryptionProvider getDefault() {
        EncryptionProvider provider = defaultEncryptionProvider.get();
        if (provider == null) {
            throw new IllegalStateException("Default encryption provider is not set.");
        }
        return provider;
    }

    public void validate() {
        if (!hasProviders()) {
            throw new IllegalStateException("None encryption provider defined. This can disabled this adding 'spring.simple-kms.enabled=false'");
        }
    }

    public boolean hasProviders() {
        return !encryptionProviderMap.isEmpty();
    }

}
