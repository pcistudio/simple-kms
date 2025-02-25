package com.pcistudio.kms;

import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

public class EncryptionProviderManager {
    private final Map<String, EncryptionProvider> encryptionProviderMap = new ConcurrentHashMap<>();
    private final AtomicReference<EncryptionProvider> defaultEncryptionProvider = new AtomicReference<>();

    public EncryptionProviderManager register(EncryptionProvider encryptionProvider) {
        encryptionProviderMap.compute(encryptionProvider.getName(), (key, existing) -> {
            if (existing != null) {
                throw new IllegalStateException("Encryption provider already registered: " + key);
            }
            return encryptionProvider;
        });
        return this;
    }

    public EncryptionProviderManager register(EncryptionProvider encryptionProvider, boolean defaultProvider) {
        register(encryptionProvider);
        if (defaultProvider) {
            defaultProvider(encryptionProvider.getName());
        }
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

}
