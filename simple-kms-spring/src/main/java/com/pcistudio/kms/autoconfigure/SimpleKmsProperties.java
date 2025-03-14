package com.pcistudio.kms.autoconfigure;

import com.pcistudio.kms.engine.AwsAESEncryptionProvider;
import com.pcistudio.kms.engine.EncryptionProviderBuilder;
import com.pcistudio.kms.engine.LocalAESEncryptionProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.Assert;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@ConfigurationProperties(
        prefix = "spring.simple-kms"
)
public class SimpleKmsProperties {

    private static final Logger log = LoggerFactory.getLogger(SimpleKmsProperties.class);
    private Map<String, ProviderProperties> providers = new HashMap<>();

    public SimpleKmsProperties setProviders(Map<String, ProviderProperties> providers) {
        this.providers = new HashMap<>(providers);
        if (providers.size() == 1) {
            providers.entrySet()
                    .stream()
                    .findAny()
                    .ifPresent(entry -> entry.getValue().setDefaultProvider(true));

        }
        return this;
    }

    List<BuilderProperties<LocalAESEncryptionProvider.LocalAESEncryptionProviderBuilder>> initializeLocalBuilder() {
        checkDefaultProviders();
        return providers.entrySet()
                .stream()
                .map(entry -> entry.getValue().setId(entry.getKey()))
                .filter(ProviderProperties::isLocal)
                .map(properties -> new BuilderProperties<>(properties.initializeLocalBuilder(), properties))
                .toList();
    }

    List<BuilderProperties<AwsAESEncryptionProvider.AwsAESEncryptionProviderBuilder>> initializeAwsBuilder() {
        checkDefaultProviders();
        return providers.entrySet()
                .stream()
                .map(entry -> entry.getValue().setId(entry.getKey()))
                .filter(ProviderProperties::isAws)
                .map(properties -> new BuilderProperties<>(properties.initializeAwsBuilder(), properties))
                .toList();
    }

    private void checkDefaultProviders() {
        Assert.notNull(providers, "Providers cannot be null");
        if (providers.isEmpty()) {
            log.warn("No providers found");
            return;
        }

        var defaultProvider = providers.entrySet()
                .stream()
                .filter(entry -> entry.getValue().isDefaultProvider())
                .map(Map.Entry::getValue)
                .toList();
        Assert.notEmpty(defaultProvider, "No default-provider found");
        Assert.isTrue(defaultProvider.size() == 1, "More than one default provider found");
    }

    record BuilderProperties<T extends EncryptionProviderBuilder>(
            T builder,
            ProviderProperties properties) {
    }
}
