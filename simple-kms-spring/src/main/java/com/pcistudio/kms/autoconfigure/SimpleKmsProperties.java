package com.pcistudio.kms.autoconfigure;

import com.pcistudio.kms.engine.AwsAESEncryptionProvider;
import com.pcistudio.kms.engine.EncryptionProviderBuilder;
import com.pcistudio.kms.engine.LocalAESEncryptionProvider;
import com.pcistudio.kms.utils.KeyGenerationUtil;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.Assert;
import software.amazon.awssdk.services.kms.model.DataKeySpec;

import javax.crypto.SecretKey;
import java.util.*;

@ConfigurationProperties(
        prefix = "spring.simple-kms"
)
public class SimpleKmsProperties {

    private Map<String, ProviderProperties> providers = new HashMap<>();

    public Map<String, ProviderProperties> getProviders() {
        return providers;
    }

    public SimpleKmsProperties setProviders(Map<String, ProviderProperties> providers) {
        this.providers = providers;
        if (providers.size() == 1) {
            providers.entrySet()
                    .stream()
                    .findAny()
                    .ifPresent(entry -> entry.getValue().setDefaultProvider(true));

        }
        return this;
    }

    public List<BuilderProperties<LocalAESEncryptionProvider.LocalAESEncryptionProviderBuilder>> initializeLocalBuilder() {
        checkDefaultProviders();
        return providers.entrySet()
                .stream()
                .map(entry -> entry.getValue().setId(entry.getKey()))
                .filter(ProviderProperties::isLocal)
                .map(properties -> new BuilderProperties<>(properties.initializeLocalBuilder(), properties))
                .toList();
    }

    public List<BuilderProperties<AwsAESEncryptionProvider.AwsAESEncryptionProviderBuilder>> initializeAwsBuilder() {
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
        Assert.notEmpty(providers, "No providers found");

        var defaultProvider = providers.entrySet()
                .stream()
                .filter(entry -> entry.getValue().isDefaultProvider())
                .map(Map.Entry::getValue)
                .toList();
        Assert.notEmpty(defaultProvider, "No default-provider found");
        Assert.isTrue(defaultProvider.size() == 1, "More than one default provider found");
    }

    public static class Aws {
        private String key;
        private DataKeySpec dataKeySpec;

        public String getKey() {
            return key;
        }

        public Aws setKey(String key) {
            this.key = key;
            return this;
        }

        public DataKeySpec getDataKeySpec() {
            return dataKeySpec;
        }

        public Aws setDataKeySpec(DataKeySpec dataKeySpec) {
            this.dataKeySpec = dataKeySpec;
            return this;
        }
    }

    public static class Local {
        private List<String> masterKeys = new ArrayList<>();
        private int keySize = 256;

        public List<String> getMasterKeys() {
            return masterKeys;
        }

        public List<SecretKey> getMasterSecretKeys() {
            return getMasterKeys()
                    .stream()
                    .map(KeyGenerationUtil::loadAESKeyFromBase64)
                    .toList();
        }


        public Local setMasterKeys(List<String> masterKeys) {
            this.masterKeys = masterKeys;
            return this;
        }

        public int getKeySize() {
            return keySize;
        }

        public Local setKeySize(int keySize) {
            this.keySize = keySize;
            return this;
        }
    }

    public record BuilderProperties<T extends EncryptionProviderBuilder>(
            T builder,
            ProviderProperties properties) {
    }
}
