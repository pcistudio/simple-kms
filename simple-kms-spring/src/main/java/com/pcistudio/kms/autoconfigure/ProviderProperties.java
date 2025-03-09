package com.pcistudio.kms.autoconfigure;

import com.pcistudio.kms.engine.AwsAESEncryptionProvider;
import com.pcistudio.kms.engine.LocalAESEncryptionProvider;
import com.pcistudio.kms.engine.serialization.Serializer;
import com.pcistudio.kms.utils.KeyGenerationUtil;
import org.springframework.util.Assert;
import software.amazon.awssdk.services.kms.model.DataKeySpec;

import javax.crypto.SecretKey;
import java.util.ArrayList;
import java.util.List;

import static com.pcistudio.kms.utils.KeyGenerationUtil.generateKeyAES;


public class ProviderProperties {
    private String id;
    private ProviderType type;
    private boolean defaultProvider = false;
    private int ivSize;
    private Serializer serializer = Serializer.JSON;

    private final Aws aws = new Aws();
    private final Local local = new Local();

    public Aws getAws() {
        return aws;
    }

    public Local getLocal() {
        return local;
    }

    public int getIvSize() {
        return ivSize;
    }


    public String getId() {
        return id;
    }

    public ProviderProperties setId(String id) {
        this.id = id;
        return this;
    }

    public ProviderType getType() {
        return type;
    }

    public ProviderProperties setType(ProviderType type) {
        this.type = type;
        return this;
    }

    public boolean isDefaultProvider() {
        return defaultProvider;
    }

    public ProviderProperties setDefaultProvider(boolean defaultProvider) {
        this.defaultProvider = defaultProvider;
        return this;
    }

    public ProviderProperties setIvSize(int ivSize) {
        this.ivSize = ivSize;
        return this;
    }

    public Serializer getSerializer() {
        return serializer;
    }

    public ProviderProperties setSerializer(Serializer serializer) {
        this.serializer = serializer;
        return this;
    }

    public boolean isLocal() {
        return type == ProviderType.LOCAL;
    }

    public boolean isAws() {
        return type == ProviderType.AWS;
    }

//    public boolean validate() {
//        Assert.notNull(type, "Missing provider type");
//        return true;
//    }

    public LocalAESEncryptionProvider.LocalAESEncryptionProviderBuilder initializeLocalBuilder() {
        Assert.notNull(type, "Missing provider type");
        Assert.isTrue(isLocal(), "Wrong provider type=" + type);
        return LocalAESEncryptionProvider.builder()
                .ivSupplier(KeyGenerationUtil.ivSupplier(getIvSize()))
                .serializer(getSerializer())
                .masterKeysHistory(getLocal().getMasterSecretKeys())
                .keySupplier(() -> generateKeyAES(getLocal().getKeySize()));
    }

    public AwsAESEncryptionProvider.AwsAESEncryptionProviderBuilder initializeAwsBuilder() {
        Assert.notNull(type, "Missing provider type");
        Assert.isTrue(isAws(), "Wrong provider type=" + type);
        return AwsAESEncryptionProvider.builder()
                .ivSupplier(KeyGenerationUtil.ivSupplier(getIvSize()))
                .serializer(getSerializer())
                .keyId(getAws().getKey())
                .dataKeySpec(getAws().getDataKeySpec());
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
            return new ArrayList<>(masterKeys);
        }

        public List<SecretKey> getMasterSecretKeys() {
            return getMasterKeys()
                    .stream()
                    .map(KeyGenerationUtil::loadAESKeyFromBase64)
                    .toList();
        }


        public Local setMasterKeys(List<String> masterKeys) {
            this.masterKeys = new ArrayList<>(masterKeys);
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

    public enum ProviderType {
        LOCAL,
        AWS
    }
}
