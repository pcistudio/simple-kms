package com.pcistudio.kms.autoconfigure;

import com.pcistudio.kms.engine.EncryptionEngine;
import com.pcistudio.kms.engine.EncryptionProviderManager;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;

@AutoConfiguration
@Import(ProvidersAutoConfiguration.class)
@ConditionalOnProperty(prefix = "spring.simple-kms", name = "enabled", havingValue = "true", matchIfMissing = true)
public class SimpleKmsAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public EncryptionEngine encryptionEngine(EncryptionProviderManager manager) {
        manager.validate();
        return new EncryptionEngine(manager);
    }
}

