package com.pcistudio.kms.autoconfigure;

import com.pcistudio.kms.engine.EncryptionEngine;
import com.pcistudio.kms.engine.EncryptionProvider;
import com.pcistudio.kms.engine.EncryptionProviderManager;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.services.kms.KmsClientBuilder;

import java.util.List;

//@Configuration
//TODO change to AutoConfiguration
@AutoConfiguration
@EnableConfigurationProperties(SimpleKmsProperties.class)
public class SimpleKmsAutoConfiguration {

    @ConditionalOnClass(name = "software.amazon.awssdk.services.kms.KmsClientBuilder")
    @Configuration(proxyBeanMethods = false)
    static class Aws {
        @Bean
        @ConditionalOnBean(KmsClientBuilder.class)
        AwsEncryptionProviderManagerBeanPostProcessor awsEncryptionProviderManagerBeanPostProcessor(SimpleKmsProperties simpleKmsProperties, ObjectProvider<KmsClientBuilder> kmsClientBuilder) {
            return new AwsEncryptionProviderManagerBeanPostProcessor(simpleKmsProperties, kmsClientBuilder);
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class Local {

        @Bean
        LocalEncryptionProviderManagerBeanPostProcessor localEncryptionProviderManagerBeanPostProcessor(SimpleKmsProperties simpleKmsProperties) {
            return new LocalEncryptionProviderManagerBeanPostProcessor(simpleKmsProperties);
        }
    }

    @Bean
    @ConditionalOnMissingBean
    public EncryptionProviderManager encryptionProviderManager(List<EncryptionProvider> encryptionProviders) {
        return new EncryptionProviderManager();
    }

    @Bean
    public EncryptionEngine encryptionEngine(EncryptionProviderManager manager) {
        manager.validate();
        return new EncryptionEngine(manager);
    }

}
