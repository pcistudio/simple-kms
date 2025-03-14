package com.pcistudio.kms.autoconfigure;

import com.pcistudio.kms.engine.EncryptionProviderManager;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.services.kms.KmsClientBuilder;

@Configuration
@EnableConfigurationProperties(SimpleKmsProperties.class)
public class ProvidersAutoConfiguration {

    @ConditionalOnClass(name = "software.amazon.awssdk.services.kms.KmsClientBuilder")
    @Configuration(proxyBeanMethods = false)
    static class Aws {
        @Bean
        @ConditionalOnBean(type = "software.amazon.awssdk.services.kms.KmsClientBuilder")
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

    /**
     * Create the default EncryptionProviderManager
     * You can inject this class and add more providers if needed
     *
     * @return
     */
    @Bean
    @ConditionalOnMissingBean
    public EncryptionProviderManager encryptionProviderManager() {
        return new EncryptionProviderManager();
    }
}
