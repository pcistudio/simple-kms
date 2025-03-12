package com.pcistudio.kms.autoconfigure;

import com.pcistudio.kms.engine.EncryptionProvider;
import com.pcistudio.kms.engine.EncryptionProviderManager;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.services.kms.KmsClientBuilder;

import java.util.List;

@Configuration
@EnableConfigurationProperties(SimpleKmsProperties.class)
public class ProvidersAutoConfiguration {

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

    /**
     * Create the default EncryptionProviderManager
     * If needed you can inject this class and add more providers if needed
     * @param encryptionProviders
     * @return
     */
    @Bean
    @ConditionalOnMissingBean
    public EncryptionProviderManager encryptionProviderManager(List<EncryptionProvider> encryptionProviders) {
        return new EncryptionProviderManager();
    }
}
