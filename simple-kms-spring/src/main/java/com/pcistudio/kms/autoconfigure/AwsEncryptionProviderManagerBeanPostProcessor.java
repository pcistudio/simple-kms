package com.pcistudio.kms.autoconfigure;

import com.pcistudio.kms.engine.AwsAESEncryptionProvider;
import com.pcistudio.kms.engine.EncryptionProviderManager;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.lang.Nullable;
import software.amazon.awssdk.services.kms.KmsClientBuilder;

@SuppressFBWarnings("UWF_FIELD_NOT_INITIALIZED_IN_CONSTRUCTOR")
public class AwsEncryptionProviderManagerBeanPostProcessor implements BeanPostProcessor, ApplicationContextAware {

    private final SimpleKmsProperties simpleKmsProperties;
    private final ObjectProvider<KmsClientBuilder> kmsClientBuilder;
    private BeanDefinitionRegistry registry;

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) {
        this.registry = (BeanDefinitionRegistry) applicationContext.getAutowireCapableBeanFactory();
    }

    public AwsEncryptionProviderManagerBeanPostProcessor(SimpleKmsProperties simpleKmsProperties, ObjectProvider<KmsClientBuilder> kmsClientBuilder) {
        this.simpleKmsProperties = simpleKmsProperties;
        this.kmsClientBuilder = kmsClientBuilder;
    }

    @Nullable
    @Override
    public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
        if (bean instanceof EncryptionProviderManager manager) {
            var builderProperties = simpleKmsProperties.initializeAwsBuilder();

            for (var builderProperty : builderProperties) {
                AwsAESEncryptionProvider provider = builderProperty
                        .builder()
                        .kmsClientBuilder(kmsClientBuilder.getObject())
                        .build();
                manager.register(provider, builderProperty.properties().isDefaultProvider());
                BeanDefinition beanDefinition = BeanDefinitionBuilder.genericBeanDefinition(provider.getClass()).getBeanDefinition();
                registry.registerBeanDefinition(builderProperty.properties().getId(), beanDefinition);
            }
        }
        return bean;
    }
}