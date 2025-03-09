package com.pcistudio.kms.autoconfigure;

import com.pcistudio.kms.engine.EncryptionProviderManager;
import com.pcistudio.kms.engine.LocalAESEncryptionProvider;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.lang.Nullable;

@SuppressFBWarnings("UWF_FIELD_NOT_INITIALIZED_IN_CONSTRUCTOR")
public class LocalEncryptionProviderManagerBeanPostProcessor implements BeanPostProcessor, ApplicationContextAware {

    private final SimpleKmsProperties simpleKmsProperties;

    private BeanDefinitionRegistry registry;

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) {
        this.registry = (BeanDefinitionRegistry) applicationContext.getAutowireCapableBeanFactory();
    }

    public LocalEncryptionProviderManagerBeanPostProcessor(SimpleKmsProperties simpleKmsProperties) {
        this.simpleKmsProperties = simpleKmsProperties;
    }


    @Nullable
    @Override
    public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
        if (bean instanceof EncryptionProviderManager manager) {
            var builderProperties = simpleKmsProperties.initializeLocalBuilder();

            for (var builderProperty : builderProperties) {
                LocalAESEncryptionProvider provider = builderProperty
                        .builder()
                        .build();
                manager.register(provider, builderProperty.properties().isDefaultProvider());
                BeanDefinition beanDefinition = BeanDefinitionBuilder.genericBeanDefinition(provider.getClass()).getBeanDefinition();
                registry.registerBeanDefinition(builderProperty.properties().getId(), beanDefinition);
            }

        }
        return bean;
    }
}