package com.pcistudio.kms.autoconfigure;

import com.pcistudio.kms.engine.EncryptionProviderManager;
import com.pcistudio.kms.engine.LocalAESEncryptionProvider;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.lang.Nullable;

@SuppressFBWarnings("UWF_FIELD_NOT_INITIALIZED_IN_CONSTRUCTOR")
public class LocalEncryptionProviderManagerBeanPostProcessor implements BeanPostProcessor {

    private final SimpleKmsProperties simpleKmsProperties;

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
            }

        }
        return bean;
    }
}