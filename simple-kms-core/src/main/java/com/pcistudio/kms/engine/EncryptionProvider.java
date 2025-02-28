package com.pcistudio.kms.engine;

public interface EncryptionProvider {
    EncryptionDescriptor getContext();
    String getName();
}
